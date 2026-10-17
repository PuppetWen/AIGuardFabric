//! Windows 内置 WMI start trace；只保留事件中的 PID/ProcessName，不按 PID 回查 argv。
use super::*;
use agf_core::process_hook::ProcessSource;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

// 订阅和事件队列仅属于本次子 PowerShell；finally 不接触其它进程/订阅。
const SCRIPT: &str = r#"
$ErrorActionPreference='Stop'; [Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$subscription=$null; $control=$null; $stop=$null; $source='AGF-ProcessStart-'+[Guid]::NewGuid().ToString('N')
try {
  $subscription=Register-WmiEvent -Class Win32_ProcessStartTrace -SourceIdentifier $source
  [Console]::Out.WriteLine('{"ready":true}')
  # .NET Framework 的 Console.In Async 仍同步阻塞；只在本实例 owned runspace 读一条停止指令。
  $control=[powershell]::Create()
  $null=$control.AddScript('[Console]::In.ReadLine()')
  $stop=$control.BeginInvoke()
  while(-not $stop.IsCompleted) {
    $event=Wait-Event -SourceIdentifier $source -Timeout 1
    if($null-ne$event) {
      $value=$event.SourceEventArgs.NewEvent
      [pscustomobject]@{ready=$false;pid=[uint32]$value.ProcessID;name=[string]$value.ProcessName} | ConvertTo-Json -Compress | ForEach-Object{[Console]::Out.WriteLine($_)}
      Remove-Event -EventIdentifier $event.EventIdentifier
    }
  }
} finally {
  if($null-ne$subscription){Unregister-Event -SourceIdentifier $source -ErrorAction SilentlyContinue}
  Get-Event -SourceIdentifier $source -ErrorAction SilentlyContinue | Remove-Event -ErrorAction SilentlyContinue
  if($null-ne$control){
    if($null-eq$stop -or $stop.IsCompleted){$control.Dispose()}
    else{$null=$control.BeginStop($null,$null)}
  }
}
"#;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    ready: bool,
    #[serde(default)]
    pid: Option<u32>,
    #[serde(default)]
    name: Option<String>,
}
async fn line(reader: &mut BufReader<tokio::process::ChildStdout>) -> DomainResult<Vec<u8>> {
    let mut bytes = Vec::new();
    let read = reader.take(4097).read_until(b'\n', &mut bytes).await?;
    if read == 0 || bytes.len() > 4096 || !bytes.ends_with(b"\n") {
        return Err(client::denied("WMI event stream ended or exceeded framing budget"));
    }
    Ok(bytes)
}
pub(super) async fn observe(client: &ProcessClient, agent: Id, duration: Duration, limit: u32) -> DomainResult<u32> {
    let encoded = STANDARD.encode(SCRIPT.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>());
    let mut command = tokio::process::Command::new("powershell.exe");
    command
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    for (name, _) in std::env::vars_os() {
        if name.to_str().is_some_and(|name| name.starts_with("AGF_")) {
            command.env_remove(name);
        }
    }
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().ok_or_else(|| client::denied("WMI child stdout unavailable"))?;
    let mut reader = BufReader::new(stdout);
    let result = async {
        let ready = tokio::time::timeout(Duration::from_secs(10), line(&mut reader))
            .await
            .map_err(|_| client::denied("WMI subscription did not become ready"))??;
        let ready: Wire =
            serde_json::from_slice(&ready).map_err(|_| client::denied("Malformed WMI readiness frame"))?;
        if !ready.ready || ready.pid.is_some() || ready.name.is_some() {
            return Err(client::denied("WMI subscription not ready"));
        }
        let until = tokio::time::Instant::now() + duration;
        let mut count = 0;
        while count < limit {
            let bytes = tokio::select! {
                result=line(&mut reader)=>result?,
                ()=tokio::time::sleep_until(until)=>break,
                result=tokio::signal::ctrl_c()=>{result?;break;}
            };
            let wire: Wire = serde_json::from_slice(&bytes).map_err(|_| client::denied("Malformed WMI event frame"))?;
            let name = wire
                .name
                .filter(|name| !name.is_empty() && name.len() <= 1024)
                .ok_or_else(|| client::denied("WMI event has no bounded ProcessName"))?;
            if wire.ready || wire.pid.is_none_or(|pid| pid == 0) {
                return Err(client::denied("Invalid WMI event PID"));
            }
            let body = event(agent, ProcessSource::WindowsWmiStart, name.as_bytes(), wire.pid, None, None, false, 0);
            if client.check(&body).await?.launch_allowed {
                return Err(client::denied("Observation cannot admit launch"));
            }
            count += 1;
        }
        Ok(count)
    }
    .await;
    // 只终止本次创建的订阅进程；正常停止/异常/取消都回收拥有的 Child。
    if child.try_wait()?.is_none() {
        if let Some(mut input) = child.stdin.take() {
            let _ = input.write_all(b"stop\n").await;
        }
        if tokio::time::timeout(Duration::from_secs(5), child.wait()).await.is_err() {
            child.start_kill()?;
            let _ = child.wait().await;
        }
    }
    result
}
