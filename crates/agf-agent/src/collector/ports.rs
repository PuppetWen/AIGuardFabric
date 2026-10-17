//! 监听端口采集（Windows 解析 `netstat -ano`；Linux 读取 `/proc/net`）。
//!
//! 三层结构，便于离线单测：
//!
//! 1. [`parse_netstat_windows`] / [`parse_ss_linux`]：**纯函数**，用夹具文本断言；
//! 2. [`collect`]（Windows）：执行 `netstat -ano` 并调用解析器（**只读本地命令，不出网**）；
//! 3. macOS：调用本机 `lsof -Fpcfn` 获取 TCP 监听和 UDP 绑定端口；缺失或失败时如实降级。
//!
//! ## 降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | `netstat` 不可用/被策略禁止 | 记 warning 返回空列表（**不是错误**，其它采集项不受影响） |
//! | 输出中的 IPv6 地址 | 归一为 `::1` / `::` 等可读形态 |
//! | 端口无法解析 | 跳过该行 |
//! | 上下文关闭端口采集 | 上层记 `skipped` 状态（见 [`skipped_outcome`]） |

use super::{CollectContext, CollectorOutcome};
use crate::payload::ListeningPort;

/// 采集器名。
pub const NAME: &str = "listening-ports";

/// 关注的端口（AI 服务常见端口，用于打标提示；本模块只产事实，不做判定）。
pub const ATTENTION_PORTS: [u16; 9] = [11434, 1234, 5000, 7860, 8000, 8080, 8888, 3000, 6333];

/// 拆分 `addr:port`（兼容 IPv6 `[::1]:8080` 与通配 `*:*`）。
#[must_use]
pub fn split_endpoint(value: &str) -> Option<(String, u16)> {
    let trimmed = value.trim();
    let (host, port_text) = if let Some(rest) = trimmed.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?;
        (host.to_string(), port)
    } else {
        let (host, port) = trimmed.rsplit_once(':')?;
        (host.to_string(), port)
    };
    let port: u16 = port_text.trim().parse().ok()?;
    Some((host, port))
}

/// 解析 Windows `netstat -ano` 输出。
#[must_use]
pub fn parse_netstat_windows(text: &str) -> Vec<ListeningPort> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let protocol = fields[0].to_ascii_lowercase();
        let is_tcp = protocol == "tcp" || protocol == "tcpv6" || protocol == "tcp6";
        let is_udp = protocol == "udp" || protocol == "udpv6" || protocol == "udp6";
        if !is_tcp && !is_udp {
            continue;
        }
        // TCP 行：proto local foreign state pid；UDP 行：proto local foreign pid
        let (local, pid_text) = if is_tcp {
            if fields.len() < 5 || !fields[3].eq_ignore_ascii_case("LISTENING") {
                continue;
            }
            (fields[1], fields[4])
        } else {
            (fields[1], fields[3])
        };
        let Some((host, port)) = split_endpoint(local) else { continue };
        let pid = pid_text.parse::<u32>().ok();
        out.push(ListeningPort {
            protocol: if is_tcp { "tcp".to_string() } else { "udp".to_string() },
            local_addr: host,
            port,
            pid,
            process: None,
        });
    }
    out.sort_by(|a, b| {
        (a.protocol.as_str(), a.port, a.local_addr.as_str()).cmp(&(b.protocol.as_str(), b.port, b.local_addr.as_str()))
    });
    out.dedup_by(|a, b| a.protocol == b.protocol && a.port == b.port && a.local_addr == b.local_addr && a.pid == b.pid);
    out
}

/// 解析 Linux `ss -ltnup` 输出（已实现但**未在真机验证**）。
#[must_use]
pub fn parse_ss_linux(text: &str) -> Vec<ListeningPort> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(state) = fields.first() else { continue };
        let protocol = if state.eq_ignore_ascii_case("LISTEN") {
            "tcp"
        } else if state.eq_ignore_ascii_case("UNCONN") {
            "udp"
        } else {
            continue;
        };
        let Some(local) = fields.get(3) else { continue };
        let Some((host, port)) = split_endpoint(local) else { continue };
        let users = fields.get(5..).unwrap_or_default().join(" ");
        let pid = users
            .split("pid=")
            .nth(1)
            .and_then(|rest| rest.split([',', ')']).next())
            .and_then(|value| value.trim().parse::<u32>().ok());
        let process = users.split("((\"").nth(1).and_then(|rest| rest.split('"').next()).map(ToString::to_string);
        out.push(ListeningPort { protocol: protocol.to_string(), local_addr: host, port, pid, process });
    }
    out.sort_by(|a, b| {
        (a.protocol.as_str(), a.port, a.local_addr.as_str()).cmp(&(b.protocol.as_str(), b.port, b.local_addr.as_str()))
    });
    out.dedup_by(|a, b| a.protocol == b.protocol && a.port == b.port && a.local_addr == b.local_addr);
    out
}

#[cfg(target_os = "linux")]
fn parse_proc_net(text: &str, protocol: &str, ipv6: bool) -> Vec<ListeningPort> {
    let mut ports = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 || (protocol == "tcp" && fields[3] != "0A") || (protocol == "udp" && fields[3] != "07") {
            continue;
        }
        let Some((addr_hex, port_hex)) = fields[1].split_once(':') else { continue };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else { continue };
        if port == 0 {
            continue;
        }
        let Ok(raw) = hex::decode(addr_hex) else { continue };
        let address = if ipv6 {
            let Ok(mut octets) = <[u8; 16]>::try_from(raw) else { continue };
            for chunk in octets.chunks_exact_mut(4) {
                chunk.reverse();
            }
            std::net::Ipv6Addr::from(octets).to_string()
        } else {
            let Ok(mut octets) = <[u8; 4]>::try_from(raw) else { continue };
            octets.reverse();
            std::net::Ipv4Addr::from(octets).to_string()
        };
        ports.push(ListeningPort {
            protocol: protocol.to_string(),
            local_addr: address,
            port,
            pid: None,
            process: None,
        });
    }
    ports
}

/// 是否属于值得关注的 AI 服务端口（事实标注，供服务端规则使用）。
#[must_use]
pub fn is_attention_port(port: u16) -> bool {
    ATTENTION_PORTS.contains(&port)
}

/// "已关闭"状态。
#[must_use]
pub fn skipped_outcome() -> CollectorOutcome<ListeningPort> {
    CollectorOutcome::skipped(NAME, "端口采集已在上下文中关闭（低开销模式）")
}

/// 执行采集（Windows：`netstat -ano`）。
#[cfg(target_os = "windows")]
#[must_use]
pub fn collect(_ctx: &CollectContext) -> CollectorOutcome<ListeningPort> {
    let started = std::time::Instant::now();
    let mut outcome = CollectorOutcome {
        name: NAME,
        items: Vec::new(),
        credential_hits: Vec::new(),
        scope: vec!["netstat -ano".to_string()],
        warnings: Vec::new(),
        level: crate::platform::SupportLevel::Implemented,
        elapsed_ms: 0,
        error: None,
    };
    match std::process::Command::new("netstat").arg("-ano").output() {
        Ok(output) => {
            let text = String::from_utf8_lossy(&output.stdout);
            outcome.items = parse_netstat_windows(&text);
            if outcome.items.is_empty() {
                outcome.warnings.push("netstat 输出中没有解析到监听端口".to_string());
            }
        }
        Err(error) => outcome.warnings.push(format!("netstat 不可用或被策略禁止（{error}）：端口采集降级为空结果")),
    }
    outcome.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    outcome
}

/// 执行采集（Linux：内核提供的只读 `/proc/net`，无需额外命令）。
#[cfg(target_os = "linux")]
#[must_use]
pub fn collect(_ctx: &CollectContext) -> CollectorOutcome<ListeningPort> {
    let started = std::time::Instant::now();
    let mut outcome = CollectorOutcome {
        name: NAME,
        items: Vec::new(),
        credential_hits: Vec::new(),
        scope: Vec::new(),
        warnings: Vec::new(),
        level: crate::platform::SupportLevel::Implemented,
        elapsed_ms: 0,
        error: None,
    };
    for (path, protocol, ipv6) in [
        ("/proc/net/tcp", "tcp", false),
        ("/proc/net/tcp6", "tcp", true),
        ("/proc/net/udp", "udp", false),
        ("/proc/net/udp6", "udp", true),
    ] {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                outcome.scope.push(path.to_string());
                outcome.items.extend(parse_proc_net(&text, protocol, ipv6));
            }
            Err(error) => outcome.warnings.push(format!("{path}: {error}")),
        }
    }
    outcome.items.sort_by(|a, b| {
        (a.protocol.as_str(), a.local_addr.as_str(), a.port).cmp(&(b.protocol.as_str(), b.local_addr.as_str(), b.port))
    });
    outcome.items.dedup_by(|a, b| a.protocol == b.protocol && a.local_addr == b.local_addr && a.port == b.port);
    if outcome.scope.is_empty() {
        outcome.error = Some("无法读取任何 /proc/net 监听端口文件".to_string());
    }
    outcome.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    outcome
}

/// 执行采集（macOS：`lsof` 字段输出；真机权限差异仍须目标系统验收）。
#[cfg(target_os = "macos")]
#[must_use]
pub fn collect(_ctx: &CollectContext) -> CollectorOutcome<ListeningPort> {
    let started = std::time::Instant::now();
    let binary = if std::path::Path::new("/usr/sbin/lsof").is_file() { "/usr/sbin/lsof" } else { "lsof" };
    let mut outcome = CollectorOutcome {
        name: NAME,
        items: Vec::new(),
        credential_hits: Vec::new(),
        scope: Vec::new(),
        warnings: Vec::new(),
        level: crate::platform::SupportLevel::Implemented,
        elapsed_ms: 0,
        error: None,
    };
    let commands: [(&str, &[&str]); 2] =
        [("tcp", &["-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcfn"]), ("udp", &["-nP", "-iUDP", "-Fpcfn"])];
    let mut failed = 0;
    for (protocol, args) in commands {
        outcome.scope.push(format!("lsof {}", args.join(" ")));
        match std::process::Command::new(binary).args(args).output() {
            Ok(output)
                if output.status.success()
                    || (output.status.code() == Some(1) && output.stdout.is_empty() && output.stderr.is_empty()) =>
            {
                outcome.items.extend(crate::collector::macos_ports::parse_lsof_fields(
                    &String::from_utf8_lossy(&output.stdout),
                    protocol,
                ));
            }
            Ok(output) => {
                failed += 1;
                outcome.warnings.push(format!("lsof {protocol} 查询失败（退出码 {:?}）", output.status.code()));
            }
            Err(error) => {
                failed += 1;
                outcome.warnings.push(format!("lsof {protocol} 不可用：{error}"));
            }
        }
    }
    outcome.items.sort_by(|a, b| {
        (a.protocol.as_str(), a.local_addr.as_str(), a.port, a.pid).cmp(&(
            b.protocol.as_str(),
            b.local_addr.as_str(),
            b.port,
            b.pid,
        ))
    });
    outcome.items.dedup_by(|a, b| {
        a.protocol == b.protocol && a.local_addr == b.local_addr && a.port == b.port && a.pid == b.pid
    });
    if failed == 2 {
        outcome.error = Some("macOS 监听端口采集不可用：TCP 与 UDP 的 lsof 查询均失败".into());
    }
    outcome.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    outcome
}

/// 其它平台仍只提供接口与 TODO 锚点。
#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
#[must_use]
pub fn collect(_ctx: &CollectContext) -> CollectorOutcome<ListeningPort> {
    match crate::platform::unsupported_error(NAME) {
        Some(error) => CollectorOutcome::unsupported(NAME, error.to_string()),
        None => CollectorOutcome::skipped(NAME, "平台判定异常：无 TODO 锚点"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETSTAT_SAMPLE: &str = "\
活动连接

  协议  本地地址          外部地址        状态           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1024
  TCP    127.0.0.1:11434        0.0.0.0:0              LISTENING       2048
  TCP    127.0.0.1:52341        127.0.0.1:11434        ESTABLISHED     4096
  TCP    [::]:8080              [::]:0                 LISTENING       3072
  UDP    0.0.0.0:5353           *:*                                    5120
  UDP    [::1]:1900             *:*                                    5121
";

    const SS_SAMPLE: &str = "\
State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      128    127.0.0.1:11434       0.0.0.0:*     users:((\"ollama\",pid=1234,fd=3))
LISTEN 0      4096   [::]:8080             [::]:*        users:((\"python\",pid=5678,fd=8))
UNCONN 0      0      0.0.0.0:5353          0.0.0.0:*
ESTAB  0      0      10.0.0.5:443          10.0.0.6:52341
";

    #[test]
    fn split_endpoint_handles_ipv4_ipv6_and_wildcards() {
        assert_eq!(split_endpoint("127.0.0.1:8080"), Some(("127.0.0.1".to_string(), 8080)));
        assert_eq!(split_endpoint("[::1]:11434"), Some(("::1".to_string(), 11434)));
        assert_eq!(split_endpoint("0.0.0.0:135"), Some(("0.0.0.0".to_string(), 135)));
        assert!(split_endpoint("*:*").is_none());
        assert!(split_endpoint("no-port").is_none());
        assert!(split_endpoint("127.0.0.1:70000").is_none(), "端口越界应判否");
    }

    #[test]
    fn netstat_parser_keeps_listening_only() {
        let ports = parse_netstat_windows(NETSTAT_SAMPLE);
        assert!(ports.iter().any(|p| p.port == 135 && p.protocol == "tcp"));
        assert!(ports.iter().any(|p| p.port == 11434 && p.pid == Some(2048)));
        assert!(ports.iter().any(|p| p.port == 8080 && p.local_addr == "::"));
        assert!(!ports.iter().any(|p| p.port == 52341), "ESTABLISHED 不得上报");
        assert!(ports.iter().any(|p| p.protocol == "udp" && p.port == 5353), "UDP 无状态也应上报");
        assert!(ports.iter().any(|p| p.port == 1900 && p.local_addr == "::1"));
        assert_eq!(ports.len(), 5, "{ports:?}");
    }

    #[test]
    fn netstat_parser_ignores_header_and_garbage() {
        assert!(parse_netstat_windows("活动连接\n\n  协议  本地地址\n").is_empty());
        assert!(parse_netstat_windows("").is_empty());
        assert!(parse_netstat_windows("TCP  not-a-port  0.0.0.0:0  LISTENING  1").is_empty());
    }

    #[test]
    fn ss_parser_extracts_process_and_pid() {
        let ports = parse_ss_linux(SS_SAMPLE);
        assert_eq!(ports.len(), 3, "{ports:?}");
        let ollama = ports.iter().find(|p| p.port == 11434).expect("ollama 行");
        assert_eq!(ollama.pid, Some(1234));
        assert_eq!(ollama.process.as_deref(), Some("ollama"));
        let udp = ports.iter().find(|p| p.protocol == "udp").expect("udp 行");
        assert_eq!(udp.port, 5353);
        assert!(ports.iter().all(|p| p.port != 443), "ESTAB 不得上报");
    }

    #[test]
    fn attention_ports_flag() {
        assert!(is_attention_port(11434));
        assert!(is_attention_port(8080));
        assert!(!is_attention_port(135));
    }

    #[test]
    fn skipped_outcome_is_not_an_error() {
        let outcome = skipped_outcome();
        assert!(outcome.is_ok());
        assert!(outcome.items.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_net_parser_keeps_bound_ports_and_addresses() {
        let tcp =
            "sl local_address rem_address st\n0: 0100007F:2CAA 00000000:0000 0A\n1: 00000000:0050 00000000:0000 01\n";
        let found = parse_proc_net(tcp, "tcp", false);
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].local_addr.as_str(), found[0].port), ("127.0.0.1", 11434));
        let ipv6 = "sl local_address rem_address st\n0: 00000000000000000000000001000000:1F90 00000000:0000 0A\n";
        assert_eq!(parse_proc_net(ipv6, "tcp", true)[0].local_addr, "::1");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collect_observes_a_real_loopback_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("回环监听");
        let port = listener.local_addr().expect("本地地址").port();
        let outcome = collect(&CollectContext::for_current_user());
        assert!(outcome.is_ok(), "{outcome:?}");
        assert!(outcome.items.iter().any(|item| item.protocol == "tcp" && item.port == port));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn collect_runs_netstat_and_degrades_gracefully() {
        let dir = tempfile::tempdir().expect("临时目录");
        let ctx = CollectContext::for_current_user().with_home(dir.path());
        let outcome = collect(&ctx);
        assert!(outcome.is_ok(), "netstat 不可用也必须降级而不是报错: {:?}", outcome.error);
        for port in &outcome.items {
            assert!(!port.local_addr.is_empty());
            assert!(matches!(port.protocol.as_str(), "tcp" | "udp"));
        }
    }
}
