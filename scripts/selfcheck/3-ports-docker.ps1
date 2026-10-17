# 自检分段 3：默认端口占用与 Docker 守护状态。

# ---------------------------------------------------------------------------
# 4. 端口占用
# ---------------------------------------------------------------------------
if (-not $Json) { Write-Host ''; Write-Host '--- 4. 端口占用 ---' -ForegroundColor DarkCyan }

$ports = [ordered]@{
    'API (8080)'        = [int](Get-AgfEnv -Name 'AGF_SERVER_PORT' -Default '8080')
    'Web (8081)'        = [int](Get-AgfEnv -Name 'AGF_WEB_PORT' -Default '8081')
    'Ingest (8090)'     = [int](Get-AgfEnv -Name 'AGF_INGEST_PORT' -Default '8090')
    'MCP 代理 (8092)'   = [int](Get-AgfEnv -Name 'AGF_MCP_PROXY_HOST_PORT' -Default '8092')
    'Syslog TCP (5514)' = [int](Get-AgfEnv -Name 'AGF_SYSLOG_TCP_PORT' -Default '5514')
    'Metrics (9100)'    = [int](Get-AgfEnv -Name 'AGF_METRICS_PORT' -Default '9100')
    'Postgres (5432)'   = [int](Get-AgfEnv -Name 'AGF_PG_HOST_PORT' -Default '5432')
    'Redis (6379)'      = [int](Get-AgfEnv -Name 'AGF_REDIS_HOST_PORT' -Default '6379')
    'NATS (4222)'       = [int](Get-AgfEnv -Name 'AGF_NATS_HOST_PORT' -Default '4222')
    'MinIO (9000)'      = [int](Get-AgfEnv -Name 'AGF_MINIO_PORT' -Default '9000')
    'Grafana (3000)'    = [int](Get-AgfEnv -Name 'AGF_GRAFANA_PORT' -Default '3000')
}
foreach ($kv in $ports.GetEnumerator()) {
    try {
        $busy = Test-AgfPort -Port $kv.Value
        if ($busy) {
            Add-Check -Name ("端口 {0}" -f $kv.Key) -Status warn -Detail '已被占用（可能是平台自身已启动）'
        }
        else {
            Add-Check -Name ("端口 {0}" -f $kv.Key) -Status ok -Detail '空闲'
        }
    }
    catch {
        Add-Check -Name ("端口 {0}" -f $kv.Key) -Status info -Detail "无法探测: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# 5. Docker 守护状态
# ---------------------------------------------------------------------------
if (-not $Json) { Write-Host ''; Write-Host '--- 5. Docker ---' -ForegroundColor DarkCyan }

if ($SkipDocker) {
    Add-Check -Name 'Docker 守护' -Status info -Detail '已按参数跳过'
}
else {
    $dockerExe = Get-AgfTool -Name 'docker'
    if ($null -eq $dockerExe) {
        Add-Check -Name 'Docker 守护' -Status warn -Detail 'docker CLI 不可用；Compose 相关步骤需登记到 pending-verification.md'
    }
    else {
        try {
            $info = & $dockerExe info --format '{{.ServerVersion}}|{{.OSType}}|{{.Driver}}' 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0 -and $info -match '\|') {
                $parts = $info.Trim() -split '\|'
                Add-Check -Name 'Docker 守护' -Status ok -Detail ("运行中 · Server {0} · {1} · {2}" -f $parts[0], $parts[1], $parts[2])
            }
            else {
                Add-Check -Name 'Docker 守护' -Status warn -Detail '未运行（请启动 Docker Desktop 后重试；不阻塞离线开发）'
            }
        }
        catch {
            Add-Check -Name 'Docker 守护' -Status warn -Detail "探测失败: $($_.Exception.Message)"
        }

        # compose 配置可解析性
        try {
            & $dockerExe compose -f (Join-Path $AgfRoot 'docker-compose.yml') config --quiet 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Add-Check -Name 'compose 配置' -Status ok -Detail 'docker-compose.yml 语法与变量插值校验通过'
            }
            else {
                Add-Check -Name 'compose 配置' -Status fail -Detail 'docker compose config 失败（缺少 .env 变量？）'
            }
        }
        catch {
            Add-Check -Name 'compose 配置' -Status warn -Detail "校验被跳过: $($_.Exception.Message)"
        }
    }
}
