#Requires -Version 5.1
<#
.SYNOPSIS
    一键起本地开发栈（§9：docker compose 依赖 + 本地跑 server/web 热重载）。

.DESCRIPTION
    默认只把**依赖服务**拉起来（postgres / redis / nats / minio），然后打印后续命令；
    用 -WithApps 时额外把 agf-server 与前端 dev server 作为后台进程启动（日志落 data\logs\）。

    为什么默认不常驻：脚本要能"跑完就返回"，否则 CI / gate 里会挂住。
    需要常驻时显式 -WithApps，会返回进程 id 并把日志路径打印出来。

.PARAMETER DepsOnly
    只起依赖服务（Justfile 的 up-deps 用这个）。

.PARAMETER WithApps
    起完依赖后再后台启动 agf-server（cargo run）与前端（pnpm dev）。

.PARAMETER NoWait
    不等待健康检查（默认等待到全部 healthy 或 60s 超时）。

.PARAMETER Down
    停止本地 compose 栈（保留数据卷）。

.NOTES
    依赖 Docker 守护进程；未运行时给出明确提示（不静默跳过）。
#>

param(
    [switch]$DepsOnly,
    [switch]$WithApps,
    [switch]$NoWait,
    [switch]$Down
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\lib.ps1"

$root = $global:AgfRoot
$envFile = Join-Path $root '.env'
$compose = Join-Path $root 'docker-compose.yml'

if (-not (Test-Path -LiteralPath $envFile)) {
    Write-AgfInfo '.env 不存在，先执行 scripts\init-env.ps1 生成'
    exit 1
}

Write-Host "`n=== 本地开发栈 ===" -ForegroundColor White

$dockerOk = $false
try {
    docker info *> $null
    if ($LASTEXITCODE -eq 0) { $dockerOk = $true }
}
catch {
    $dockerOk = $false
}
if (-not $dockerOk) {
    Write-AgfFail 'Docker 守护进程不可用：请启动 Docker Desktop（未运行时不静默跳过）'
    exit 1
}

Push-Location $root
try {
    if ($Down) {
        docker compose -f $compose --env-file $envFile down
        if ($LASTEXITCODE -ne 0) { throw 'docker compose down 失败' }
        Write-AgfOk '本地栈已停止（数据卷保留；彻底清理用 docker compose down -v）'
        exit 0
    }

    $deps = @('postgres', 'redis', 'nats', 'minio')
    Write-AgfInfo ('启动依赖服务：{0}' -f ($deps -join ' / '))
    docker compose -f $compose --env-file $envFile up -d @deps
    if ($LASTEXITCODE -ne 0) { throw 'docker compose up 失败' }

    if (-not $NoWait) {
        Write-AgfInfo '等待依赖健康检查（最长 60s）...'
        $deadline = (Get-Date).AddSeconds(60)
        $pending = $deps.Count
        while ((Get-Date) -lt $deadline -and $pending -gt 0) {
            Start-Sleep -Seconds 2
            $pending = 0
            foreach ($svc in $deps) {
                $state = (docker compose -f $compose --env-file $envFile ps --format '{{.Service}} {{.State}} {{.Health}}' 2>$null) |
                    Where-Object { $_ -like "$svc *" }
                if (-not $state) { $pending++; continue }
                if ($state -notmatch 'running' -or ($state -match 'health' -and $state -notmatch 'healthy')) { $pending++ }
            }
        }
        if ($pending -gt 0) {
            Write-AgfFail ("仍有 {0} 个依赖未就绪；用 docker compose logs <服务> 排查" -f $pending)
            exit 1
        }
        Write-AgfOk '依赖服务全部就绪'
    }

    if ($DepsOnly -or -not $WithApps) {
        Write-AgfInfo '下一步（任选）：'
        Write-Host '  cargo run -p agf-server         # 后端（API + 控制台后端）' -ForegroundColor Gray
        Write-Host '  cd apps\web; pnpm dev           # 前端热重载' -ForegroundColor Gray
        Write-Host '  scripts\demo.ps1                # 单机全链路演示' -ForegroundColor Gray
        Write-Host '  scripts\seed.ps1                # 灌演示数据' -ForegroundColor Gray
        if ($DepsOnly) { exit 0 }
        exit 0
    }

    # 后台启动后端与前端（日志落 data\logs\）
    $logDir = Join-Path $root 'data\logs'
    New-AgfDirectory -Path $logDir | Out-Null
    $serverLog = Join-Path $logDir 'agf-server.out.log'
    $webLog = Join-Path $logDir 'web.out.log'

    Write-AgfInfo '后台启动 agf-server（cargo run -p agf-server）...'
    $server = Start-Process -FilePath 'cargo' -ArgumentList 'run', '-p', 'agf-server' -WorkingDirectory $root -RedirectStandardOutput $serverLog -RedirectStandardError (Join-Path $logDir 'agf-server.err.log') -PassThru
    Write-AgfOk ('agf-server pid={0}，日志 {1}' -f $server.Id, $serverLog)

    $webDir = Join-Path $root 'apps\web'
    if (Test-Path -LiteralPath (Join-Path $webDir 'node_modules')) {
        Write-AgfInfo '后台启动前端（pnpm dev）...'
        $web = Start-Process -FilePath 'pnpm' -ArgumentList 'dev' -WorkingDirectory $webDir -RedirectStandardOutput $webLog -RedirectStandardError (Join-Path $logDir 'web.err.log') -PassThru
        Write-AgfOk ('web pid={0}，日志 {1}' -f $web.Id, $webLog)
    }
    else {
        Write-AgfSkip 'apps/web/node_modules 不存在，跳过前端；先 cd apps\web; pnpm install'
    }

    Write-AgfInfo '停止：Stop-Process -Id <pid>；或 scripts\dev-up.ps1 -Down'
}
finally {
    Pop-Location
}
exit 0
