<#
.SYNOPSIS
    AIGuardFabric 零外部依赖自检（§0 铁律 5）。

.DESCRIPTION
    打印并校验：
      1. 项目根（唯一写入区）与路径纪律
      2. 各工具版本（rustc/cargo/node/pnpm/docker/compose/git）
      3. 数据卷占用（data/ 下各子目录）
      4. 端口占用（本平台默认端口）
      5. Docker 守护状态
      6. 关键配置项强度（JWT 密钥、主密钥、数据库口令）
      7. 项目内缓存重定向是否生效
      8. D:\Environment 是否被污染（对比写入时间基线）

    退出码：0 = 通过（可能有警告）；1 = 存在阻断项。

.EXAMPLE
    pwsh -File scripts/selfcheck.ps1
    pwsh -File scripts/selfcheck.ps1 -Json     # 机器可读输出（CI 用）
#>

[CmdletBinding()]
param(
    [switch]$Json,
    [switch]$SkipDocker,
    [switch]$WriteBaseline
)

$env:AGF_ENV_QUIET = '1'
. "$PSScriptRoot\env.ps1"

# ---------------------------------------------------------------------------
# 0. 可选：写入只读工具链基线（用于后续比对"是否被污染"）
# ---------------------------------------------------------------------------
if ($WriteBaseline) {
    $lockDir = Join-Path $AgfRoot 'tools\locks'
    if (-not (Test-Path -LiteralPath $lockDir)) { New-Item -ItemType Directory -Force -Path $lockDir | Out-Null }
    $watch = @(
        (Join-Path $AgfEnvRoot 'Rust'),
        (Join-Path $AgfEnvRoot 'nvm4w'),
        (Join-Path $AgfEnvRoot 'pyenv-win'),
        (Join-Path $AgfEnvRoot 'Java'),
        (Join-Path $AgfEnvRoot 'GoLang'),
        (Join-Path $AgfEnvRoot 'Docker')
    )
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($w in $watch) {
        if (-not (Test-Path -LiteralPath $w)) { continue }
        # 只记录顶层目录与关键文件，避免扫描过慢
        Get-ChildItem -LiteralPath $w -Force -ErrorAction SilentlyContinue | Select-Object -First 200 | ForEach-Object {
            $entries.Add([pscustomobject]@{
                    path       = $_.FullName
                    mtimeTicks = $_.LastWriteTimeUtc.Ticks
                })
        }
    }
    $baseline = [pscustomobject]@{
        generatedAt = (Get-Date).ToString('o')
        envRoot     = $AgfEnvRoot
        note        = 'AIGuardFabric 只读工具链基线：记录 mtime，若后续探测到更新说明 D:\Environment 被写入'
        entries     = $entries
    }
    $out = Join-Path $lockDir 'environment-baseline.json'
    $baseline | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $out -Encoding UTF8
    Write-Host "已写入基线: $out ($($entries.Count) 项)" -ForegroundColor Green
    exit 0
}

$script:Checks = [System.Collections.Generic.List[object]]::new()

function Add-Check {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Status,   # ok | warn | fail | info
        [Parameter(Mandatory)][string]$Detail
    )
    $script:Checks.Add([pscustomobject]@{ name = $Name; status = $Status; detail = $Detail })
    if (-not $Json) {
        $color = switch ($Status) {
            'ok'   { 'Green' }
            'warn' { 'Yellow' }
            'fail' { 'Red' }
            default { 'Gray' }
        }
        $tag = switch ($Status) {
            'ok'   { '[ OK ]' }
            'warn' { '[WARN]' }
            'fail' { '[FAIL]' }
            default { '[INFO]' }
        }
        Write-Host ("{0} {1,-34} {2}" -f $tag, $Name, $Detail) -ForegroundColor $color
    }
}

function Get-ToolVersion {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string[]]$VersionArgs = @('--version')
    )
    $exe = Get-AgfTool -Name $Name
    if ($null -eq $exe) { return $null }
    try {
        # 部分工具把版本写 stderr（如 docker compose），因此合并流
        $out = & $exe @VersionArgs 2>&1 | Out-String
        return ($out -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 } | Select-Object -First 1).Trim()
    }
    catch {
        return $null
    }
}

if (-not $Json) {
    Write-AgfBanner 'AIGuardFabric 自检（零外部依赖）'
    Write-Host ("时间: {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'))
    Write-Host ''
    Write-Host '--- 1. 路径纪律 ---' -ForegroundColor DarkCyan
}
# ---------------------------------------------------------------------------
# 分段执行：各段由 selfcheck/ 下的脚本 dot-source 进来（同一作用域，共享
# $AgfRoot / $script:Checks / Add-Check 等），对外命令与输出完全不变。
# ---------------------------------------------------------------------------
. "$PSScriptRoot\selfcheck\1-paths.ps1"
. "$PSScriptRoot\selfcheck\2-tools-volumes.ps1"
. "$PSScriptRoot\selfcheck\3-ports-docker.ps1"
. "$PSScriptRoot\selfcheck\4-secrets.ps1"
. "$PSScriptRoot\selfcheck\5-cache.ps1"
. "$PSScriptRoot\selfcheck\6-pollution-paths.ps1"
. "$PSScriptRoot\selfcheck\9-report.ps1"
