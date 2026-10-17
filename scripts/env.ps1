<#
.SYNOPSIS
    AIGuardFabric 环境初始化（所有脚本的统一入口）。

.DESCRIPTION
    落实 §0 路径纪律：
      * 项目根是唯一写入区，所有脚本都从这里取路径，绝不硬编码绝对路径；
      * 需要新装的东西一律落在项目内（tools/、.cargo/、.npm/、.pnpm-store/、.venv/），
        禁止污染 D:\Environment 与全局 PATH；
      * 本机既有工具链只读复用（D:\Environment）。

    用法（其它脚本第一行）：
        . "$PSScriptRoot\env.ps1"

    静默模式：调用方在 dot-source 之前设置
        $env:AGF_ENV_QUIET = '1'
    本文件**不使用 param()** —— dot-source 时调用方的 param 块优先生效，
    参数化会导致脚本行为随调用方变化（踩过的坑，见 docs/pending-verification.md 的实现注记）。

.NOTES
    本文件被 dot-source，因此**不要**在顶层使用 exit；用 throw 表达致命错误。
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# 静默开关（环境变量而非参数，避免 dot-source 参数冲突）
$AgfQuiet = ($env:AGF_ENV_QUIET -eq '1')

# ---------------------------------------------------------------------------
# 0. 控制台编码：脚本以 UTF-8(BOM) 保存，Windows PowerShell 5.1 与 pwsh 7 均可正确读取中文
# ---------------------------------------------------------------------------
try {
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [Console]::OutputEncoding = $utf8
    $OutputEncoding = $utf8
}
catch {
    # 某些宿主（如 ISE 重定向）不允许修改编码；忽略即可，不影响功能
}

# ---------------------------------------------------------------------------
# 1. 项目根（本文件位于 <root>/scripts/）
# ---------------------------------------------------------------------------
$script:AgfRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$global:AgfRoot = $script:AgfRoot

# ---------------------------------------------------------------------------
# 2. 加载 .env（若存在）；不存在时回退到 .env.example 的默认值
# ---------------------------------------------------------------------------
function Read-DotEnv {
    param([Parameter(Mandatory)][string]$Path)
    $map = @{}
    if (-not (Test-Path -LiteralPath $Path)) { return $map }
    foreach ($line in Get-Content -LiteralPath $Path -Encoding UTF8) {
        $t = $line.Trim()
        if ($t.Length -eq 0) { continue }
        if ($t.StartsWith('#')) { continue }
        $idx = $t.IndexOf('=')
        if ($idx -lt 1) { continue }
        $k = $t.Substring(0, $idx).Trim()
        $v = $t.Substring($idx + 1).Trim()
        # 去掉成对引号
        if ($v.Length -ge 2 -and (($v.StartsWith('"') -and $v.EndsWith('"')) -or ($v.StartsWith("'") -and $v.EndsWith("'")))) {
            $v = $v.Substring(1, $v.Length - 2)
        }
        $map[$k] = $v
    }
    return $map
}

$envFile = Join-Path $AgfRoot '.env'
$global:AgfEnv = Read-DotEnv -Path $envFile
$global:AgfEnvLoadedFrom = if (Test-Path -LiteralPath $envFile) { $envFile } else { '<none>' }

function Get-AgfEnv {
    <#
    .SYNOPSIS
        读取配置：优先级 = 进程环境变量 > .env > 传入默认值。
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Default = ''
    )
    $fromProcess = [Environment]::GetEnvironmentVariable($Name)
    if (-not [string]::IsNullOrEmpty($fromProcess)) { return $fromProcess }
    if ($AgfEnv.ContainsKey($Name)) { return $AgfEnv[$Name] }
    return $Default
}

# ---------------------------------------------------------------------------
# 3. 关键路径（全部由项目根推导，绝不硬编码）
# ---------------------------------------------------------------------------
$global:AgfToolsDir   = Get-AgfEnv -Name 'AGF_TOOLS_DIR'  -Default (Join-Path $AgfRoot 'tools')
$global:AgfDataDir    = Get-AgfEnv -Name 'AGF_DATA_DIR'   -Default (Join-Path $AgfRoot 'data')
$global:AgfVendorDir  = Get-AgfEnv -Name 'AGF_VENDOR_DIR' -Default (Join-Path $AgfRoot 'vendor')
$global:AgfModelsDir  = Get-AgfEnv -Name 'AGF_MODELS_DIR' -Default (Join-Path $AgfRoot 'models')
$global:AgfEnvRoot    = Get-AgfEnv -Name 'AGF_ENV_ROOT'   -Default 'D:\Environment'

# ---------------------------------------------------------------------------
# 4. 缓存重定向（铁律 2：缓存写项目内，避免写系统盘）
#
# CARGO_HOME 保存 registry/git 下载与缓存记账，并不是只读工具链目录。
# 将其重定向到项目内 .cargo；cargo/rustc 代理仍通过 PATH 复用既有安装，
# rustup 工具链由独立的 RUSTUP_HOME 定位，保持不变。
#   * 工具链：复用本机既有环境；依赖缓存：使用 <root>/.cargo；
#   * 构建产物：由项目内 .cargo/config.toml 的 build.target-dir 重定向到 <root>/target，
#     并同时设置 CARGO_TARGET_DIR 双保险；
#   * 项目内安装的 CLI：cargo install --root <root>/tools（见 dev-up.ps1 / Justfile）。
# 结论：D:\Environment 只读复用，项目目录是唯一写入区。
# ---------------------------------------------------------------------------
$global:AgfCargoHome = Join-Path $AgfRoot '.cargo'
$global:AgfNpmCache  = Join-Path $AgfRoot '.npm'
$global:AgfPnpmStore = Join-Path $AgfRoot '.pnpm-store'
$global:AgfVenvDir   = Join-Path $AgfRoot '.venv'

$env:AGF_PROJECT_ROOT = $AgfRoot
$env:AGF_DATA_DIR = $AgfDataDir
$env:CARGO_HOME = $AgfCargoHome
$env:CARGO_TARGET_DIR = Join-Path $AgfRoot 'target'
$env:CARGO_INSTALL_ROOT = Join-Path $AgfRoot 'tools'
$env:npm_config_cache = $AgfNpmCache
# pnpm 11 不再读取 npm_config_*；使用其专用配置变量。
$env:pnpm_config_store_dir = $AgfPnpmStore
$env:PNPM_HOME = (Join-Path $AgfRoot 'tools\pnpm')

# ---------------------------------------------------------------------------
# 5. PATH 前置（项目内工具优先，但不动系统环境变量）
# ---------------------------------------------------------------------------
function Add-PathPrefix {
    param([Parameter(Mandatory)][string]$Directory)
    if (-not (Test-Path -LiteralPath $Directory)) { return }
    $parts = $env:PATH -split [IO.Path]::PathSeparator
    if ($parts -notcontains $Directory) {
        $env:PATH = $Directory + [IO.Path]::PathSeparator + $env:PATH
    }
}

Add-PathPrefix (Join-Path $AgfToolsDir 'bin')
Add-PathPrefix (Join-Path $AgfRoot '.cargo\bin')

# 本机既有工具链（只读复用；已存在则不会重复加入）
$candidates = @(
    (Join-Path $AgfEnvRoot 'Rust\cargo\bin'),
    (Join-Path $AgfEnvRoot 'nvm4w\nodejs'),
    (Join-Path $AgfEnvRoot 'Git\cmd'),
    (Join-Path $AgfEnvRoot 'Docker\resources\bin')
)
foreach ($c in $candidates) { Add-PathPrefix $c }

# ---------------------------------------------------------------------------
# 6. 便捷工具函数
# ---------------------------------------------------------------------------
function Get-AgfTool {
    <#
    .SYNOPSIS
        解析可执行文件路径：优先项目内 tools/bin，其次 PATH。
    #>
    param([Parameter(Mandatory)][string]$Name)
    $local = Join-Path $AgfToolsDir "bin\$Name.exe"
    if (Test-Path -LiteralPath $local) { return $local }
    $localNoExt = Join-Path $AgfToolsDir "bin\$Name"
    if (Test-Path -LiteralPath $localNoExt) { return $localNoExt }
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -ne $cmd) { return $cmd.Source }
    return $null
}

function Invoke-Agf {
    <#
    .SYNOPSIS
        运行外部命令并正确处理退出码（PowerShell 的 $ErrorActionPreference='Stop' 对
        原生命令 stderr 过于敏感，这里显式判定 $LASTEXITCODE）。
    #>
    param(
        [Parameter(Mandatory)][string]$Exe,
        [string[]]$Arguments = @(),
        [string]$WorkingDirectory = $AgfRoot,
        [switch]$AllowFailure
    )
    Push-Location -LiteralPath $WorkingDirectory
    try {
        & $Exe @Arguments
        $code = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
    if ($code -ne 0 -and -not $AllowFailure) {
        throw "命令失败（退出码 $code）: $Exe $($Arguments -join ' ')"
    }
    return $code
}

function Test-AgfPort {
    <#
    .SYNOPSIS
        检测本机端口是否被占用。
    #>
    param([Parameter(Mandatory)][int]$Port)
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -eq $Port }
    return ($null -ne $listeners -and @($listeners).Count -gt 0)
}

function Get-AgfDirectorySize {
    <#
    .SYNOPSIS
        目录占用（字节）。目录不存在或无文件返回 0。
    .NOTES
        Set-StrictMode 下访问不存在的 .Sum 属性会抛异常，因此显式累加。
    #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return [int64]0 }
    $total = [int64]0
    $files = Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        try { $total += [int64]$f.Length } catch { }
    }
    return $total
}

function Format-AgfSize {
    param([Parameter(Mandatory)][int64]$Bytes)
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N2} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N2} KB' -f ($Bytes / 1KB)) }
    return "$Bytes B"
}

function Write-AgfBanner {
    param([Parameter(Mandatory)][string]$Text)
    $line = '=' * 74
    Write-Host $line -ForegroundColor DarkCyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor DarkCyan
}

function Write-AgfStep {
    param([Parameter(Mandatory)][string]$Text)
    Write-Host "==> $Text" -ForegroundColor Green
}

function Write-AgfWarn {
    param([Parameter(Mandatory)][string]$Text)
    Write-Host "[警告] $Text" -ForegroundColor Yellow
}

function Write-AgfError {
    param([Parameter(Mandatory)][string]$Text)
    Write-Host "[错误] $Text" -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# 7. 环境摘要（除非 AGF_ENV_QUIET=1）
# ---------------------------------------------------------------------------
if (-not $AgfQuiet) {
    Write-Host "AIGuardFabric 环境已初始化" -ForegroundColor Cyan
    Write-Host ("  项目根        : {0}" -f $AgfRoot)
    Write-Host ("  只读工具链    : {0}" -f $AgfEnvRoot)
    Write-Host ("  配置来源      : {0}" -f $AgfEnvLoadedFrom)
    Write-Host ("  构建产物      : {0}" -f $env:CARGO_TARGET_DIR)
    Write-Host ("  项目内 CLI    : {0}" -f $env:CARGO_INSTALL_ROOT)
    Write-Host ("  项目依赖缓存  : {0}" -f $env:CARGO_HOME)
}
