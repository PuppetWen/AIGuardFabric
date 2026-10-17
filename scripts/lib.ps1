#Requires -Version 5.1
<#
.SYNOPSIS
    AIGuardFabric 脚本公共库：路径解析、JSON/文件 IO、确定性伪随机、统一控制台输出。

.DESCRIPTION
    被其它脚本 dot-source：`. "$PSScriptRoot\lib.ps1"`（lib.ps1 内部会 dot-source env.ps1）。

    为什么要这个库：
      * JSON 在 Windows PowerShell 5.1 的 ConvertTo-Json 会产生 "<冒号><两个空格>" 的非标准空白，
        且 -Depth 默认只有 2；本库统一处理（-Depth 30 + 空白归一）；
      * 5.1 下 $PSCommandPath / [System.IO.File]::WriteAllText 可用，但 UTF8 编码行为不一致，
        本库固定"无 BOM UTF-8"写文件 + "带 BOM UTF-8"写 .ps1（PS 5.1 才不会按 GBK 解码中文）；
      * 合成样本需要**可复现**的伪随机（固定种子），而不是 New-Object System.Random 无种子版本。

.NOTES
    本文件被 dot-source，因此**不要**在顶层使用 exit；用 throw 表达致命错误。
    不使用 param()（同 env.ps1，避免 dot-source 时的参数冲突）。
#>

if (-not (Get-Variable -Name AgfRoot -Scope Global -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot\env.ps1"
}

# ---------------------------------------------------------------------------
# 路径
# ---------------------------------------------------------------------------
$global:AgfScriptsDir = $PSScriptRoot

function Get-AgfPath {
    <#
    .SYNOPSIS
        相对项目根拼路径（保证所有脚本都从 $AgfRoot 推导，绝不硬编码）。
    #>
    param([Parameter(Mandatory)][string]$Relative)
    # 用 $global:AgfRoot：本文件被 dot-source 进调用方作用域，函数体内的 $AgfRoot
    # 可能因作用域不同而取不到（Set-StrictMode Latest 会直接报错），全局变量最稳。
    return (Join-Path $global:AgfRoot $Relative)
}

function New-AgfDirectory {
    <#
    .SYNOPSIS
        创建目录（幂等），返回是否**新建**。父目录一并创建。
    #>
    param([Parameter(Mandatory)][string]$Path)
    if (Test-Path -LiteralPath $Path) { return $false }
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    return $true
}

# ---------------------------------------------------------------------------
# 文件 IO
# ---------------------------------------------------------------------------
function Write-AgfTextFile {
    <#
    .SYNOPSIS
        以 UTF-8 写文本文件。默认**无 BOM**（数据/JSON/Markdown/日志），
        -WithBom 时带 BOM（scripts/*.ps1 必须带 BOM，否则 PS 5.1 按 GBK 解码中文）。
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content,
        [switch]$WithBom
    )
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-AgfDirectory -Path $dir | Out-Null }
    $enc = New-Object System.Text.UTF8Encoding([bool]$WithBom)
    [System.IO.File]::WriteAllText($Path, $Content, $enc)
}

function Write-AgfJsonFile {
    <#
    .SYNOPSIS
        写 JSON 文件：-Depth 30 + 修正 PS 5.1 的 "<冒号>双空格" 空白 + UTF-8 无 BOM。
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Object,
        [int]$Depth = 30
    )
    $json = ($Object | ConvertTo-Json -Depth $Depth)
    # PS 5.1 会输出 `"k":  1`（冒号后两个空格）；归一为 `"k": 1`
    $json = [regex]::Replace($json, '":\s{2,}', '": ')
    Write-AgfTextFile -Path $Path -Content $json
}

function Read-AgfJsonFile {
    <#
    .SYNOPSIS
        读 JSON 文件（缺失返回 $null）。
    #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
}

# ---------------------------------------------------------------------------
# 确定性伪随机（合成样本可复现）
# ---------------------------------------------------------------------------
function New-AgfSeededRandom {
    <#
    .SYNOPSIS
        固定种子的 PRNG。同一 seed 永远生成同一序列，保证合成样本幂等。
    #>
    param([int]$Seed = 20260221)
    return (New-Object System.Random($Seed))
}

function Get-AgfSeededPick {
    <#
    .SYNOPSIS
        从数组中确定性地取一个元素。
    #>
    param(
        [Parameter(Mandatory)][System.Random]$Random,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Items
    )
    if ($Items.Count -eq 0) { throw 'Get-AgfSeededPick: Items 为空' }
    return $Items[$Random.Next(0, $Items.Count)]
}

function Get-AgfStableHash {
    <#
    .SYNOPSIS
        内容指纹（sha256 前 16 位十六进制）。用于"文件是否变化"的幂等判定。
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $hash = $sha.ComputeHash($bytes)
    }
    finally {
        $sha.Dispose()
    }
    return (($hash | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0, 16)
}

# ---------------------------------------------------------------------------
# 控制台输出（与 env.ps1 的 Write-Agf* 配套；这里只补几种状态标签）
# ---------------------------------------------------------------------------
function Write-AgfOk {
    param([Parameter(Mandatory)][string]$Text)
    Write-Host "[ OK ] $Text" -ForegroundColor Green
}

function Write-AgfInfo {
    param([Parameter(Mandatory)][string]$Text)
    Write-Host "[INFO] $Text" -ForegroundColor Cyan
}

function Write-AgfSkip {
    param([Parameter(Mandatory)][string]$Text)
    Write-Host "[SKIP] $Text" -ForegroundColor DarkGray
}

function Write-AgfFail {
    param([Parameter(Mandatory)][string]$Text)
    Write-Host "[FAIL] $Text" -ForegroundColor Red
}

function Write-AgfExpect {
    <#
    .SYNOPSIS
        打印"预期结果"（demo.ps1 每一步都要有）。
    #>
    param(
        [Parameter(Mandatory)][string]$Expected,
        [string]$Actual = ''
    )
    Write-Host ("   预期: {0}" -f $Expected) -ForegroundColor Cyan
    if ($Actual) { Write-Host ("   实测: {0}" -f $Actual) -ForegroundColor Gray }
}

function Assert-AgfSwitch {
    <#
    .SYNOPSIS
        互斥参数校验（如 -Execute 与 -WhatIf 不可同用）。
    #>
    param(
        [Parameter(Mandatory)][string[]]$Names,
        [Parameter(Mandatory)][string[]]$Values
    )
    $on = @()
    for ($i = 0; $i -lt $Names.Count; $i++) {
        if ($Values[$i]) { $on += $Names[$i] }
    }
    if ($on.Count -gt 1) {
        throw ("参数互斥：{0} 只能选一个" -f ($on -join ' / '))
    }
}

# ---------------------------------------------------------------------------
# HTTP（PS 5.1 默认走 IE 引擎，必须强制 TLS1.2 并禁用进度条）
# ---------------------------------------------------------------------------
function Get-AgfWebRequest {
    <#
    .SYNOPSIS
        下载 URL 到文件或返回文本。失败**抛异常**（绝不静默跳过）。
    .NOTES
        PS 5.1 的 Invoke-WebRequest 默认不启用 TLS 1.2，且 $ProgressPreference='Continue'
        会让大文件下载极慢，这里统一处理。
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$OutFile = '',
        [int]$TimeoutSec = 30
    )
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $prevProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        if ($OutFile) {
            $dir = Split-Path -Parent $OutFile
            if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-AgfDirectory -Path $dir | Out-Null }
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop | Out-Null
            return $OutFile
        }
        return (Invoke-WebRequest -Uri $Uri -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop).Content
    }
    finally {
        $ProgressPreference = $prevProgress
    }
}

function Test-AgfHttpStatus {
    <#
    .SYNOPSIS
        只探测 URL 可达性，返回状态码（失败返回 0，不抛异常——干跑时用）。
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [int]$TimeoutSec = 15
    )
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $prevProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        $resp = Invoke-WebRequest -Uri $Uri -TimeoutSec $TimeoutSec -UseBasicParsing -Method Head -ErrorAction Stop
        return [int]$resp.StatusCode
    }
    catch {
        return 0
    }
    finally {
        $ProgressPreference = $prevProgress
    }
}
