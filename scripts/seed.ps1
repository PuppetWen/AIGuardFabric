#Requires -Version 5.1
<#
.SYNOPSIS
    灌入演示数据（资产 / 风险检出 / 告警 / 案件 / 政策 / 红队结果）。

.DESCRIPTION
    数据来源：data/seed/（由 scripts/gen-fixtures.ps1 生成的**合成**数据集，
    清单见 data/seed/index.json）。本脚本有三种落地路径，**按可用性逐级降级并如实报告**：

      1. `cargo run -p agf-cli -- seed ...`
         项目首选路径。当前仓库 `crates/agf-cli/src/main.rs` 仍是脚手架
         （只打印"agfctl 脚手架：实现见 docs/roadmap.md"），**没有 seed 子命令**——
         因此脚本会明确打印"该子命令尚未实现"，并把该缺陷登记到
         docs/pending-verification.scripts.md，**绝不假装成功**。

      2. `-ApiBase <url>`：显式指定后端地址时，尝试 `POST <ApiBase><AGF_API_PREFIX>/seed/<数据集>`。
         2xx 记为成功；404/405 记为"接口尚未实现"；其它非 2xx 记为失败（不吞错）。

      3. 都没有时：只做**离线校验**（清单完整性、条数、必填字段），
         并打印如何用离线演示替代（scripts/demo.ps1 不依赖后端）。

.PARAMETER ApiBase
    后端基地址（如 http://127.0.0.1:8080）。给定时才会发 HTTP 请求。

.PARAMETER UseCli
    允许尝试 `cargo run -p agf-cli -- seed`（默认允许；该命令会编译，耗时较长）。

.PARAMETER NoCli
    完全不尝试 CLI（只做离线校验 / HTTP 灌库）。

.PARAMETER WhatIf
    只打印计划（要灌哪些数据集、条数、目标），不执行 CLI、不发 HTTP、不写盘。

.PARAMETER Force
    允许重复灌入（默认也会灌，但会先提示"重复灌入可能产生重复行"）。

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\seed.ps1 -WhatIf

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\seed.ps1

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\seed.ps1 -ApiBase http://127.0.0.1:8080

.NOTES
    退出码：0 = 离线校验通过（可能伴随"子命令未实现"的说明）；1 = 校验失败或 HTTP 灌库失败。
#>

[CmdletBinding()]
param(
    [string]$ApiBase = '',
    [switch]$UseCli,
    [switch]$NoCli,
    [switch]$WhatIf,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$env:AGF_ENV_QUIET = '1'
. "$PSScriptRoot\lib.ps1"

if (-not $NoCli) { $UseCli = $true }
if ($UseCli -and $NoCli) {
    Write-AgfError '-UseCli 与 -NoCli 互斥'
    exit 2
}

$seedDir = Get-AgfPath 'data\seed'
$indexPath = Join-Path $seedDir 'index.json'

Write-AgfBanner 'AIGuardFabric 演示数据灌入（seed）'
Write-Host ("  数据目录 : {0}" -f $seedDir)
Write-Host ("  模式     : {0}" -f $(if ($WhatIf) { 'WhatIf（只打印计划）' } else { '执行' }))
Write-Host ("  CLI 路径 : {0}" -f $(if ($UseCli) { 'cargo run -p agf-cli -- seed（当前为脚手架，预计不可用）' } else { '已禁用（-NoCli）' }))
Write-Host ("  HTTP 路径: {0}" -f $(if ($ApiBase) { "$ApiBase（显式指定）" } else { '未指定（不会发请求）' }))
Write-Host ''

# ---------------------------------------------------------------------------
# 1. 读取清单
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $indexPath)) {
    Write-AgfError "缺少数据清单 $indexPath"
    Write-Host '  先生成演示数据：powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\gen-fixtures.ps1' -ForegroundColor Yellow
    exit 1
}
$index = Read-AgfJsonFile -Path $indexPath
if ($null -eq $index) {
    Write-AgfError "数据清单解析失败：$indexPath（JSON 非法？）"
    exit 1
}

Write-AgfStep '1/4 校验演示数据集（离线）'
$requiredFields = @{
    'assets'   = @('id', 'name', 'kind', 'owner', 'department', 'classification', 'lifecycle')
    'findings' = @('id', 'asset_id', 'title', 'severity', 'status', 'rule_id')
    'alerts'   = @('id', 'title', 'severity', 'status', 'asset')
    'cases'    = @('id', 'title', 'severity', 'status', 'owner')
    'policies' = @('id', 'name', 'effect', 'target', 'status')
    'redteam_cases' = @('id', 'family', 'title', 'severity', 'status')
}
$problems = New-Object System.Collections.Generic.List[string]
$plan = New-Object System.Collections.Generic.List[object]

foreach ($ds in $index.datasets) {
    $file = Join-Path $seedDir $ds.file
    $exists = Test-Path -LiteralPath $file
    $declared = [int]$ds.count
    $actual = 0
    $fieldIssues = 0
    if ($exists) {
        $payload = Read-AgfJsonFile -Path $file
        if ($null -eq $payload) {
            $problems.Add("$($ds.file): JSON 解析失败")
        }
        else {
            $actual = @($payload.items).Count
            if ($actual -ne $declared) {
                $problems.Add("$($ds.file): 清单声明 $declared 条，实际 $actual 条")
            }
            if ($requiredFields.ContainsKey($ds.name)) {
                $need = $requiredFields[$ds.name]
                $i = 0
                foreach ($item in @($payload.items)) {
                    $i++
                    foreach ($f in $need) {
                        if (-not $item.PSObject.Properties.Name.Contains($f)) {
                            $fieldIssues++
                            $problems.Add("$($ds.file) #$i 缺字段 '$f'")
                        }
                    }
                }
            }
        }
    }
    else {
        $problems.Add("$($ds.file): 文件不存在")
    }
    $plan.Add([pscustomobject]@{
            name     = $ds.name
            file     = $ds.file
            table    = $ds.table
            declared = $declared
            actual   = $actual
            exists   = $exists
            fieldIssues = $fieldIssues
        })
}

foreach ($p in $plan) {
    $flag = if (-not $p.exists) { '[FAIL]' } elseif ($p.actual -ne $p.declared) { '[WARN]' } else { '[ OK ]' }
    $color = if ($flag -eq '[FAIL]') { 'Red' } elseif ($flag -eq '[WARN]') { 'Yellow' } else { 'Green' }
    Write-Host ("  {0} {1,-16} {2,-20} 声明 {3,3} 条 / 实际 {4,3} 条 → 表 {5}" -f `
            $flag, $p.name, $p.file, $p.declared, $p.actual, $p.table) -ForegroundColor $color
}
if ($problems.Count -gt 0) {
    Write-Host ''
    Write-AgfWarn ("离线校验发现 $($problems.Count) 处问题：")
    foreach ($p in $problems) { Write-Host "    - $p" -ForegroundColor Yellow }
}

# ---------------------------------------------------------------------------
# 2. 计划
# ---------------------------------------------------------------------------
Write-AgfStep '2/4 灌库计划'
if ($WhatIf) {
    foreach ($p in $plan) {
        Write-Host ("  [WhatIf] {0} → 表 {1}（{2} 条）" -f $p.file, $p.table, $p.actual) -ForegroundColor DarkYellow
    }
    Write-Host ''
    Write-AgfInfo 'WhatIf 模式：未执行 CLI、未发 HTTP、未写盘。'
    exit 0
}

# ---------------------------------------------------------------------------
# 3. 路径一：agf-cli seed
# ---------------------------------------------------------------------------
Write-AgfStep '3/4 尝试 CLI 灌库（cargo run -p agf-cli -- seed）'
$cliDone = $false
$cargo = Get-AgfTool -Name 'cargo'
if (-not $UseCli) {
    Write-AgfSkip '已按 -NoCli 跳过 CLI 路径'
}
elseif ($null -eq $cargo) {
    Write-AgfWarn 'cargo 不可用（未找到）；跳过 CLI 路径'
}
else {
    Write-Host "  执行: cargo run -p agf-cli -- seed --dir `"$seedDir`"" -ForegroundColor DarkGray
    Write-Host '  （首次会编译 workspace，可能耗时数分钟；输出见下）' -ForegroundColor DarkGray
    Push-Location -LiteralPath $AgfRoot
    try {
        $cliOut = & $cargo run -p agf-cli -- seed --dir $seedDir 2>&1 | Out-String
        $cliCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
    Write-Host $cliOut.Trim() -ForegroundColor DarkGray
    Write-Host ("  agf-cli 退出码: {0}" -f $cliCode) -ForegroundColor DarkGray

    # 判定：当前 agf-cli 是脚手架（打印固定文案并 exit 0），没有 seed 子命令
    if ($cliOut -match '脚手架' -or $cliOut -match 'scaffold') {
        Write-Host ''
        Write-AgfWarn 'agf-cli 的 seed 子命令**尚未实现**（crates/agf-cli 仍是脚手架，只打印占位文案）。'
        Write-Host '        该缺陷已登记：docs/pending-verification.scripts.md' -ForegroundColor Yellow
        Write-Host '        CLI 未真正灌入任何数据——本步骤**不视为成功**。' -ForegroundColor Yellow
    }
    elseif ($cliCode -eq 0) {
        Write-AgfOk 'agf-cli seed 执行成功（退出码 0）'
        $cliDone = $true
    }
    else {
        Write-AgfError ("agf-cli seed 失败（退出码 {0}）——请检查上面的输出" -f $cliCode)
    }
}

# ---------------------------------------------------------------------------
# 4. 路径二：HTTP 灌库（仅在显式 -ApiBase 时）
# ---------------------------------------------------------------------------
Write-AgfStep '4/4 HTTP 灌库'
$apiPrefix = Get-AgfEnv -Name 'AGF_API_PREFIX' -Default '/api/v1'
$httpDone = 0
$httpFailed = 0
$httpNotImpl = 0

if (-not $ApiBase) {
    Write-AgfSkip "未指定 -ApiBase：跳过 HTTP 灌库（离线校验完成即退出）"
    Write-Host '        如需 HTTP 灌库：-ApiBase http://127.0.0.1:8080（需 agf-server 已启动）' -ForegroundColor DarkGray
}
else {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $base = $ApiBase.TrimEnd('/')
    Write-AgfInfo ("目标后端: {0}{1}/seed/<数据集>" -f $base, $apiPrefix)
    foreach ($p in $plan) {
        if (-not $p.exists) {
            Write-AgfFail ("{0}: 文件缺失，跳过" -f $p.name)
            $httpFailed++
            continue
        }
        $uri = "{0}{1}/seed/{2}" -f $base, $apiPrefix, $p.name
        $body = Get-Content -LiteralPath (Join-Path $seedDir $p.file) -Raw -Encoding UTF8
        try {
            $resp = Invoke-WebRequest -Uri $uri -Method Post -ContentType 'application/json; charset=utf-8' `
                -Body ([System.Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 30 -UseBasicParsing -ErrorAction Stop
            Write-AgfOk ("{0,-16} HTTP {1} → 已灌入 {2} 条" -f $p.name, $resp.StatusCode, $p.actual)
            $httpDone++
        }
        catch {
            $status = 0
            if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
            if ($status -eq 404 -or $status -eq 405) {
                Write-AgfWarn ("{0,-16} HTTP {1} → 后端接口尚未实现（跳过）" -f $p.name, $status)
                $httpNotImpl++
            }
            else {
                Write-AgfError ("{0,-16} HTTP {1} → {2}" -f $p.name, $status, $_.Exception.Message)
                $httpFailed++
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------
Write-Host ''
Write-AgfBanner '灌库结果'
$verified = ($problems.Count -eq 0)
Write-Host ("  离线校验 : {0}（{1} 个数据集）" -f $(if ($verified) { '通过' } else { "有 $($problems.Count) 处问题" }), $plan.Count)
Write-Host ("  CLI 灌库 : {0}" -f $(if ($cliDone) { '成功' } else { '未成功（agf-cli seed 子命令未实现 / 被跳过）' }))
Write-Host ("  HTTP 灌库: {0}" -f $(if (-not $ApiBase) { '未执行（未指定 -ApiBase）' } else { "成功 $httpDone / 接口未实现 $httpNotImpl / 失败 $httpFailed" }))
Write-Host ''

if ($problems.Count -gt 0) {
    Write-AgfError '离线校验未通过：请先运行 scripts\gen-fixtures.ps1 修复数据集'
    exit 1
}
if ($httpFailed -gt 0) {
    Write-AgfError "HTTP 灌库有 $httpFailed 个数据集失败"
    exit 1
}

Write-Host '说明：' -ForegroundColor Cyan
Write-Host '  * 演示数据（合成）已就绪于 data/seed/，可用于**离线**全链路演示：' -ForegroundColor Gray
Write-Host '      powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\demo.ps1' -ForegroundColor Gray
Write-Host '  * 真正的库表灌入（agf-cli seed / HTTP 接口）在 M2 里程碑实现前不可用，' -ForegroundColor Gray
Write-Host '    已登记到 docs/pending-verification.scripts.md（PV-S-002）。' -ForegroundColor Gray

if (-not $cliDone -and -not $ApiBase) {
    Write-Host ''
    Write-AgfWarn '本次**没有**向任何数据库写入数据：CLI 子命令未实现，且未指定 -ApiBase。'
    Write-Host '        这不是失败，而是当前仓库的真实状态；演示请走 scripts\demo.ps1（离线 fixtures）。' -ForegroundColor Yellow
}
exit 0
