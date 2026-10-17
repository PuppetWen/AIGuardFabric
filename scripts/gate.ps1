#Requires -Version 5.1
<#
.SYNOPSIS
    AIGuardFabric 全部门禁（§9：scripts/gate.ps1 跑全部门禁）。

.DESCRIPTION
    逐项执行并打印 PASS / FAIL / SKIP 与耗时，最后给出总结与退出码（有 FAIL 则 1）。

    门禁项（与 Justfile 的 gate 目标、提示词 §11.8 对齐）：
      fmt        cargo fmt --all --check
      size       项目源码文件不超过 500 行（含模拟器脚本）
      clippy     cargo clippy --workspace --all-targets -- -D warnings
      test       cargo test --workspace
      onboarding 真实 agf-agent + 本地回环 MCP/模型接入模拟
      targets    scripts/check-test-targets.ps1（孤儿测试目录 / 未被声明的测试源文件）
      rules      规则库正负样本回归（cargo test -p agf-scan --test rules_library）
      deny       cargo deny check（项目内 tools/bin/cargo-deny.exe）
      coverage   cargo llvm-cov（≥70%，见 coverage.ps1）
      web        前端 lint / typecheck / test / build（pnpm，未装依赖时 SKIP）
      compose    docker compose config --quiet（三个 compose 文件）
      selfcheck  scripts/selfcheck.ps1

.PARAMETER Only
    只跑指定项（逗号分隔，如 -Only fmt,clippy）。

.PARAMETER Skip
    跳过指定项（逗号分隔）。

.PARAMETER Coverage
    在门禁里包含覆盖率（默认**不**包含：llvm-cov 需要重建全工作区，耗时数分钟）。

.NOTES
    本机只有 Windows PowerShell 5.1（无 pwsh）；脚本文件必须带 BOM 保存。
    「做不到」的项一律报 SKIP 并写明原因与所需条件，**绝不伪造 PASS**。
    本脚本是入口脚本（非 dot-source），因此可以用 param()。
#>

param(
    [string[]]$Only = @(),
    [string[]]$Skip = @(),
    [switch]$Coverage
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\lib.ps1"

$script:GateResults = @()

function Invoke-GateStep {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action,
        [string]$SkipReason = ''
    )
    if ($SkipReason) {
        Write-AgfSkip ("{0}：{1}" -f $Name, $SkipReason)
        $script:GateResults += [pscustomobject]@{ Name = $Name; Status = 'SKIP'; Seconds = 0.0; Note = $SkipReason }
        return
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Host ("`n=== {0} ===" -f $Name) -ForegroundColor White
    $ok = $true
    $note = ''
    $previousErrorAction = $ErrorActionPreference
    try {
        # PowerShell 5.1 can turn native stderr diagnostics into terminating
        # NativeCommandError records. Each gate checks the process exit code.
        $ErrorActionPreference = 'Continue'
        & $Action
        if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) { $ok = $false; $note = ("退出码 {0}" -f $LASTEXITCODE) }
    }
    catch {
        $ok = $false
        $note = $_.Exception.Message
    }
    finally {
        $ErrorActionPreference = $previousErrorAction
    }
    $sw.Stop()
    $secs = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    if ($ok) { Write-AgfOk ("{0} 通过（{1}s）" -f $Name, $secs) }
    else { Write-AgfFail ("{0} 失败（{1}s）：{2}" -f $Name, $secs, $note) }
    $status = 'FAIL'
    if ($ok) { $status = 'PASS' }
    $script:GateResults += [pscustomobject]@{ Name = $Name; Status = $status; Seconds = $secs; Note = $note }
}

# 注意：管道在只有 1 个元素时返回的是**标量字符串**，不是数组；
# 严格模式下 `$onlyList.Count` 会直接抛 "The property 'Count' cannot be found"
# （实测踩过：`-Only deny` 必崩）。因此一律用 @() 强制成数组，并过滤空项。
$onlyList = @($Only | ForEach-Object { $_.Split(',') } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$skipList = @($Skip | ForEach-Object { $_.Split(',') } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$validSteps = @('fmt', 'clippy', 'size', 'test', 'onboarding', 'targets', 'rules', 'deny', 'coverage', 'web', 'helm', 'compose', 'selfcheck')
foreach ($name in @($onlyList) + @($skipList)) {
    if ($validSteps -notcontains $name) { throw "未知门禁项：$name（可用项：$($validSteps -join ', ')）" }
}

function Test-GateWanted {
    param([Parameter(Mandatory)][string]$Name)
    if ($skipList -contains $Name) { return $false }
    if ($onlyList.Count -gt 0) { return ($onlyList -contains $Name) }
    return $true
}

$root = $global:AgfRoot
Push-Location $root
try {
    if (Test-GateWanted 'fmt') {
        Invoke-GateStep -Name 'fmt' -Action { cargo fmt --all --check }
    }
    if (Test-GateWanted 'clippy') {
        Invoke-GateStep -Name 'clippy' -Action { cargo clippy --workspace --all-targets -- -D warnings }
    }
    if (Test-GateWanted 'size') {
        Invoke-GateStep -Name 'size' -Action { & (Join-Path $PSScriptRoot 'check-file-size.ps1') }
    }
    if (Test-GateWanted 'test') {
        Invoke-GateStep -Name 'test' -Action { cargo test --workspace }
    }
    if (Test-GateWanted 'onboarding') {
        $python = Get-AgfTool -Name 'python'
        if ($null -eq $python) {
            Invoke-GateStep -Name 'onboarding' -Action { } -SkipReason '未找到 Python；使用 D:\Environment 中现有 Python 3 运行本地接入验收'
        }
        else {
            Invoke-GateStep -Name 'onboarding' -Action {
                $previousTarget = $env:CARGO_TARGET_DIR
                try {
                    $work = Join-Path $root '.tmp\gate-onboarding'
                    $env:CARGO_TARGET_DIR = Join-Path $work 'target'
                    cargo build -p agf-agent --offline
                    if ($LASTEXITCODE -ne 0) { throw 'agf-agent 离线构建失败' }
                    & $python (Join-Path $root 'scripts\verify-stdio-onboarding.py') `
                        --agent-bin (Join-Path $env:CARGO_TARGET_DIR 'debug\agf-agent.exe') --work-dir $work
                    if ($LASTEXITCODE -ne 0) { throw '本地接入模拟验收失败' }
                }
                finally { $env:CARGO_TARGET_DIR = $previousTarget }
            }
        }
    }
    if (Test-GateWanted 'targets') {
        # 假绿灯头号来源：`tests/<name>/` 是孤儿子模块（没有 main.rs、也没有同级 <name>.rs），
        # cargo 根本不会编译它 ⇒ "0 failed" 其实是"没跑"。本项静态抓孤儿目录 + 未被声明的 .rs。
        Invoke-GateStep -Name 'targets' -Action { & (Join-Path $PSScriptRoot 'check-test-targets.ps1') }
    }
    if (Test-GateWanted 'rules') {
        Invoke-GateStep -Name 'rules' -Action { cargo test -p agf-scan --test rules_library }
    }
    if (Test-GateWanted 'deny') {
        $deny = Join-Path $root 'tools\bin\cargo-deny.exe'
        if (Test-Path -LiteralPath $deny) {
            Invoke-GateStep -Name 'deny' -Action {
                # 铁律 2：cargo-deny 会把 RustSec 公告库缓存到 $CARGO_HOME/advisory-dbs。
                # 这里以**绝对路径**调用项目内的 cargo-deny.exe（不依赖 rustup 代理），
                # 因此可以安全地把 CARGO_HOME 临时指向项目内 .cargo，避免污染只读工具链目录
                # （实测踩过：不重定向时会在 D:\Environment\Rust\cargo\advisory-dbs 落库）。
                $prevCargoHome = $env:CARGO_HOME
                $prevErrorAction = $ErrorActionPreference
                try {
                    $env:CARGO_HOME = Join-Path $global:AgfRoot '.cargo'
                    # cargo-deny emits non-fatal diagnostics on stderr. Judge its exit code,
                    # not PowerShell 5.1's NativeCommandError wrapper for those warnings.
                    $ErrorActionPreference = 'Continue'
                    & $deny check
                    $code = $LASTEXITCODE
                }
                finally {
                    $ErrorActionPreference = $prevErrorAction
                    $env:CARGO_HOME = $prevCargoHome
                }
                if ($code -ne 0) { throw "cargo deny check 失败（退出码 $code）" }
            }
        }
        else {
            Invoke-GateStep -Name 'deny' -Action { } -SkipReason '未安装 cargo-deny；在项目内安装：cargo install --root tools cargo-deny --locked'
        }
    }
    if (Test-GateWanted 'coverage') {
        if ($Coverage) {
            Invoke-GateStep -Name 'coverage' -Action { & (Join-Path $PSScriptRoot 'coverage.ps1') }
        }
        else {
            Invoke-GateStep -Name 'coverage' -Action { } -SkipReason '默认跳过（耗时长）；需要时加 -Coverage'
        }
    }
    if (Test-GateWanted 'web') {
        $web = Join-Path $root 'apps\web'
        if (Test-Path -LiteralPath (Join-Path $web 'node_modules')) {
            Invoke-GateStep -Name 'web' -Action {
                Push-Location $web
                try {
                    pnpm run lint
                    if ($LASTEXITCODE -ne 0) { throw 'pnpm lint 失败' }
                    pnpm run typecheck
                    if ($LASTEXITCODE -ne 0) { throw 'pnpm typecheck 失败' }
                    pnpm run test
                    if ($LASTEXITCODE -ne 0) { throw 'pnpm test 失败' }
                    pnpm run build
                }
                finally { Pop-Location }
            }
        }
        else {
            Invoke-GateStep -Name 'web' -Action { } -SkipReason 'apps/web/node_modules 不存在；先在 apps/web 里 pnpm install'
        }
    }
    if (Test-GateWanted 'helm') {
        # Helm Chart 校验：lint + 三套 values 的 template 渲染。
        # helm 装在项目内 `tools\bin\helm.exe`（铁律 2：不污染 D:\Environment、不装全局 PATH）。
        $helm = Join-Path $root 'tools\bin\helm.exe'
        $chart = Join-Path $root 'deploy\helm\aiguardfabric'
        if (-not (Test-Path -LiteralPath $helm)) {
            Invoke-GateStep -Name 'helm' -Action { } -SkipReason '未安装 helm；在项目内安装：见 docs/deployment.md（放到 tools\bin\helm.exe）'
        }
        elseif (-not (Test-Path -LiteralPath $chart)) {
            Invoke-GateStep -Name 'helm' -Action { } -SkipReason "未找到 Chart：$chart"
        }
        else {
            Invoke-GateStep -Name 'helm' -Action {
                # 密钥校验（agf.validateSecrets）在缺密钥时会 fail —— 那是**设计意图**，
                # 因此渲染时统一指向外部 Secret（方案 A），只验证模板本身能否渲染。
                & $helm lint $chart
                if ($LASTEXITCODE -ne 0) { throw 'helm lint 失败' }
                foreach ($values in @('values.yaml', 'values-prod.yaml', 'values-airgap.yaml')) {
                    $file = Join-Path $chart $values
                    if (-not (Test-Path -LiteralPath $file)) { continue }
                    & $helm template agf $chart -f $file --set secrets.existingSecret=agf-external-secret | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw "helm template（$values）失败" }
                }
            }
        }
    }
    if (Test-GateWanted 'compose') {
        Invoke-GateStep -Name 'compose' -Action {
            docker compose -f docker-compose.yml --env-file .env.example config --quiet
            if ($LASTEXITCODE -ne 0) { throw 'docker-compose.yml 校验失败' }
            docker compose -f docker-compose.dev.yml --env-file .env.example config --quiet
            if ($LASTEXITCODE -ne 0) { throw 'docker-compose.dev.yml 校验失败' }
            docker compose -f docker-compose.prod.yml --env-file .env.example config --quiet
            if ($LASTEXITCODE -ne 0) { throw 'docker-compose.prod.yml 校验失败' }
        }
    }
    if (Test-GateWanted 'selfcheck') {
        Invoke-GateStep -Name 'selfcheck' -Action { & (Join-Path $PSScriptRoot 'selfcheck.ps1') }
    }
}
finally {
    Pop-Location
}

Write-Host "`n============================== 门禁总结 ==============================" -ForegroundColor White
foreach ($r in $script:GateResults) {
    $line = "{0,-10} {1,-5} {2,6}s  {3}" -f $r.Name, $r.Status, $r.Seconds, $r.Note
    if ($r.Status -eq 'PASS') { Write-Host $line -ForegroundColor Green }
    elseif ($r.Status -eq 'FAIL') { Write-Host $line -ForegroundColor Red }
    else { Write-Host $line -ForegroundColor DarkGray }
}
$pass = ($script:GateResults | Where-Object { $_.Status -eq 'PASS' } | Measure-Object).Count
$fail = ($script:GateResults | Where-Object { $_.Status -eq 'FAIL' } | Measure-Object).Count
$skipped = ($script:GateResults | Where-Object { $_.Status -eq 'SKIP' } | Measure-Object).Count
$totalSecs = [math]::Round((($script:GateResults | Measure-Object -Property Seconds -Sum).Sum), 1)
Write-Host ("结果：{0} 通过 / {1} 失败 / {2} 跳过，合计 {3}s" -f $pass, $fail, $skipped, $totalSecs) -ForegroundColor White

if ($fail -gt 0) {
    Write-AgfFail '存在未通过的门禁项，详见上方 FAIL 行'
    exit 1
}
if ($skipped -gt 0) {
    Write-AgfInfo '存在跳过项（原因见上表）；补齐条件后重跑即可闭环'
}
exit 0
