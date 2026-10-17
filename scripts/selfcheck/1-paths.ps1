# 自检分段 1：项目根与路径纪律（由 selfcheck.ps1 dot-source，共享同一作用域）。

# ---------------------------------------------------------------------------
# 1. 路径纪律
# ---------------------------------------------------------------------------
# 铁律 1：项目根 = workspace 根（Cargo.toml 直接位于项目根，不再套一层同名子目录）。
# 铁律 4：脚本本身**不硬编码任何绝对路径**。因此"文档约定的默认路径"改为由
# AGF_EXPECTED_ROOT 注入（可选项，不设则只做结构性判定）。
$expectedRoot = Get-AgfEnv -Name 'AGF_EXPECTED_ROOT' -Default ''
if ($expectedRoot) {
    if ($AgfRoot -eq $expectedRoot) {
        Add-Check -Name '项目根' -Status ok -Detail $AgfRoot
    }
    else {
        Add-Check -Name '项目根' -Status warn -Detail "$AgfRoot（AGF_EXPECTED_ROOT 期望 $expectedRoot，请确认）"
    }
}
elseif (Test-Path -LiteralPath (Join-Path $AgfRoot 'Cargo.toml')) {
    Add-Check -Name '项目根' -Status ok -Detail "$AgfRoot（Cargo.toml 直接位于根，符合铁律 1；默认路径比对可设 AGF_EXPECTED_ROOT 开启）"
}
else {
    Add-Check -Name '项目根' -Status fail -Detail "$AgfRoot（根目录下没有 Cargo.toml，不符合铁律 1）"
}

$mustExist = @('Cargo.toml', '.env.example', 'docker-compose.yml', 'crates', 'apps', 'deploy', 'docs', 'scripts', 'tests')
$missing = @()
foreach ($item in $mustExist) {
    if (-not (Test-Path -LiteralPath (Join-Path $AgfRoot $item))) { $missing += $item }
}
if ($missing.Count -eq 0) {
    Add-Check -Name '项目结构完整' -Status ok -Detail "$($mustExist.Count) 项关键路径均存在"
}
else {
    Add-Check -Name '项目结构完整' -Status fail -Detail ("缺失: " + ($missing -join ', '))
}

foreach ($d in @('tools', 'vendor', 'models', 'data', '.cargo')) {
    $p = Join-Path $AgfRoot $d
    if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Force -Path $p | Out-Null }
}
