# 自检分段 2：工具链版本与数据卷占用。

# ---------------------------------------------------------------------------
# 2. 工具版本
# ---------------------------------------------------------------------------
if (-not $Json) { Write-Host ''; Write-Host '--- 2. 工具链版本 ---' -ForegroundColor DarkCyan }

$tools = @(
    @{ name = 'rustc';          args = @('--version') },
    @{ name = 'cargo';          args = @('--version') },
    @{ name = 'rustfmt';        args = @('--version') },
    @{ name = 'cargo-clippy';   args = @('--version') },
    @{ name = 'node';           args = @('--version') },
    @{ name = 'npm';            args = @('--version') },
    @{ name = 'pnpm';           args = @('--version') },
    @{ name = 'git';            args = @('--version') },
    @{ name = 'docker';         args = @('--version') }
)
foreach ($t in $tools) {
    $v = Get-ToolVersion -Name $t.name -VersionArgs $t.args
    if ($null -eq $v) {
        Add-Check -Name $t.name -Status warn -Detail '未找到（相关步骤将被跳过并登记到 pending-verification）'
    }
    else {
        Add-Check -Name $t.name -Status ok -Detail $v
    }
}

$compose = Get-ToolVersion -Name 'docker' -VersionArgs @('compose', 'version')
if ($null -eq $compose) {
    Add-Check -Name 'docker compose' -Status warn -Detail 'docker compose 子命令不可用'
}
else {
    Add-Check -Name 'docker compose' -Status ok -Detail $compose
}

# ---------------------------------------------------------------------------
# 3. 数据卷占用
# ---------------------------------------------------------------------------
if (-not $Json) { Write-Host ''; Write-Host '--- 3. 数据卷占用 ---' -ForegroundColor DarkCyan }

$volumes = @('pg', 'redis', 'nats', 'clickhouse', 'minio', 'evidence', 'seed', 'backup', 'grafana')
$total = [int64]0
foreach ($v in $volumes) {
    $p = Join-Path $AgfDataDir $v
    $size = Get-AgfDirectorySize -Path $p
    $total += $size
    $exists = Test-Path -LiteralPath $p
    Add-Check -Name "data/$v" -Status info -Detail ("{0}{1}" -f (Format-AgfSize -Bytes $size), $(if ($exists) { '' } else { '（尚未创建）' }))
}
Add-Check -Name 'data 合计' -Status info -Detail (Format-AgfSize -Bytes $total)

foreach ($v in $volumes) {
    $p = Join-Path $AgfDataDir $v
    if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Force -Path $p | Out-Null }
}

# 缓存目录占用（验证铁律 2 生效）
foreach ($c in @('.cargo', '.pnpm-store', 'target', 'tools')) {
    $p = Join-Path $AgfRoot $c
    Add-Check -Name "缓存 $c" -Status info -Detail (Format-AgfSize -Bytes (Get-AgfDirectorySize -Path $p))
}
