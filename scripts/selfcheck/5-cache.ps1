# 自检分段 5：项目内缓存重定向验证（铁律 2）。

# ---------------------------------------------------------------------------
# 7. 缓存重定向验证（铁律 2）
#
# 判定口径：
#   * 构建产物必须落项目内（CARGO_TARGET_DIR / .cargo/config.toml）；
#   * 项目内安装在 <root>/tools；
#   * CARGO_HOME 的 registry/git 缓存必须留在项目内；
#   * RUSTUP_HOME 保持既有工具链位置，cargo/rustc 代理通过 PATH 复用。
# ---------------------------------------------------------------------------
if (-not $Json) { Write-Host ''; Write-Host '--- 7. 缓存与产物重定向 ---' -ForegroundColor DarkCyan }

function Test-AgfProjectCachePath {
    param([AllowNull()][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try {
        $rootPath = [IO.Path]::GetFullPath($AgfRoot).TrimEnd('\', '/')
        $candidate = if ([IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path $AgfRoot $Path }
        $fullPath = [IO.Path]::GetFullPath($candidate).TrimEnd('\', '/')
        return $fullPath.Equals($rootPath, [StringComparison]::OrdinalIgnoreCase) -or
            $fullPath.StartsWith($rootPath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
    }
    catch { return $false }
}

$targetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $AgfRoot 'target' }
if (Test-AgfProjectCachePath $targetDir) {
    Add-Check -Name 'CARGO_TARGET_DIR' -Status ok -Detail $targetDir
}
else {
    Add-Check -Name 'CARGO_TARGET_DIR' -Status fail -Detail "$targetDir（构建产物必须落项目内，铁律 2）"
}

$cfgPath = Join-Path $AgfRoot '.cargo\config.toml'
if (Test-Path -LiteralPath $cfgPath) {
    $cfgText = Get-Content -LiteralPath $cfgPath -Raw
    if ($cfgText -match 'target-dir\s*=\s*"target"') {
        Add-Check -Name '.cargo/config.toml' -Status ok -Detail 'build.target-dir = "target"（相对项目内，可迁移）'
    }
    else {
        Add-Check -Name '.cargo/config.toml' -Status warn -Detail '未设置 build.target-dir = "target"'
    }
}
else {
    Add-Check -Name '.cargo/config.toml' -Status warn -Detail '缺失'
}

if (Test-AgfProjectCachePath $env:CARGO_HOME) {
    Add-Check -Name 'CARGO_HOME' -Status ok -Detail "$($env:CARGO_HOME)（项目内依赖缓存；工具链通过 PATH 与 RUSTUP_HOME 复用）"
}
else {
    Add-Check -Name 'CARGO_HOME' -Status fail -Detail "$($env:CARGO_HOME)（依赖缓存必须落项目内）"
}

if ($env:RUSTUP_HOME) {
    Add-Check -Name 'RUSTUP_HOME' -Status ok -Detail "$($env:RUSTUP_HOME)（只读复用）"
}
else {
    Add-Check -Name 'RUSTUP_HOME' -Status info -Detail '未设置（rustup 使用默认位置）'
}

foreach ($cache in @(
    @{ name = 'npm 缓存'; path = $env:npm_config_cache },
    @{ name = 'pnpm 缓存'; path = $env:pnpm_config_store_dir }
)) {
    $status = if (Test-AgfProjectCachePath $cache.path) { 'ok' } else { 'fail' }
    Add-Check -Name $cache.name -Status $status -Detail ("{0}（必须落项目内）" -f $cache.path)
}
