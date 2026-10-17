# 自检分段 6：只读工具链未被污染比对 + 绝对路径纪律（铁律 4）。

# ---------------------------------------------------------------------------
# 8. 只读工具链未被污染
# ---------------------------------------------------------------------------
if (-not $Json) { Write-Host ''; Write-Host '--- 8. 只读工具链完整性 ---' -ForegroundColor DarkCyan }

if (Test-Path -LiteralPath $AgfEnvRoot) {
    Add-Check -Name 'D:\Environment 可读' -Status ok -Detail $AgfEnvRoot
    $baselineFile = Join-Path $AgfRoot 'tools\locks\environment-baseline.json'
    if (Test-Path -LiteralPath $baselineFile) {
        try {
            $baseline = Get-Content -LiteralPath $baselineFile -Raw -Encoding UTF8 | ConvertFrom-Json
            $changed = @()
            $dirTouched = @()
            foreach ($entry in $baseline.entries) {
                if (-not (Test-Path -LiteralPath $entry.path)) {
                    $changed += "缺失:$($entry.path)"
                }
                else {
                    $item = Get-Item -LiteralPath $entry.path -Force
                    if ($item.LastWriteTimeUtc.Ticks -gt [int64]$entry.mtimeTicks) {
                        if ($item.PSIsContainer) {
                            # 目录自身的 mtime 只要**任何**子项被增删改写就会变。
                            # cargo/rustup 的缓存记账（$CARGO_HOME\.global-cache 等）会周期性
                            # 触碰这些目录，属正常读写而非"安装"，因此目录级变化只作提示；
                            # 文件级变化仍然按警告处理（那才可能意味着工具链被替换）。
                            $dirTouched += $entry.path
                        }
                        else {
                            $changed += "已变更:$($entry.path)"
                        }
                    }
                }
            }
            if ($changed.Count -eq 0) {
                $note = if ($dirTouched.Count -gt 0) {
                    "；{0} 个目录 mtime 有变动（cargo 缓存记账所致，非安装）" -f $dirTouched.Count
                }
                else { '' }
                Add-Check -Name '只读工具链未被修改' -Status ok -Detail ("基线 {0} 项一致（文件级）{1}" -f $baseline.entries.Count, $note)
            }
            else {
                Add-Check -Name '只读工具链未被修改' -Status warn -Detail ("检测到 " + ($changed.Count) + " 项文件级变化: " + (($changed | Select-Object -First 3) -join '; '))
            }
        }
        catch {
            Add-Check -Name '只读工具链未被修改' -Status info -Detail "基线解析失败: $($_.Exception.Message)"
        }
    }
    else {
        Add-Check -Name '只读工具链未被修改' -Status info -Detail "尚无基线；运行 scripts/selfcheck.ps1 -WriteBaseline 生成"
    }
}
else {
    Add-Check -Name 'D:\Environment 可读' -Status warn -Detail '只读工具链根不存在（可能已迁移）'
}

# 检查项目内是否意外产生全局安装痕迹（写入 D:\Environment 的典型位置）
$suspicious = @()
foreach ($p in @('Rust\cargo\bin\agfctl.exe', 'nvm4w\nodejs\node_modules\@aiguardfabric')) {
    $full = Join-Path $AgfEnvRoot $p
    if (Test-Path -LiteralPath $full) { $suspicious += $full }
}
if ($suspicious.Count -eq 0) {
    Add-Check -Name '无全局安装痕迹' -Status ok -Detail '未发现平台组件被装到只读工具链'
}
else {
    Add-Check -Name '无全局安装痕迹' -Status fail -Detail ("发现: " + ($suspicious -join ', '))
}

# ---------------------------------------------------------------------------
# 9. 绝对路径纪律（铁律 4）
#
# 脚本 / 编排 / 镜像里出现盘符绝对路径，就是把"项目位置"写死，
# 一旦换机器或换目录就会直接碎。这条检查把铁律 4 变成可判定项。
# 例外（两种，均为显式声明）：
#   * D:\Environment —— 本机既有只读工具链根，属环境事实，统一由 AGF_ENV_ROOT 注入；
#   * 行内含 `afp-allow-abs-path` 标记 —— 只读复用系统级工具的兜底搜索路径，
#     不由本项目写死项目位置。
# ---------------------------------------------------------------------------
if (-not $Json) { Write-Host ''; Write-Host '--- 9. 绝对路径纪律（铁律 4）---' -ForegroundColor DarkCyan }

$scanFiles = @()
$scanFiles += @(Get-ChildItem -Path (Join-Path $AgfRoot 'scripts') -Filter '*.ps1' -File -ErrorAction SilentlyContinue)
foreach ($rel in @('docker-compose.yml', 'deploy\docker\Dockerfile', 'Justfile')) {
    $p = Join-Path $AgfRoot $rel
    if (Test-Path -LiteralPath $p) { $scanFiles += @(Get-Item -LiteralPath $p) }
}
$offenders = @()
foreach ($f in $scanFiles) {
    $lineNo = 0
    foreach ($line in @(Get-Content -LiteralPath $f.FullName -Encoding UTF8)) {
        $lineNo++
        # 盘符绝对路径 = "单个字母 + 冒号 + 斜杠/反斜杠"，且该字母前不能是字母数字
        # （否则会把 URL 中 "http://" 的 "p:" 误判成盘符——实测踩过）
        if ($line -notmatch '(?<![A-Za-z0-9])[A-Za-z]:[\\/]') { continue }
        if ($line -match 'D:[\\/]Environment') { continue }
        if ($line -match 'afp-allow-abs-path') { continue }
        $offenders += ("{0}:{1}" -f $f.Name, $lineNo)
    }
}
if ($offenders.Count -eq 0) {
    Add-Check -Name '无硬编码绝对路径' -Status ok -Detail ("已扫描 {0} 个脚本/编排/镜像文件，路径均由项目根或环境变量推导" -f $scanFiles.Count)
}
else {
    Add-Check -Name '无硬编码绝对路径' -Status fail -Detail ("发现 {0} 处: {1}" -f $offenders.Count, (($offenders | Select-Object -First 6) -join ', '))
}
