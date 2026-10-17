#Requires -Version 5.1
<#
.SYNOPSIS
    集成测试目标守卫：抓出「孤儿测试目录」与「未被声明的测试源文件」。

.DESCRIPTION
    为什么需要这个脚本（真实事故）：
      `crates/agf-adapters/tests/http_vendors/mod.rs` 与 `tests/email_smtp/mod.rs`
      曾是**孤儿子模块**——`tests/` 下有目录，但**没有 cargo 能发现的测试目标**
      （cargo 的自动发现只认 `tests/<name>.rs` 与 `tests/<name>/main.rs`）。
      结果：整套 wiremock / 假 SMTP 测试**根本没被编译**，
      workspace 显示「0 failed」其实是「没跑」，测试总数无故从 2562 掉到 2525。
      **这是最危险的假绿灯**——绿灯不是因为通过，而是因为不存在。

    本脚本对 `crates/*/tests`、`apps/*/tests` 逐个测试目录检查：

      1. 每个 `tests/<name>/` 目录必须存在 cargo 能识别的入口
         （`tests/<name>/main.rs`）**或**同级存在 `tests/<name>.rs`（`#[path]` 方案）；
         否则判定 **孤儿** 并 exit 1。
         （例外：`tests/common/` 这类**共享辅助模块**目录——被同 `/tests` 下别的测试目标
          用 `mod common;` / `#[path]` 引用到——记为「辅助模块」而非孤儿；
          只有 JSON/PEM 等数据文件的目录不是 Rust 测试目标。）
      2. 入口可达性：目录内每个 `.rs` 都必须能被入口的 `mod x;` 链（含 `#[path]`）
         递归到达；列出**未被声明的孤儿 .rs**。
      3. 报告每个测试目标的名称与用例数：默认**静态**统计 `#[test]` / `#[tokio::test]`
         （不编译、秒级）；加 `-CargoList` 改用
         `cargo test -p <pkg> --test <target> -- --list` 取**权威**用例数（需要编译）。

    退出码：出现「孤儿」或「未声明文件」返回 1，全部 OK 返回 0（便于接入 CI / gate.ps1）。

.OUTPUTS
    表格：`包 | 测试目标 | 用例数 | 状态(OK/孤儿/未声明文件)`，
    随后是失败明细（每个孤儿目录 / 未被声明的 .rs 各一行），最后是汇总行。

.PARAMETER Path
    扫描根目录（默认 `crates`、`apps`）。

.PARAMETER Root
    仓库根（默认由脚本位置推导为上一级目录）。

.PARAMETER CargoList
    用 `cargo test -- --list` 取权威用例数（慢：需编译）。默认用静态统计。

.EXAMPLE
    scripts/check-test-targets.ps1
    静态检查全仓（默认）。

.EXAMPLE
    scripts/check-test-targets.ps1 -CargoList
    用 cargo 权威列表逐目标核对用例数。

.NOTES
    本机只有 Windows PowerShell 5.1（无 pwsh）；脚本文件必须带 BOM 保存，否则中文按 GBK 解码。
    只读脚本：不改任何源码，只做 AST 级（正则）文本分析。
#>
[CmdletBinding()]
param(
    # 扫描根目录列表（默认为仓库两大源码区）
    [string[]]$Path = @('crates', 'apps'),

    # 仓库根（默认由脚本位置推导：scripts/ 的上一级）
    [string]$Root = '',

    # 使用 cargo test -- --list 取权威用例数（需要编译，慢）
    [switch]$CargoList
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# $PSScriptRoot 在 param 默认值里取不到（实测：报 "Path 为空字符串"），因此在正文里兜底。
if (-not $Root) { $Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path }

# ---------------------------------------------------------------------------
# 文本读取与注释剥离
# ---------------------------------------------------------------------------
function Read-TextUtf8 {
    <#
    .SYNOPSIS
        以 UTF-8 读文本（PS 5.1 的 Get-Content 默认按 ANSI/GBK 解码，中文会碎）。
    #>
    param([Parameter(Mandatory)][string]$FilePath)
    return [System.IO.File]::ReadAllText($FilePath, (New-Object System.Text.UTF8Encoding($false)))
}

function Remove-RustComments {
    <#
    .SYNOPSIS
        剥掉 Rust 注释，避免把注释里的 `// mod foo;` 当成真声明。
    .NOTES
        只剥**整行**注释（`//`、`///`、`//!`）与块注释 `/* */`：
        行尾 `//` 不剥（字符串里的 `https://` 会被误伤），代价是「行尾注释里的 mod 声明」
        不会被识别——实际代码里 mod 声明独占一行，这个取舍是安全的。
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $t = [regex]::Replace($Text, '/\*.*?\*/', '', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    $t = [regex]::Replace($t, '(?m)^[ \t]*//.*$', '')
    return $t
}

# `mod x;` / `pub(crate) mod x;` / `#[path = "a/b.rs"] mod x;`
$script:ModDeclRegex = [regex]'(?m)(?:#\[\s*path\s*=\s*"(?<path>[^"]+)"\s*\]\s*)?(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*;'
# `#[test]` / `#[tokio::test]` / `#[tokio::test(flavor = "multi_thread")]`
# 注意不匹配 `#[cfg(test)]`（标识符必须整体是 test，可带 `::` 前缀）。
$script:TestAttrRegex = [regex]'#\[\s*(?:[A-Za-z_][A-Za-z0-9_]*::)*test\s*(?:\([^)]*\))?\s*\]'

function Resolve-ModTarget {
    <#
    .SYNOPSIS
        把一条 `mod` 声明解析成实际文件（Rust 2018+ 解析顺序：<name>.rs → <name>/mod.rs）。
    #>
    param(
        [Parameter(Mandatory)][string]$BaseDir,
        [AllowEmptyString()][string]$ModPath = '',
        [Parameter(Mandatory)][string]$Name
    )
    if ($ModPath) {
        $p = Join-Path $BaseDir $ModPath
        if (Test-Path -LiteralPath $p -PathType Leaf) { return (Get-Item -LiteralPath $p).FullName }
        return ''
    }
    $flat = Join-Path $BaseDir ("{0}.rs" -f $Name)
    if (Test-Path -LiteralPath $flat -PathType Leaf) { return (Get-Item -LiteralPath $flat).FullName }
    $nested = Join-Path (Join-Path $BaseDir $Name) 'mod.rs'
    if (Test-Path -LiteralPath $nested -PathType Leaf) { return (Get-Item -LiteralPath $nested).FullName }
    return ''
}

function Get-RustModuleClosure {
    <#
    .SYNOPSIS
        从入口文件出发，按 `mod x;`（含 `#[path]`）递归求可达文件闭包。
    .OUTPUTS
        hashtable：Files = 可达文件全路径数组；Missing = 解析不到文件的 mod 声明描述数组。
    #>
    param([Parameter(Mandatory)][string]$RootFile)

    $visited = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $missing = New-Object System.Collections.Generic.List[string]
    # #[path] files use mod.rs-like ownership, even if named owned.rs.
    # The same file may be included by both ordinary and explicit-path declarations.
    $contexts = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $queue = New-Object 'System.Collections.Generic.Queue[object]'
    $rootPath = (Get-Item -LiteralPath $RootFile).FullName
    $queue.Enqueue([pscustomobject]@{ File = $rootPath; ChildrenSibling = $true })

    while ($queue.Count -gt 0) {
        $frame = $queue.Dequeue()
        $cur = [string]$frame.File
        $context = "{0}|{1}" -f $cur, $frame.ChildrenSibling
        if (-not $contexts.Add($context)) { continue }
        $visited.Add($cur) | Out-Null
        $text = Remove-RustComments (Read-TextUtf8 -FilePath $cur)
        foreach ($m in $script:ModDeclRegex.Matches($text)) {
            # Out-of-line #[path] is relative to this source file's directory.
            # Ordinary foo.rs owns foo/; roots, mod.rs and incoming #[path]
            # inclusions own their source directory (rustc mod_dir_path ownership).
            $baseDir = Split-Path -Parent $cur
            if (-not $m.Groups['path'].Success -and -not $frame.ChildrenSibling) {
                $baseDir = Join-Path $baseDir ([System.IO.Path]::GetFileNameWithoutExtension($cur))
            }
            $target = Resolve-ModTarget -BaseDir $baseDir -ModPath $m.Groups['path'].Value -Name $m.Groups['name'].Value
            if (-not $target) {
                $missing.Add(("{0} → mod {1};" -f $cur, $m.Groups['name'].Value)) | Out-Null
                continue
            }
            $sibling = $m.Groups['path'].Success -or [System.IO.Path]::GetFileName($target) -eq 'mod.rs'
            $queue.Enqueue([pscustomobject]@{ File = $target; ChildrenSibling = $sibling })
        }
    }
    return @{ Files = @($visited); Missing = @($missing) }
}

function Get-StaticTestCount {
    <#
    .SYNOPSIS
        静态统计一组 .rs 里的 `#[test]` / `#[tokio::test]` 用例数（去重后按文件累加）。
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Files)
    $n = 0
    foreach ($f in $Files) {
        $text = Remove-RustComments (Read-TextUtf8 -FilePath $f)
        $n += $script:TestAttrRegex.Matches($text).Count
    }
    return $n
}

function Get-CargoListCount {
    <#
    .SYNOPSIS
        用 `cargo test -p <pkg> --test <target> -- --list` 取权威用例数（返回 $null 表示取数失败）。
    #>
    param(
        [Parameter(Mandatory)][string]$Package,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$WorkingDir
    )
    $out = @()
    $code = 1
    Push-Location $WorkingDir
    # 注意：`2>&1` 会把 cargo 的 stderr（编译进度 / "Blocking waiting for file lock"）变成
    # ErrorRecord，在 $ErrorActionPreference='Stop' 下会直接抛异常终止脚本。
    # 这里临时降级为 Continue，让"取数失败"走返回值（$null）而不是异常。
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & cargo test -p $Package --test $Target -- --list 2>&1
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $prevEap
        Pop-Location
    }
    if ($code -ne 0) { return $null }
    return (@($out | Where-Object { "$_" -match ': test$' })).Count
}

function Get-PackageName {
    <#
    .SYNOPSIS
        从 Cargo.toml 的 [package] 段取 name（取不到则退回目录名）。
    #>
    param([Parameter(Mandatory)][string]$CargoToml)
    $text = Read-TextUtf8 -FilePath $CargoToml
    $block = [regex]::Match($text, '(?ms)^\[package\].*?(?=^\[|\z)')
    if ($block.Success) {
        $n = [regex]::Match($block.Value, '(?m)^\s*name\s*=\s*"([^"]+)"')
        if ($n.Success) { return $n.Groups[1].Value }
    }
    return (Split-Path -Leaf (Split-Path -Parent $CargoToml))
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
$rows = New-Object System.Collections.Generic.List[object]
$problems = New-Object System.Collections.Generic.List[string]

foreach ($scan in $Path) {
    $scanRoot = $scan
    if (-not [System.IO.Path]::IsPathRooted($scanRoot)) { $scanRoot = Join-Path $Root $scan }
    if (-not (Test-Path -LiteralPath $scanRoot -PathType Container)) { continue }

    foreach ($pkgDir in (Get-ChildItem -LiteralPath $scanRoot -Directory | Sort-Object Name)) {
        $cargoToml = Join-Path $pkgDir.FullName 'Cargo.toml'
        if (-not (Test-Path -LiteralPath $cargoToml -PathType Leaf)) { continue }
        $testsDir = Join-Path $pkgDir.FullName 'tests'
        if (-not (Test-Path -LiteralPath $testsDir -PathType Container)) { continue }

        $pkg = Get-PackageName -CargoToml $cargoToml
        $topFiles = @(Get-ChildItem -LiteralPath $testsDir -File -Filter '*.rs' | Sort-Object Name)
        $subDirs = @(Get-ChildItem -LiteralPath $testsDir -Directory | Sort-Object Name)

        # ---- 1) 枚举 cargo 能发现的测试目标（自动发现：tests/*.rs 与 tests/*/main.rs） ----
        $targets = New-Object System.Collections.Generic.List[object]
        foreach ($f in $topFiles) {
            $targets.Add([pscustomobject]@{ Name = $f.BaseName; Entry = $f.FullName; Kind = 'file' })
        }
        foreach ($d in $subDirs) {
            $entry = Join-Path $d.FullName 'main.rs'
            if (Test-Path -LiteralPath $entry -PathType Leaf) {
                $targets.Add([pscustomobject]@{ Name = $d.Name; Entry = (Get-Item -LiteralPath $entry).FullName; Kind = 'dir' })
            }
        }

        # ---- 重复目标名（cargo 会直接报错，这里提前抓） ----
        $dupNames = @($targets | Group-Object Name | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
        foreach ($dn in $dupNames) {
            $problems.Add(("[重复目标] {0} / {1}：同名测试目标存在多个入口（cargo 会构建失败）" -f $pkg, $dn)) | Out-Null
        }

        # ---- 2) 每个目标求可达闭包 ----
        $reachableAll = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $targetInfo = New-Object System.Collections.Generic.List[object]
        foreach ($t in $targets) {
            $closure = Get-RustModuleClosure -RootFile $t.Entry
            foreach ($f in $closure.Files) { $reachableAll.Add($f) | Out-Null }

            # 候选全集：入口所在「目录形态」的全部 .rs（用于判"未被声明"）
            $universe = New-Object System.Collections.Generic.List[string]
            $universe.Add($t.Entry) | Out-Null
            $scopeDir = $null
            if ($t.Kind -eq 'dir') { $scopeDir = Split-Path -Parent $t.Entry }
            else {
                $sibling = Join-Path $testsDir ([System.IO.Path]::GetFileNameWithoutExtension($t.Entry))
                if (Test-Path -LiteralPath $sibling -PathType Container) { $scopeDir = (Get-Item -LiteralPath $sibling).FullName }
            }
            if ($scopeDir) {
                foreach ($f in Get-ChildItem -LiteralPath $scopeDir -Recurse -File -Filter '*.rs') {
                    $universe.Add($f.FullName) | Out-Null
                }
            }
            $undeclared = @($universe | Sort-Object -Unique | Where-Object { $closure.Files -notcontains $_ })

            $targetInfo.Add([pscustomobject]@{
                    Row    = $t
                    Files  = @($closure.Files)
                    Missing = @($closure.Missing)
                    Undeclared = @($undeclared)
                }) | Out-Null
        }

        # ---- 3) 无入口的子目录：辅助模块 or 孤儿 ----
        $helperInfo = New-Object System.Collections.Generic.List[object]
        foreach ($d in $subDirs) {
            $entry = Join-Path $d.FullName 'main.rs'
            if (Test-Path -LiteralPath $entry -PathType Leaf) { continue }
            if (Test-Path -LiteralPath (Join-Path $testsDir ("{0}.rs" -f $d.Name)) -PathType Leaf) { continue }

            $own = @(Get-ChildItem -LiteralPath $d.FullName -Recurse -File -Filter '*.rs')
            if ($own.Count -eq 0) { continue }
            $referenced = @($own | Where-Object { $reachableAll.Contains($_.FullName) })
            if ($referenced.Count -eq 0) {
                # 谁也没引用 ⇒ 孤儿：cargo 不会编译它，测试静默地不存在
                $rows.Add([pscustomobject]@{ Package = $pkg; Target = $d.Name; Count = 0; Status = '孤儿' }) | Out-Null
                $problems.Add(("[孤儿测试目录] {0} / tests/{1}/：无 main.rs，也无同级 tests/{1}.rs，且未被任何测试目标用 mod/#[path] 引用 ⇒ cargo 不会编译它" -f $pkg, $d.Name)) | Out-Null
                continue
            }

            # 辅助目录可能同时由 `mod common;` 与多个入口的 #[path] 引用。
            # 用所有测试目标的可达文件并集判断，避免把另一个入口已编译的文件误报为孤儿。
            $undeclared = @($own | ForEach-Object { $_.FullName } | Where-Object { -not $reachableAll.Contains($_) })
            $helperInfo.Add([pscustomobject]@{
                    Name    = ("{0} (辅助模块)" -f $d.Name)
                    Files   = @($referenced | ForEach-Object { $_.FullName })
                    Missing = @()
                    Undeclared = @($undeclared)
                }) | Out-Null
        }

        # ---- 4) 出表 ----
        foreach ($ti in $targetInfo) {
            $count = Get-StaticTestCount -Files $ti.Files
            if ($CargoList) {
                $cargoCount = Get-CargoListCount -Package $pkg -Target $ti.Row.Name -WorkingDir $Root
                if ($null -ne $cargoCount) { $count = $cargoCount }
                else { $problems.Add(("[统计失败] {0} / {1}：cargo test -- --list 未跑通，已退回静态统计（{2}）" -f $pkg, $ti.Row.Name, $count)) | Out-Null }
            }
            $status = 'OK'
            if ($ti.Undeclared.Count -gt 0) {
                $status = ("未声明文件({0})" -f $ti.Undeclared.Count)
                foreach ($u in $ti.Undeclared) {
                    $rel = $u.Substring($Root.Length).TrimStart('\', '/') -replace '\\', '/'
                    $problems.Add(("[未声明文件] {0} / {1}：{2} 未被入口的 mod 链到达 ⇒ 不会被编译" -f $pkg, $ti.Row.Name, $rel)) | Out-Null
                }
            }
            foreach ($mi in $ti.Missing) {
                $problems.Add(("[mod 解析失败] {0} / {1}：{2}（声明的模块文件不存在）" -f $pkg, $ti.Row.Name, $mi)) | Out-Null
                if ($status -eq 'OK') { $status = '缺模块文件' }
            }
            if ($dupNames -contains $ti.Row.Name -and $status -eq 'OK') { $status = '重复目标' }
            $rows.Add([pscustomobject]@{ Package = $pkg; Target = $ti.Row.Name; Count = $count; Status = $status }) | Out-Null
        }
        foreach ($hi in $helperInfo) {
            $count = Get-StaticTestCount -Files $hi.Files
            $status = 'OK'
            if ($hi.Undeclared.Count -gt 0) {
                $status = ("未声明文件({0})" -f $hi.Undeclared.Count)
                foreach ($u in $hi.Undeclared) {
                    $rel = $u.Substring($Root.Length).TrimStart('\', '/') -replace '\\', '/'
                    $problems.Add(("[未声明文件] {0} / {1}：{2} 未被入口的 mod 链到达 ⇒ 不会被编译" -f $pkg, $hi.Name, $rel)) | Out-Null
                }
            }
            foreach ($mi in $hi.Missing) {
                $problems.Add(("[mod 解析失败] {0} / {1}：{2}（声明的模块文件不存在）" -f $pkg, $hi.Name, $mi)) | Out-Null
                if ($status -eq 'OK') { $status = '缺模块文件' }
            }
            $rows.Add([pscustomobject]@{ Package = $pkg; Target = $hi.Name; Count = $count; Status = $status }) | Out-Null
        }
    }
}

# ---------------------------------------------------------------------------
# 打印
# ---------------------------------------------------------------------------
$pkgWidth = 20
$tgtWidth = 34
foreach ($r in $rows) {
    if ($r.Package.Length -gt $pkgWidth) { $pkgWidth = $r.Package.Length }
    if ($r.Target.Length -gt $tgtWidth) { $tgtWidth = $r.Target.Length }
}

$mode = '静态统计 #[test]/#[tokio::test]'
if ($CargoList) { $mode = 'cargo test -- --list（权威）' }
Write-Output ("测试目标守卫（用例数口径：{0}）" -f $mode)
Write-Output ("{0} | {1} | {2} | {3}" -f '包'.PadRight($pkgWidth), '测试目标'.PadRight($tgtWidth), '用例数'.PadLeft(6), '状态')
Write-Output ("{0}-+-{1}-+-{2}-+-{3}" -f ''.PadRight($pkgWidth, '-'), ''.PadRight($tgtWidth, '-'), ''.PadRight(6, '-'), ''.PadRight(12, '-'))
foreach ($r in $rows) {
    Write-Output ("{0} | {1} | {2} | {3}" -f $r.Package.PadRight($pkgWidth), $r.Target.PadRight($tgtWidth), ("{0}" -f $r.Count).PadLeft(6), $r.Status)
}

$badRows = @($rows | Where-Object { $_.Status -ne 'OK' })
if ($problems.Count -gt 0) {
    Write-Output ''
    Write-Output '---- 明细 ----'
    foreach ($p in $problems) { Write-Output $p }
}

$totalTargets = $rows.Count
$totalCases = (($rows | Measure-Object -Property Count -Sum).Sum)
if ($null -eq $totalCases) { $totalCases = 0 }
Write-Output ''
Write-Output ("汇总：{0} 个测试目标 / 用例数合计 {1}（辅助模块与目标可能共享文件，合计仅供量级核对）；异常行 {2} 个。" -f $totalTargets, $totalCases, $badRows.Count)

$blocking = @($problems | Where-Object { $_ -match '^\[(孤儿测试目录|未声明文件|缺模块文件|重复目标)\]' })
if ($badRows.Count -gt 0 -or $blocking.Count -gt 0) {
    Write-Output 'RESULT: FAIL —— 存在孤儿测试目录 / 未声明测试源文件（这些测试不会被编译，"0 failed" 是假绿灯）。'
    exit 1
}
Write-Output 'RESULT: OK —— 所有 tests/ 目录都有 cargo 可发现的入口，且目录内 .rs 全部被声明。'
exit 0
