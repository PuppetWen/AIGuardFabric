# =============================================================================
# pending-verification.docs.md 历史快照
#
# 用途：把 `docs/pending-verification.docs.md` 的当前内容按 UTC 时间戳归档到
#       `docs/pending-verification-history/`，形成可追溯的历史快照序列。
#       每次对清单做阶段性收口（增删条目、改状态）前后都可运行一次。
#
# 用法：
#   pwsh scripts/snapshot-pending-verification.ps1 [-Label <标签>]
#
# 说明：
#   * 快照文件名：`YYYYmmddTHHMMSSZ[-label].md`，UTC 时间戳保证单调排序。
#   * 在快照头部注入一行 `> Snapshot: <时间> | source: docs/pending-verification.docs.md | label: <标签>`。
#   * 同时维护 `docs/pending-verification-history/INDEX.md`（倒序索引）。
#   * 本脚本只读取项目内文件、写入项目内 `docs/`，不触碰 D:\Environment。
# =============================================================================
[CmdletBinding()]
param(
    [string]$Label = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# 项目根 = 本脚本上一级
$repo = Split-Path -Parent $PSScriptRoot
$source = Join-Path $repo 'docs/pending-verification.docs.md'
$histDir = Join-Path $repo 'docs/pending-verification-history'

if (-not (Test-Path $source)) {
    Write-Error "找不到源文件：$source"
    exit 1
}

New-Item -ItemType Directory -Force -Path $histDir | Out-Null

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$slug = if ($Label -ne '') { '-' + ($Label -replace '[^A-Za-z0-9\-]', '-').ToLower() } else { '' }
$name = "$stamp$slug.md"
$dest = Join-Path $histDir $name

$header = "> Snapshot: $stamp | source: docs/pending-verification.docs.md | label: $(if ($Label) { $Label } else { '(none)' })`n`n"
$content = Get-Content -Raw -Encoding UTF8 $source
Set-Content -Encoding UTF8 -Path $dest -Value ($header + $content)

# 维护倒序索引
$index = Join-Path $histDir 'INDEX.md'
$entries = @(Get-ChildItem -Path $histDir -Filter '*.md' |
    Where-Object { $_.Name -ne 'INDEX.md' } |
    Sort-Object Name -Descending)
$lines = @('# pending-verification.docs.md 历史快照索引', '', '| 快照 | 时间(UTC) |', '|---|---|')
foreach ($e in $entries) {
    $ts = $e.BaseName -replace '^(\d{8}T\d{6}Z).*$', '$1'
    $lines += "| [$($e.Name)]($($e.Name)) | $ts |"
}
Set-Content -Encoding UTF8 -Path $index -Value ($lines -join "`n")

Write-Host "已生成历史快照：docs/pending-verification-history/$name"
Write-Host "索引已更新：docs/pending-verification-history/INDEX.md（共 $($entries.Count) 份）"
