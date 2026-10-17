<#
.SYNOPSIS
    源码文件行数守卫：列出所有超过阈值的源码文件。

.DESCRIPTION
    扫描 crates、apps、sdk、scripts、deploy、tests、tools/simulators（可用 -Path 覆盖）。
    Rust、TypeScript、PowerShell、Python、CSS 等源码，排除构建产物与依赖目录。
    输出「行数 + 相对路径」清单与超限总数。

    包含版本化 SQL 迁移及其原字节分片；历史 0001 已用分片保持校验和。

    退出码：发现超限文件返回 1，清单为空返回 0（便于接入 CI 门禁）。

.EXAMPLE
    scripts/check-file-size.ps1
    全量扫描，包含 deploy/sql/migrations/** 与 deploy/sql/migration_parts/**。

.EXAMPLE
    scripts/check-file-size.ps1 -Path crates/agf-ingest
    只扫描指定目录（验收 agf-ingest 拆分时用）。
#>
[CmdletBinding()]
param(
    # 单文件行数上限
    [int]$Max = 500,

    # 扫描根目录列表（默认包含应用、脚本、测试及模拟器）
    [string[]]$Path = @('crates', 'apps', 'sdk', 'scripts', 'deploy', 'tests', 'tools/simulators'),

    # 相对路径基准（默认当前目录）
    [string]$Root = (Get-Location).Path
)

$ErrorActionPreference = 'Stop'

# 只统计源码扩展名；排除构建产物与依赖目录
$extensions = @('.rs', '.ts', '.tsx', '.mts', '.cts', '.ps1', '.py', '.css', '.js', '.jsx', '.mjs', '.cjs', '.html', '.sh', '.go', '.sql')
$excludeDirs = @('target', 'node_modules')

function Get-NormalizedRelativePath {
    param([string]$Base, [string]$Full)
    $baseFull = (Resolve-Path -LiteralPath $Base).Path
    $rel = $Full.Substring($baseFull.Length).TrimStart('\', '/')
    return ($rel -replace '\\', '/')
}

$offenders = New-Object System.Collections.Generic.List[object]

foreach ($p in $Path) {
    $scanRoot = $p
    if (-not [System.IO.Path]::IsPathRooted($scanRoot)) {
        $scanRoot = Join-Path $Root $p
    }
    if (-not (Test-Path -LiteralPath $scanRoot)) { continue }

    $files = Get-ChildItem -LiteralPath $scanRoot -Recurse -File -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        if ($extensions -notcontains $f.Extension.ToLowerInvariant()) { continue }

        # 排除 target/ 与 node_modules/（任意层级）
        $skip = $false
        foreach ($part in ($f.FullName -split '[\\/]')) {
            if ($excludeDirs -contains $part) { $skip = $true; break }
        }
        if ($skip) { continue }

        $rel = Get-NormalizedRelativePath -Base $Root -Full $f.FullName

        # 行数口径：ReadAllLines().Count —— **含空行**（Get-Content | Measure-Object -Line 不数空行，会偏小）
        $lines = [System.IO.File]::ReadAllLines($f.FullName).Count
        if ($lines -gt $Max) {
            $offenders.Add([pscustomobject]@{ Lines = $lines; Path = $rel }) | Out-Null
        }
    }
}

$sorted = @($offenders | Sort-Object -Property @{ Expression = 'Lines'; Descending = $true }, Path)

if ($sorted.Count -eq 0) {
    Write-Output "OK: 没有超过 $Max 行的源码文件（扫描范围: $($Path -join ', ')；包含 SQL 迁移）。"
} else {
    Write-Output "超过 $Max 行的源码文件（共 $($sorted.Count) 个）："
    foreach ($o in $sorted) {
        Write-Output ("{0,6}  {1}" -f $o.Lines, $o.Path)
    }
    Write-Output "总计: $($sorted.Count) 个文件超限"
}

if ($sorted.Count -gt 0) { exit 1 } else { exit 0 }
