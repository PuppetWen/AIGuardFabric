#Requires -Version 5.1
<#
.SYNOPSIS
    恢复：从 backup.ps1 产出的备份目录恢复数据库（可选数据目录）。

.DESCRIPTION
    安全约束（破坏性操作必须二次确认）：
      1) 默认进入交互确认；CI/无人值守用 -Force；
      2) 恢复前**自动再备份一次**当前库（除非 -NoPreBackup），避免"恢复错了回不去"；
      3) 恢复前打印目标库与服务名，并校验备份包 MANIFEST 的 sha256；
      4) 只做 pg_restore --clean --if-exists，绝不 DROP DATABASE。

.PARAMETER BackupFile
    备份目录（如 data\backup\20260221-101530）或其中的 agf.dump 文件路径。

.PARAMETER WithData
    恢复seed/uploads/fixtures普通数据；压缩包不得覆盖审计见证。

.PARAMETER AllowUnanchoredLegacy
    当前和备份均无见证时，显式接受旧未锚定数据；绝不生成可信检查点。

.PARAMETER NoPreBackup
    跳过恢复前的自动备份（不推荐）。

.PARAMETER Force
    跳过交互确认（CI 用）。

.PARAMETER WhatIf
    干跑：只打印将要执行的动作。
#>

param(
    [Parameter(Mandatory)][string]$BackupFile,
    [switch]$WithData,
    [switch]$NoPreBackup,
    [switch]$AllowUnanchoredLegacy,
    [switch]$Force,
    [switch]$WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\lib.ps1"
. "$PSScriptRoot\audit-witness-backup.ps1"

$root = $global:AgfRoot
$dataRoot = Get-AgfAuditDataRoot $root $env:AGF_DATA_DIR

$dbUser = Get-AgfEnv -Name 'AGF_PG_USER' -Default (Get-AgfEnv -Name 'POSTGRES_USER' -Default 'agf')
$dbName = Get-AgfEnv -Name 'AGF_PG_DB' -Default (Get-AgfEnv -Name 'POSTGRES_DB' -Default 'aiguardfabric')
$pgService = Get-AgfEnv -Name 'AGF_POSTGRES_SERVICE' -Default 'postgres'
$compose = Join-Path $root 'docker-compose.yml'

# 所有备份输入必须先复制到项目内受控目录，拒绝外部绝对路径和链接。
$BackupFile = Assert-AgfBackupPath $root ([IO.Path]::GetFullPath($BackupFile))
# 解析备份目录与 dump 文件
$dir = $BackupFile
$dump = $BackupFile
if ((Test-Path -LiteralPath $BackupFile -PathType Container)) {
    $dump = Join-Path $BackupFile 'agf.dump'
}
else {
    $dir = Split-Path -Parent $BackupFile
}
$dir = Assert-AgfBackupPath $root $dir
$dump = Assert-AgfBackupPath $root $dump
if (-not (Test-Path -LiteralPath $dump -PathType Leaf)) {
    Write-AgfFail ('找不到备份文件：{0}' -f $dump)
    exit 1
}

Write-Host "`n=== 恢复 ===" -ForegroundColor White
Write-AgfInfo ('备份：{0}' -f $dump)
Write-AgfInfo ('目标库：{0}@{1}（compose 服务 {2}）' -f $dbName, $dbUser, $pgService)
Write-AgfInfo '恢复方式：pg_restore --clean --if-exists（不 DROP DATABASE，不影响其它库）'

# 校验 MANIFEST（存在则逐条核对 sha256）
$manifest = Join-Path $dir 'MANIFEST.txt'
if (Test-Path -LiteralPath $manifest) {
    $bad = 0
    foreach ($line in (Get-Content -LiteralPath $manifest -Encoding UTF8)) {
        if ($line -match '^(\S+)\s+(\d+)\s+([0-9a-f]{64})$') {
            $name = $Matches[1]
            if ($name.IndexOfAny([char[]]'\/:') -ge 0 -or $name -in @('.','..')) { throw '清单仅允许备份根的直接文件。' }
            $expect = $Matches[3]
            $path = Assert-AgfBackupPath $root (Join-Path $dir $name)
            if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw ('清单文件缺失：' + $name) } else {
                $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower()
                if ($actual -ne $expect) { Write-AgfFail ('校验失败：{0}（期望 {1}，实际 {2}）' -f $name, $expect, $actual); $bad++ }
                else { Write-AgfOk ('校验通过：{0}' -f $name) }
            }
        }
    }
    if ($bad -gt 0) { Write-AgfFail '备份包校验失败，拒绝恢复'; exit 1 }
}
else {
    Write-AgfSkip '备份包内无 MANIFEST.txt，跳过 sha256 校验'
}

# 在数据库有任何写入之前校验见证包、现场归属和普通压缩包路径。
$restorePlan = Get-AgfWitnessRestorePlan $root $dataRoot $dir ([bool]$AllowUnanchoredLegacy)
if (Test-Path -LiteralPath (Join-Path $dir 'AUDIT-WITNESSES.json')) {
    $completePath = Assert-AgfBackupPath $root (Join-Path $dir 'BACKUP-COMPLETE.json')
    $complete = ConvertFrom-Json -InputObject ($script:AgfWitnessUtf8.GetString((Read-AgfWitnessBytes $root $completePath 16384)))
    if ($complete.Version -ne 2 -or $complete.Status -cne 'COMPLETE' -or
        $complete.WitnessManifestSha256 -cne (Get-FileHash -LiteralPath (Join-Path $dir 'AUDIT-WITNESSES.json')).Hash -or
        $complete.WitnessState -cne $restorePlan.Archive.State -or
        $complete.ManifestSha256 -cne (Get-FileHash -LiteralPath $manifest).Hash -or
        $complete.DatabaseDumpSha256 -cne (Get-FileHash -LiteralPath $dump).Hash -or
        $complete.DatabaseDumpBytes -ne (Get-Item -LiteralPath $dump).Length) { throw '备份完成回执不匹配，拒绝恢复不完整包。' }
}
$zip = Join-Path $dir 'data-files.zip'
$dataLayout = $null
if ($WithData -and (Test-Path -LiteralPath $zip)) { $dataLayout = Test-AgfLegacyDataArchive $root $zip }

if ($WhatIf) {
    Write-AgfExpect -Expected '干跑：只打印动作'
    Write-Host ('  见证：现场{0}；存在则保留，缺失时仅恢复已校验原字节' -f $restorePlan.Live.State) -ForegroundColor Gray
    Write-Host ('  pg_restore --clean --if-exists -U {0} -d {1} < agf.dump' -f $dbUser, $dbName) -ForegroundColor Gray
    exit 0
}

if (-not $Force) {
    $answer = Read-Host ('确认要用该备份覆盖当前库 {0} 吗？输入 yes 继续' -f $dbName)
    if ($answer -ne 'yes') {
        Write-AgfInfo '已取消（未做任何修改）'
        exit 1
    }
}

$running = (docker compose -f $compose ps --services --filter 'status=running' 2>$null) -contains $pgService
if (-not $running) {
    Write-AgfFail ('{0} 容器未运行；先执行 scripts\dev-up.ps1 -DepsOnly' -f $pgService)
    exit 1
}

if (-not $NoPreBackup) {
    Write-AgfInfo '恢复前自动备份当前库（可回滚）...'
    & (Join-Path $PSScriptRoot 'backup.ps1') -Keep 20
    if ($LASTEXITCODE -ne 0) { Write-AgfFail '恢复前备份失败，已中止（避免不可回滚）'; exit 1 }
}

Write-AgfInfo '执行 pg_restore ...'
Push-Location $root
try {
    # PowerShell 不支持 `<` 输入重定向，且管道按文本处理会破坏二进制备份；
    # 因此把重定向交给 cmd.exe（与 backup.ps1 的 pg_dump 导出对称）。
    $pgr = 'pg_restore --clean --if-exists --no-owner -U {0} -d {1}' -f $dbUser, $dbName
    $cmd = 'docker compose -f "{0}" exec -T {1} {2} < "{3}"' -f $compose, $pgService, $pgr, $dump
    cmd.exe /c $cmd
    if ($LASTEXITCODE -ne 0) { throw ('pg_restore 退出码 {0}' -f $LASTEXITCODE) }
}
finally {
    Pop-Location
}

$witnessResult = Complete-AgfWitnessRestore $root $dataRoot $restorePlan
Write-AgfInfo ('见证恢复边界：{0}' -f $witnessResult)

if ($WithData) {
    $zip = Join-Path $dir 'data-files.zip'
    if (Test-Path -LiteralPath $zip) {
        Write-AgfInfo '解包数据目录 ...'
        $checkedLayout = Test-AgfLegacyDataArchive $root $zip
        if ($checkedLayout -cne $dataLayout) { throw '普通数据包布局在恢复期间改变。' }
        $unpackRoot = if ($dataLayout -ceq 'leaf') { Join-Path $root 'data' } else { $root }
        Expand-Archive -LiteralPath $zip -DestinationPath $unpackRoot -Force
        Write-AgfOk '数据目录已恢复'
    }
    else {
        Write-AgfSkip '备份包内没有 data-files.zip'
    }
}

Write-AgfOk '恢复完成'
Write-AgfInfo '启动后必须使用原可信主密钥核验GET /api/v1/audit/verify；旧DB与较新见证冲突应拒绝，不可删除见证规避。'
exit 0
