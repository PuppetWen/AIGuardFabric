#Requires -Version 5.1
<#
.SYNOPSIS
    备份：PostgreSQL 逻辑备份 + 关键数据目录 + sha256 清单（§9 运维 / agfctl 备份的一部分）。

.DESCRIPTION
    产物落 <项目根>\data\backup\<yyyyMMdd-HHmmss-UUID>\：
      agf.dump             pg_dump -Fc（自定义格式，pg_restore 可选择性恢复）
      data-files.zip       data\ 下关键子目录（不含 backup 自身）
      audit-witnesses-v1   数据库外见证的原始字节（已初始化时）
      AUDIT-WITNESSES.json 见证完整集合/SHA与明确的未初始化状态
      BACKUP-COMPLETE.json 完成回执（最后写入，失败包不包含此文件）
      MANIFEST.txt         每个文件的 sha256 + 字节数 + 生成时间
      README.txt           恢复步骤（含 restore.ps1 用法）

.PARAMETER Keep
    保留最近 N 份备份（默认 10；0 = 不清理）。

.PARAMETER SkipData
    跳过seed/uploads/fixtures压缩包；审计见证仍必须单独保留。

.PARAMETER WhatIf
    干跑：只打印将要执行的动作，不落任何文件。

.NOTES
    PostgreSQL 走容器内 pg_dump（compose 服务名 postgres），连接参数从 .env 读取；
    容器不在运行时**明确失败**并给出启动命令，不静默跳过。
#>

param(
    [int]$Keep = 10,
    [switch]$SkipData,
    [switch]$WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\lib.ps1"
. "$PSScriptRoot\audit-witness-backup.ps1"

$root = $global:AgfRoot
$stamp = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N')
$dest = Assert-AgfBackupPath $root (Join-Path $root ("data\backup\{0}" -f $stamp))
$dataRoot = Get-AgfAuditDataRoot $root $env:AGF_DATA_DIR
$witnessBefore = Get-AgfWitnessSnapshot $root $dataRoot
$backupOwner = 'AIGuardFabric backup v2 / ' + $stamp

$dbUser = Get-AgfEnv -Name 'AGF_PG_USER' -Default (Get-AgfEnv -Name 'POSTGRES_USER' -Default 'agf')
$dbName = Get-AgfEnv -Name 'AGF_PG_DB' -Default (Get-AgfEnv -Name 'POSTGRES_DB' -Default 'aiguardfabric')
$pgService = Get-AgfEnv -Name 'AGF_POSTGRES_SERVICE' -Default 'postgres'

Write-Host "`n=== 备份 ===" -ForegroundColor White
Write-AgfInfo ('目标目录：{0}' -f $dest)
Write-AgfInfo ('数据库：{0}@{1}（compose 服务 {2}）' -f $dbName, $dbUser, $pgService)

if ($WhatIf) {
    Write-AgfExpect -Expected '干跑：只打印动作，不落文件'
    Write-Host ('  docker compose exec -T {0} pg_dump -U {1} -Fc {2} > agf.dump' -f $pgService, $dbUser, $dbName) -ForegroundColor Gray
    if (-not $SkipData) { Write-Host '  Compress-Archive data\{seed,fixtures,uploads} data-files.zip' -ForegroundColor Gray }
    Write-Host ('  audit-witnesses-v1 原字节 + AUDIT-WITNESSES.json（当前 {0}）' -f $witnessBefore.State) -ForegroundColor Gray
    Write-Host '  MANIFEST.txt（sha256 + 字节数）与BACKUP-COMPLETE.json' -ForegroundColor Gray
    exit 0
}

if (Test-Path -LiteralPath $dest) { throw '备份目录已存在，拒绝覆盖。' }
$null = New-Item -ItemType Directory -Path $dest
Set-AgfWitnessMode $dest $true
Write-AgfBackupNew (Join-Path $dest '.agf-backup-owner') ($script:AgfWitnessUtf8.GetBytes($backupOwner))

# 1) 数据库
$running = (docker compose -f (Join-Path $root 'docker-compose.yml') ps --services --filter 'status=running' 2>$null) -contains $pgService
if (-not $running) {
    Write-AgfFail ('{0} 容器未运行；先执行 scripts\dev-up.ps1 -DepsOnly' -f $pgService)
    exit 1
}
$dumpFile = Join-Path $dest 'agf.dump'
Write-AgfInfo '导出数据库（pg_dump -Fc）...'
Push-Location $root
try {
    # 必须用 cmd.exe 重定向：PowerShell 的管道按文本/对象处理，会把 -Fc 二进制 dump 破坏掉
    $cmd = 'docker compose -f "{0}" exec -T {1} pg_dump -U {2} -Fc {3} > "{4}"' -f (Join-Path $root 'docker-compose.yml'), $pgService, $dbUser, $dbName, $dumpFile
    cmd.exe /c $cmd
    if ($LASTEXITCODE -ne 0) { throw ('pg_dump 退出码 {0}' -f $LASTEXITCODE) }
}
catch {
    Write-AgfFail ('pg_dump 失败：{0}' -f $_.Exception.Message)
    exit 1
}
finally {
    Pop-Location
}
$dumpSize = (Get-Item -LiteralPath $dumpFile).Length
Write-AgfOk ('数据库已导出：{0} 字节' -f $dumpSize)

# 见证无论是否-SkipData均需保留。导出期间改变则明确失败，不交付不一致包。
Save-AgfWitnessBackup $root $dataRoot $dest $witnessBefore

# 2) 普通数据目录
if (-not $SkipData) {
    $candidates = @(@('data\seed', 'data\uploads', 'data\fixtures') |
        ForEach-Object { Join-Path $root $_ } |
        Where-Object { Test-Path -LiteralPath $_ })
    if ($candidates.Count -gt 0) {
        $zip = Join-Path $dest 'data-files.zip'
        Write-AgfInfo ('打包数据目录：{0}' -f (($candidates | ForEach-Object { Split-Path -Leaf $_ }) -join ', '))
        foreach ($candidate in $candidates) { Assert-AgfOrdinaryDataTree $root $candidate }
        Compress-Archive -Path $candidates -DestinationPath $zip -Force
        foreach ($candidate in $candidates) { Assert-AgfOrdinaryDataTree $root $candidate }
        $null = Test-AgfLegacyDataArchive $root $zip
        Write-AgfOk ('数据目录已打包：{0} 字节' -f (Get-Item -LiteralPath $zip).Length)
    }
    else {
        Write-AgfSkip '没有可打包的数据目录（data\seed|uploads|fixtures 均不存在）'
    }
}

# 3) 清单
$lines = @()
$lines += ('备份时间：{0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
$lines += ('项目根：{0}' -f $root)
$lines += ('数据库：{0}@{1} / 服务 {2}' -f $dbName, $dbUser, $pgService)
$lines += ''
$lines += ('{0,-40} {1,14}  {2}' -f '文件', '字节', 'sha256')
foreach ($f in (Get-ChildItem -LiteralPath $dest -File | Sort-Object Name)) {
    $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLower()
    $lines += ('{0,-40} {1,14}  {2}' -f $f.Name, $f.Length, $hash)
}
Write-AgfTextFile -Path (Join-Path $dest 'MANIFEST.txt') -Content ($lines -join "`n")

$readme = @()
$readme += 'AIGuardFabric 备份包'
$readme += ''
$readme += ('生成：{0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
$readme += ''
$readme += '恢复步骤：'
$readme += ('  1) 启动依赖：scripts\dev-up.ps1 -DepsOnly')
$readme += ('  2) 恢复数据库：scripts\restore.ps1 -BackupFile "{0}"' -f $dest)
$readme += '  3) 如需普通数据，一并传-WithData；见证始终由restore.ps1校验并保留实时版本。'
$readme += '     没有实时见证时仅从本包原字节恢复。切勿手工覆盖较新的见证或重签旧数据库。'
$readme += '     SHA用于传输完整性；启动后使用原可信主密钥核验签名与见证祖先关系。'
$readme += ('  4) 校验：scripts\selfcheck.ps1 与 GET /healthz')
Write-AgfTextFile -Path (Join-Path $dest 'README.txt') -Content ($readme -join "`n")

$complete = [ordered]@{Version=2;Status='COMPLETE';CompletedUtc=[DateTime]::UtcNow.ToString('o');WitnessState=$witnessBefore.State;WitnessManifestSha256=(Get-FileHash -LiteralPath (Join-Path $dest 'AUDIT-WITNESSES.json')).Hash;ManifestSha256=(Get-FileHash -LiteralPath (Join-Path $dest 'MANIFEST.txt')).Hash;DatabaseDumpSha256=(Get-FileHash -LiteralPath $dumpFile).Hash;DatabaseDumpBytes=$dumpSize}
Write-AgfBackupNew (Join-Path $dest 'BACKUP-COMPLETE.json') ($script:AgfWitnessUtf8.GetBytes(($complete|ConvertTo-Json)))
Write-AgfOk ('备份完成：{0}' -f $dest)

# 4) 保留策略
if ($Keep -gt 0) {
    # 旧无标记备份保留不动；只清理本入口本版本的完整、精确归属备份。
    $all = @(Get-ChildItem -LiteralPath (Join-Path $root 'data\backup') -Directory | Where-Object {
        $_.Name -cmatch '^\d{8}-\d{6}-[0-9a-f]{32}$' -and
        (Test-Path -LiteralPath (Join-Path $_.FullName 'BACKUP-COMPLETE.json') -PathType Leaf) -and
        (Test-Path -LiteralPath (Join-Path $_.FullName '.agf-backup-owner') -PathType Leaf) -and
        $script:AgfWitnessUtf8.GetString((Read-AgfWitnessBytes $root (Join-Path $_.FullName '.agf-backup-owner') 256)) -ceq ('AIGuardFabric backup v2 / ' + $_.Name)
    } | Sort-Object Name -Descending)
    if ($all.Count -gt $Keep) {
        $drop = $all | Select-Object -Skip $Keep
        foreach ($d in $drop) {
            $absolute = Assert-AgfBackupPath $root $d.FullName
            if ([IO.Directory]::GetParent($absolute).FullName -cne (Join-Path $root 'data\backup')) { throw '过期备份超出精确范围。' }
            # 崩溃留下的部分完成文件不能成为清理授权。
            $markerBytes = Read-AgfWitnessBytes $root (Join-Path $absolute 'BACKUP-COMPLETE.json') 16384
            try { $marker = ConvertFrom-Json -InputObject ($script:AgfWitnessUtf8.GetString($markerBytes)) }
            catch { Write-AgfSkip ('保留不完整回执备份：' + $d.Name); continue }
            if ($marker.Version -ne 2 -or $marker.Status -cne 'COMPLETE') { Write-AgfSkip ('保留非完整备份：' + $d.Name); continue }
            foreach ($entry in Get-ChildItem -LiteralPath $absolute -Recurse -Force) { $null = Assert-AgfBackupPath $root $entry.FullName }
            Remove-Item -LiteralPath $absolute -Recurse -Force
            Write-AgfInfo ('清理过期备份：{0}' -f $d.Name)
        }
    }
}
exit 0
