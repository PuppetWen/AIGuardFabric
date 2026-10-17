#Requires -Version 5.1
# 编译缓存复用是显式选择；失败证据与历史计数另存并验证，任何旧计数都不得参与本轮合并。
function Assert-CoverageCachePlain([string]$Path) {
    $item=Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Coverage cache reparse refused' }
        if ($item -is [IO.FileInfo]) { $item=$item.Directory } else { $item=$item.Parent }
    }
}
function Assert-CoverageCacheSha([string]$Path,[string]$Sha) {
    Assert-CoverageCachePlain $Path
    if ($Sha -cnotmatch '^[0-9A-F]{64}$' -or (Get-FileHash -LiteralPath $Path).Hash -cne $Sha) { throw 'Coverage cache provenance SHA differs' }
}
function Get-CoverageCacheFiles([string]$Root) {
    $stack=New-Object 'System.Collections.Generic.Stack[string]'; $stack.Push($Root)
    while ($stack.Count) {
        $directory=$stack.Pop(); Assert-CoverageCachePlain $directory
        foreach ($entry in Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop) {
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Coverage cache tree reparse refused' }
            if ($entry.PSIsContainer) { $stack.Push($entry.FullName) } else { $entry }
        }
    }
}
function Assert-CoverageReuseArchiveEvidence($Reuse) {
    Assert-CoverageCacheSha $Reuse.ArchiveReceipt $Reuse.ArchiveReceiptSha256
    Assert-CoverageCacheSha $Reuse.OriginalOuterReceipt $Reuse.OriginalOuterReceiptSha256
    Assert-CoverageCacheSha $Reuse.OriginalProductReceipt $Reuse.OriginalProductReceiptSha256
    $proof=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Reuse.ArchiveReceipt))
    foreach ($row in $proof.ArchivedFiles) { Assert-CoverageCacheSha $row.Destination $row.Sha256 }
    $sourceReceipt=Join-Path ([IO.Path]::GetDirectoryName($Reuse.OriginalOuterReceipt)) 'orphaned-source-profiles-v1\receipt.json'
    Assert-CoverageCacheSha $sourceReceipt $proof.SourceOrphansReceiptSha256
    $source=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($sourceReceipt))
    foreach ($row in $source.Moved) { Assert-CoverageCacheSha $row.Destination $row.Sha256 }
}
function Get-CoverageReuseCache([string]$Root,[string]$OriginRun,[string]$ArchiveReceiptSha,[string]$Run) {
    if ($OriginRun -cnotmatch '^[0-9a-f]{32}$' -or $OriginRun -ceq $Run -or $ArchiveReceiptSha -cnotmatch '^[0-9A-F]{64}$') { throw 'Explicit cache origin/archive binding absent' }
    $origin=Join-Path $Root ('.tmp\owned-cov\'+$OriginRun); $target=Join-Path $origin 't'
    $outer=Join-Path $Root ('.tmp\owned-cov\audit-'+$OriginRun)
    $product=Join-Path $Root ('target\coverage\'+$OriginRun+'\coverage-run.json')
    $archive=Join-Path $outer 'archived-target-profiles-v2'; $archiveReceipt=Join-Path $archive 'receipt.json'
    Assert-CoverageCachePlain $target
    if (([IO.File]::ReadAllText((Join-Path $origin '.task-owner'))).TrimEnd("`r","`n") -cne ('AIGuardFabric coverage.ps1 '+$OriginRun)) { throw 'Compile cache owner differs' }
    Assert-CoverageCacheSha $archiveReceipt $ArchiveReceiptSha
    $proof=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($archiveReceipt))
    if ($proof.Schema -cne 'agf.coverage-profile-archive.v2' -or $proof.Status -cne 'PASS' -or $proof.RunId -cne $OriginRun -or $proof.MovedTargetProfileCount -ne 429 -or $proof.MovedMergedDataCount -ne 1 -or $proof.AlreadyArchivedSourceProfileCount -ne 3 -or $proof.TotalPreservedFileCount -ne 433 -or $proof.OriginalFailureReclassified -or @($proof.Rollback).Count -ne 0 -or @($proof.RollbackErrors).Count -ne 0) { throw 'Exact 433-file archive proof differs' }
    Assert-CoverageCacheSha (Join-Path $outer 'receipt.json') $proof.OriginalOuterReceiptSha256
    Assert-CoverageCacheSha $product $proof.OriginalProductReceiptSha256
    Assert-CoverageCacheSha (Join-Path $outer 'orphaned-source-profiles-v1\receipt.json') $proof.SourceOrphansReceiptSha256
    $orphanProof=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $outer 'orphaned-source-profiles-v1\receipt.json')))
    if ($orphanProof.Status -cne 'PASS' -or $orphanProof.Moved.Count -ne 3) { throw 'Source orphan archive differs' }
    foreach ($row in $orphanProof.Moved) { Assert-CoverageCacheSha $row.Destination $row.Sha256; if (Test-Path -LiteralPath $row.Source) { throw 'Source orphan reappeared' } }
    $oldProduct=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($product))
    $oldOuter=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $outer 'receipt.json')))
    if ($oldProduct.status -cne 'FAIL' -or $oldOuter.Status -cne 'FAIL' -or $oldProduct.runId -cne $OriginRun -or $oldProduct.target -cne $target -or $oldProduct.profileCount -ne 429 -or $oldProduct.historicalProfilesUsed -or !$oldProduct.workspaceAllTargets) { throw 'Original failed run provenance differs' }
    $seen=@{}
    foreach ($row in $proof.ArchivedFiles) {
        $destination=[IO.Path]::GetFullPath($row.Destination)
        if ([IO.Path]::GetDirectoryName($destination) -cne $archive -or $seen.ContainsKey($destination)) { throw 'Archive path escaped or duplicated' }
        Assert-CoverageCacheSha $destination $row.Sha256
        if ((Get-Item -LiteralPath $destination).Length -ne $row.Length) { throw 'Archive length differs' }
        $seen[$destination]=$true
    }
    if ($seen.Count -ne 430) { throw 'Archived target file set incomplete' }
    foreach ($entry in $oldOuter.Tools.PSObject.Properties) { Assert-CoverageCacheSha $entry.Name $entry.Value.sha256 }
    # 不声称旧缓存每个对象有历史 SHA 证据；仅复用本项目归属明确、工具一致的 Cargo 编译缓存。
    $bytes=0L; $fileCount=0L
    foreach ($file in Get-CoverageCacheFiles $target) {
        if ($file.Extension -ceq '.profraw' -or $file.Name -ceq 'AIGuardFabric.profdata') { throw 'Historical profile remains in compile cache' }
        $bytes+=$file.Length; $fileCount++
    }
    return [ordered]@{Schema='agf.coverage-cache-reuse.v1';CompileTarget=$target;CompileTargetCacheOriginRunId=$OriginRun;ArchiveReceipt=$archiveReceipt;ArchiveReceiptSha256=$ArchiveReceiptSha;OriginalOuterReceipt=Join-Path $outer 'receipt.json';OriginalOuterReceiptSha256=$proof.OriginalOuterReceiptSha256;OriginalProductReceipt=$product;OriginalProductReceiptSha256=$proof.OriginalProductReceiptSha256;OriginalNativeManifestSha256=$oldOuter.RustInputsManifestSha256;OldProfileFilesPreserved=432;OldMergedDataPreserved=1;HistoricalProfilesUsed=$false;ExistingTargetBytes=$bytes;ExistingTargetFileCount=$fileCount;CacheObjectHistoricalShaAttested=$false}
}
