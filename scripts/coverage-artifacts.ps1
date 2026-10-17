#Requires -Version 5.1
# Cargo 当轮协议而非旧 target 目录决定报告对象；测试 stdout 在 build-finished 之后仅保存，不解释。
function Get-CoverageTargetKey([string]$PackageId,$Target) {
    if (!$PackageId -or !$Target.name -or ![IO.Path]::IsPathRooted([string]$Target.src_path)) { throw 'Cargo target 身份字段缺失' }
    return Get-CoverageArgvSha256 @($PackageId,[string]$Target.src_path,[string]$Target.name,(@($Target.kind) -join ','),(@($Target.crate_types) -join ','))
}
function Get-CoverageTargetUniverse($Metadata,[string]$Root,[string]$TargetDirectory) {
    if ($Metadata.target_directory -cne $TargetDirectory -or !$Metadata.workspace_members.Count) { throw 'Metadata workspace/target 不符' }
    $members=@{}; $targets=@{}; $excluded=New-Object 'System.Collections.Generic.List[object]'
    foreach ($id in $Metadata.workspace_members) { if ($members.ContainsKey($id)) { throw '重复 workspace member' }; $members[$id]=$true }
    $packages=@{}
    foreach ($package in $Metadata.packages) {
        if (!$members.ContainsKey($package.id)) { continue }
        if ($packages.ContainsKey($package.id)) { throw '重复 metadata package' }; $packages[$package.id]=$package.name
        foreach ($target in $package.targets) {
            $src=[IO.Path]::GetFullPath([string]$target.src_path)
            if ($src -cne $target.src_path -or !$src.StartsWith($Root+'\',[StringComparison]::Ordinal)) { throw 'Workspace target 源文件逃逸' }
            Assert-CoverageReportPlain $src
            $required=$target.PSObject.Properties['required-features']
            # 当前工作区无此类目标；未来出现必须显式提供真实 feature 证据后重新审查，不能静默漏掉。
            if ($null -ne $required -and $null -ne $required.Value -and @($required.Value).Count -gt 0) { throw '非空 required-features 尚未审查，拒绝缩小目标集合' }
            $key=Get-CoverageTargetKey $package.id $target
            if ($targets.ContainsKey($key)) { throw '重复 metadata target' }
            $row=[ordered]@{Key=$key;PackageId=$package.id;Package=$package.name;Name=$target.name;Source=$src;Kind=@($target.kind);CrateTypes=@($target.crate_types)}
            if (@($target.kind) -ccontains 'custom-build') { $excluded.Add([ordered]@{Target=$row;Reason='custom-build 不是报告对象或被测目标'}); continue }
            $targets[$key]=$row
        }
    }
    if ($packages.Count -ne $members.Count -or !$targets.Count) { throw 'Metadata workspace member/目标不完整' }
    return [pscustomobject]@{Members=$members;Packages=$packages;Targets=$targets;Excluded=$excluded.ToArray()}
}
function Get-CoverageCargoArtifacts([string]$Log,$Universe,[string]$TargetDirectory,[switch]$RequireAllTargets) {
    Assert-CoverageReportPlain $Log
    if ((Get-Item -LiteralPath $Log).Length -gt 128MB) { throw 'Cargo JSON 日志超过预算' }
    $seenTargets=@{}; $objects=@{}; $records=New-Object 'System.Collections.Generic.List[object]'
    $finished=$false; $protocolLines=0; $opaqueLines=0; $dependencyArtifacts=0
    $reader=[IO.File]::OpenText($Log)
    try {
        while ($null -ne ($line=$reader.ReadLine())) {
            if ($finished) { $opaqueLines++; continue }
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try { $message=ConvertFrom-Json -InputObject $line } catch { throw 'build-finished 前出现非 Cargo JSON 协议行' }
            if ($null -eq $message -or !$message.PSObject.Properties['reason']) { throw 'Cargo 协议 reason 缺失' }
            $protocolLines++
            if ($message.reason -ceq 'build-finished') {
                if ($message.success -isnot [bool] -or !$message.success) { throw 'Cargo build-finished 未严格成功' }
                $finished=$true; continue
            }
            if ($message.reason -cin @('compiler-message','build-script-executed')) { continue }
            if ($message.reason -cne 'compiler-artifact') { throw '未知 Cargo 协议事件' }
            if ($message.fresh -isnot [bool]) { throw 'Cargo fresh 字段不是 bool' }
            if (!$Universe.Members.ContainsKey([string]$message.package_id)) { $dependencyArtifacts++; continue }
            if (@($message.target.kind) -ccontains 'custom-build') { continue }
            $key=Get-CoverageTargetKey $message.package_id $message.target
            if (!$Universe.Targets.ContainsKey($key)) { throw '当轮 artifact 不属于 metadata target 集合' }
            $seenTargets[$key]=$true; $paths=@($message.filenames)
            if ($null -ne $message.executable) { $paths+=@([string]$message.executable) }
            $recordObjects=New-Object 'System.Collections.Generic.List[string]'
            foreach ($path in @($paths | Sort-Object -Unique)) {
                if ([IO.Path]::GetExtension([string]$path) -cnotin @('.exe','.dll')) { continue }
                $full=[IO.Path]::GetFullPath([string]$path)
                if ($full -cne $path -or !$full.StartsWith($TargetDirectory+'\',[StringComparison]::Ordinal)) { throw 'Cargo 报告对象逃逸编译目录' }
                Assert-CoverageReportPlain $full
                if (!$objects.ContainsKey($full)) { $objects[$full]=[ordered]@{Path=$full;Sha256=(Get-FileHash -LiteralPath $full).Hash;Length=(Get-Item -LiteralPath $full).Length} }
                $recordObjects.Add($full)
            }
            $records.Add([ordered]@{TargetKey=$key;Fresh=$message.fresh;Features=@($message.features | Sort-Object);Profile=$message.profile;Objects=$recordObjects.ToArray()})
        }
    } finally { $reader.Dispose() }
    if (!$finished -or !$seenTargets.Count) { throw 'Cargo 协议缺少唯一成功结束或 workspace artifacts' }
    if ($RequireAllTargets -and ($seenTargets.Count -ne $Universe.Targets.Count -or @($Universe.Targets.Keys | Where-Object {!$seenTargets.ContainsKey($_)}).Count)) { throw 'workspace all-targets 的 metadata 闭包不完整' }
    $rows=@($objects.Keys | Sort-Object | ForEach-Object {$objects[$_]})
    if (!$rows.Count) { throw '当轮 workspace exe/DLL 集合为空' }
    $producerKeys=@($records | ForEach-Object {$_.TargetKey+'|'+(ConvertTo-Json -InputObject $_.Features -Compress)+'|'+(ConvertTo-Json -InputObject $_.Profile -Compress)+'|'+(Get-CoverageArgvSha256 @($_.Objects))} | Sort-Object)
    return [ordered]@{Log=$Log;LogSha256=(Get-FileHash -LiteralPath $Log).Hash;BuildFinishedSuccess=$true;ProtocolLines=$protocolLines;OpaqueTestLines=$opaqueLines;DependencyArtifactCount=$dependencyArtifacts;Targets=@($seenTargets.Keys | Sort-Object);Artifacts=$records.ToArray();ProducerSetSha256=Get-CoverageArgvSha256 $producerKeys;Objects=$rows;ObjectSetSha256=Get-CoverageArgvSha256 @($rows | ForEach-Object {$_.Path+'|'+$_.Sha256+'|'+$_.Length})}
}
function Assert-CoverageCurrentObjectSets($Compile,$Tests) {
    if ($Compile.ObjectSetSha256 -cne $Tests.ObjectSetSha256 -or $Compile.ProducerSetSha256 -cne $Tests.ProducerSetSha256 -or $Compile.Objects.Count -ne $Tests.Objects.Count -or (Get-CoverageArgvSha256 @($Compile.Targets)) -cne (Get-CoverageArgvSha256 @($Tests.Targets))) { throw '预编译与实际全测试的完整当前对象/目标/features/profile/SHA 集合不一致' }
    foreach ($row in $Tests.Objects) { Assert-CoverageReportPlain $row.Path; if ((Get-FileHash -LiteralPath $row.Path).Hash -cne $row.Sha256 -or (Get-Item -LiteralPath $row.Path).Length -ne $row.Length) { throw '当前 workspace 对象已改变' } }
}
function Get-CoverageHistoricalObjectDifference([string]$TargetDirectory,$Current) {
    $currentPaths=@{}; foreach ($row in $Current) { $currentPaths[$row.Path]=$true }
    $stack=New-Object 'System.Collections.Generic.Stack[string]'; $stack.Push((Join-Path $TargetDirectory 'debug'))
    $different=New-Object 'System.Collections.Generic.List[object]'; $count=0
    while ($stack.Count) { foreach ($entry in Get-ChildItem -LiteralPath $stack.Pop() -Force) {
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw '历史对象诊断树含 reparse' }
        if (++$count -gt 200000) { throw '历史对象诊断树超过预算' }
        if ($entry.PSIsContainer) { $stack.Push($entry.FullName); continue }
        if ($entry.Extension -cin @('.exe','.dll') -and !$currentPaths.ContainsKey($entry.FullName)) { $different.Add([ordered]@{Path=$entry.FullName;Length=$entry.Length;HistoricalBytesAttested=$false;Reason='不在当轮完整 workspace Cargo artifact 集合；仅诊断保留，不删除或当作206等价对象'}) }
    } }
    return $different.ToArray()
}
