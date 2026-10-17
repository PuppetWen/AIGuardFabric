#Requires -Version 5.1
# 仅同轮完整对象/profile 的几何证明；原始 mismatch 与旧失败保持原样。
function Get-CoverageFreshRef([string]$Path) {
    Assert-CoverageReportPlain $Path
    return [ordered]@{Path=$Path;Sha256=(Get-FileHash -LiteralPath $Path).Hash;Length=(Get-Item -LiteralPath $Path).Length}
}
function Assert-CoverageFreshRef($Ref) {
    if (!$Ref -or $Ref.Sha256 -cnotmatch '^[0-9A-F]{64}$') { throw '证明引用 SHA 缺失' }
    Assert-CoverageReportPlain ([string]$Ref.Path)
    if ((Get-FileHash -LiteralPath $Ref.Path).Hash -cne $Ref.Sha256) { throw '证明引用字节改变' }
    if ($Ref.PSObject.Properties['Length'] -and (Get-Item -LiteralPath $Ref.Path).Length -ne $Ref.Length) { throw '证明引用长度改变' }
}
function Write-CoverageFreshJson([string]$Path,$Value) {
    $bytes=([Text.UTF8Encoding]::new($false)).GetBytes((ConvertTo-Json -InputObject $Value -Depth 64)+"`n")
    $file=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $file.Write($bytes,0,$bytes.Length);$file.Flush($true) } finally {$file.Dispose()}
}
function ConvertTo-CoverageFreshCanonical($Value) {
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) {return $Value}
    if ($Value -is [Collections.IDictionary]) {
        $result=[ordered]@{};foreach($key in @($Value.Keys | Sort-Object -CaseSensitive)) {$result[$key]=ConvertTo-CoverageFreshCanonical $Value[$key]};return $result
    }
    if ($Value -is [pscustomobject]) {
        $result=[ordered]@{};foreach($property in @($Value.PSObject.Properties | Sort-Object Name -CaseSensitive)) {$result[$property.Name]=ConvertTo-CoverageFreshCanonical $property.Value};return $result
    }
    if ($Value -is [Collections.IEnumerable]) {
        $result=New-Object 'System.Collections.Generic.List[object]';foreach($entry in $Value){$result.Add((ConvertTo-CoverageFreshCanonical $entry))};return ,($result.ToArray())
    }
    throw '未知上下文值类型'
}
function Assert-CoverageFreshContext($Context) {
    if ($Context.Policy -cne 'FreshHashZeroDuplicateMappingProof' -or $Context.RunId -cnotmatch '^[0-9a-f]{32}$') { throw '必须显式选择本轮几何证明策略' }
    foreach ($name in @('Root','Target','Reports')) {
        $path=[string]$Context.$name
        if ([IO.Path]::GetFullPath($path) -cne $path -or !(Test-Path -LiteralPath $path -PathType Container)) { throw '证明目录身份无效' }
        $item=Get-Item -LiteralPath $path -Force
        while ($item) { if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw '证明目录含 reparse' };$item=$item.Parent }
    }
    if (!$Context.Target.StartsWith($Context.Root+'\',[StringComparison]::Ordinal) -or !$Context.Reports.StartsWith($Context.Root+'\',[StringComparison]::Ordinal)) { throw '证明目录逃逸项目' }
    foreach ($name in @('NativeReceipt','NativeInputs','SourceState','CurrentArtifacts','Merged','Python','Analyzer')) { Assert-CoverageFreshRef $Context.$name }
    if ($Context.Python.Sha256 -cne '62EBC90A2884BB63A0CD67E789CAFDD51E771EEE043587E2354327B4CCC9BB05') { throw '未审定 Python 工具' }
    if ($Context.Analyzer.Path -cne (Join-Path $Context.Root 'scripts\coverage-fresh-mapping.py')) { throw '分析器不是项目专属脚本' }
    if ($Context.CurrentArtifacts.Path -cne (Join-Path $Context.Reports 'current-workspace-artifacts.json')) { throw '对象证明路径不符' }
    if ($Context.SourceState.Path -cne $Context.NativeInputs.Path -or $Context.SourceState.Sha256 -cne $Context.NativeInputs.Sha256) { throw 'Native 源绑定不同' }
    $tools=$Context.ReviewedLlvmTools
    foreach ($name in @('cov','profdata')) { Assert-CoverageFreshRef ([pscustomobject]@{Path=$tools.$name;Sha256=$tools.($name+'Sha256')}) }
    Assert-CoverageFreshRef ([pscustomobject]@{Path=$tools.manifest;Sha256=$tools.manifestSha256})
    $artifact=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Context.CurrentArtifacts.Path))
    $metadataPath=Join-Path $Context.Reports 'metadata.log'
    Assert-CoverageFreshRef ([pscustomobject]@{Path=$metadataPath;Sha256=$artifact.MetadataSha256})
    $metadata=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($metadataPath))
    $universe=Get-CoverageTargetUniverse $metadata $Context.Root $Context.Target
    $compiled=$null;$tested=$null
    foreach ($name in @('Compile','Tests')) {
        $saved=$artifact.$name
        Assert-CoverageFreshRef ([pscustomobject]@{Path=$saved.Log;Sha256=$saved.LogSha256})
        $actual=Get-CoverageCargoArtifacts $saved.Log $universe $Context.Target -RequireAllTargets
        if ($actual.ObjectSetSha256 -cne $saved.ObjectSetSha256 -or $actual.ProducerSetSha256 -cne $saved.ProducerSetSha256) { throw '当前 Cargo 完整对象/producer 集合改变' }
        if ($name -ceq 'Compile') { $compiled=$actual } else {$tested=$actual}
    }
    Assert-CoverageCurrentObjectSets $compiled $tested
    $objectHash=Get-CoverageArgvSha256 @($Context.Objects | ForEach-Object {$_.Path+'|'+$_.Sha256+'|'+$_.Length})
    if ($objectHash -cne $Context.ObjectSetSha256 -or $tested.ObjectSetSha256 -cne $objectHash) { throw '上下文对象集合改变' }
    $profileHash=Get-CoverageArgvSha256 @($Context.Profiles.Keys | Sort-Object | ForEach-Object {$_+'|'+$Context.Profiles[$_]})
    if ($profileHash -cne $Context.ProfileSetSha256 -or !$Context.Profiles.Count) { throw '上下文 profile 集合改变' }
    foreach ($path in $Context.Profiles.Keys) { Assert-CoverageFreshRef ([pscustomobject]@{Path=$path;Sha256=$Context.Profiles[$path]}) }
    $names=@('summary','summary-json','lcov','html')
    if ($Context.FourReportCommands.Count -ne 4 -or $Context.FourReportResults.Count -ne 4) { throw '四报告事实不完整' }
    for ($i=0;$i -lt 4;$i++) {
        $command=$Context.FourReportCommands[$i];$result=$Context.FourReportResults[$i]
        $request=Get-CoverageCurrentRequest $names[$i] $tools.cov $Context.Tool $Context.Root $Context.Target $Context.Reports $Context.Merged.Path $Context.Objects
        $argvHash=Get-CoverageArgvSha256 (@($request.Subcommand)+@($request.Arguments))
        if ($command.name -cne $names[$i] -or $command.program -cne $request.Program -or $command.subcommand -cne $request.Subcommand -or $command.argvSha256 -cne $argvHash -or (Get-CoverageArgvSha256 (@($command.subcommand)+@($command.arguments))) -cne $argvHash) { throw '原报告 argv/官方 filter 不符' }
        if ($result.argvSha256 -cne $argvHash -or $result.ignoreSha256 -cne $request.IgnoreSha256 -or $result.objectSetSha256 -cne $objectHash -or $result.objectCount -ne $Context.Objects.Count) { throw '原报告对象/filter 证明不符' }
        foreach ($name in @('response','stdout','stderr')) {
            if ($name -ceq 'response' -and $command.$name -cne $result.$name) { throw '原报告 response 引用不符' }
            if ($command.($name+'Sha256') -cne $result.($name+'Sha256')) { throw '原报告输出引用不符' }
            Assert-CoverageFreshRef ([pscustomobject]@{Path=$command.$name;Sha256=$command.($name+'Sha256')})
        }
    }
}
function Invoke-CoverageFreshAnalyzer($Context,[string]$Mode,[string]$ContextPath,[string]$CommandsPath,$ProofRef) {
    Assert-CoverageFreshRef $Context.Python;Assert-CoverageFreshRef $Context.Analyzer
    $arguments=@('-I','-X','utf8','-B',$Context.Analyzer.Path,$Mode,'--context',$ContextPath,'--commands',$CommandsPath)
    if ($Mode -ceq 'analyze') {$arguments+=@('--output',$ProofRef.Path)} else {$arguments+=@('--proof',$ProofRef.Path,'--proof-sha256',$ProofRef.Sha256)}
    foreach ($argument in $arguments) { if ($argument -match '["\r\n\x00]' -or $argument.EndsWith('\')) {throw 'Python 参数不安全'} }
    $start=New-Object Diagnostics.ProcessStartInfo
    $start.FileName=$Context.Python.Path;$start.Arguments=($arguments | ForEach-Object {'"'+$_+'"'}) -join ' '
    $start.WorkingDirectory=$Context.Root;$start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $child=New-Object Diagnostics.Process;$child.StartInfo=$start
    $outStream=New-Object IO.MemoryStream;$errStream=New-Object IO.MemoryStream
    try {
        if (!$child.Start()) {throw 'Python 证明进程未启动'}
        $stdout=$child.StandardOutput.BaseStream.CopyToAsync($outStream);$stderr=$child.StandardError.BaseStream.CopyToAsync($errStream);$watch=[Diagnostics.Stopwatch]::StartNew()
        while (!$child.WaitForExit(250)) { $child.Refresh();if ($watch.Elapsed.TotalSeconds -gt 300 -or $child.WorkingSet64 -gt 4GB -or $outStream.Length -gt 65536 -or $errStream.Length -gt 65536) {throw 'Python 证明超过预算'} }
        $child.WaitForExit();$null=$stdout.GetAwaiter().GetResult();$null=$stderr.GetAwaiter().GetResult()
        $out=[Text.Encoding]::UTF8.GetString($outStream.ToArray());$err=[Text.Encoding]::UTF8.GetString($errStream.ToArray())
        if ($out.Length -gt 65536 -or $err.Length -gt 65536 -or $child.ExitCode -ne 0 -or $err.Length) {throw ('Python 证明失败：'+$err)}
        $result=ConvertFrom-Json -InputObject $out
        if ($result.Accepted -isnot [bool] -or !$result.Accepted -or $result.StrongZeroMismatch -isnot [bool] -or $result.StrongZeroMismatch) {throw 'Python 证明返回合同不符'}
    } finally {if($child){try{if(!$child.HasExited){$child.Kill();$child.WaitForExit()}}finally{$child.Dispose()}};$outStream.Dispose();$errStream.Dispose()}
    Assert-CoverageFreshRef $Context.Python;Assert-CoverageFreshRef $Context.Analyzer
}
function Invoke-CoverageFreshMappingProof($Context) {
    Assert-CoverageFreshContext $Context
    $contextPath=Join-Path $Context.Reports 'fresh-mapping-context.json'
    $commandsPath=Join-Path $Context.Reports 'fresh-mapping-commands.json'
    $proofPath=Join-Path $Context.Reports 'fresh-mapping-proof.json'
    Write-CoverageFreshJson $contextPath $Context
    $base=@($Context.FourReportCommands[1].arguments)
    $withoutSummary=@($base[0..($base.Count-2)])
    $empty=@($withoutSummary);$empty[1]='-empty-profile'
    $requests=@(@($base+@('-dump','-num-threads=1')),$withoutSummary,$empty)
    $names=@('fresh-mapping-dump','fresh-mapping-full','fresh-mapping-empty');$commands=@()
    for($i=0;$i -lt 3;$i++) {
        $commands+=@(Invoke-CoverageCurrentProcess -Name $names[$i] -Program $Context.ReviewedLlvmTools.cov -Subcommand 'export' -Arguments $requests[$i] -Reports $Context.Reports -Root $Context.Root -TimeoutSeconds 180 -MaxWorkingSetBytes 16GB -MaxStderrBytes 64MB)
    }
    Write-CoverageFreshJson $commandsPath $commands
    Invoke-CoverageFreshAnalyzer $Context 'analyze' $contextPath $commandsPath ([pscustomobject]@{Path=$proofPath})
    $ref=Get-CoverageFreshRef $proofPath;$ref.Schema='agf.coverage-fresh-hash-zero-mapping.v1'
    $null=Assert-CoverageFreshMappingProof $Context ([pscustomobject]$ref)
    return [ordered]@{Accepted=$true;Mode='FreshHashZeroDuplicateMappingProof';StrongZeroMismatch=$false;Proof=$ref;Commands=$commands}
}
function Assert-CoverageFreshMappingProof($Context,$ProofRef) {
    Assert-CoverageFreshContext $Context;Assert-CoverageFreshRef $ProofRef
    if ($ProofRef.Path -cne (Join-Path $Context.Reports 'fresh-mapping-proof.json') -or $ProofRef.Schema -cne 'agf.coverage-fresh-hash-zero-mapping.v1') {throw '独立证明引用身份不符'}
    $contextPath=Join-Path $Context.Reports 'fresh-mapping-context.json';$commandsPath=Join-Path $Context.Reports 'fresh-mapping-commands.json'
    Assert-CoverageReportPlain $contextPath;Assert-CoverageReportPlain $commandsPath
    $saved=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($contextPath))
    if ((ConvertTo-Json -InputObject (ConvertTo-CoverageFreshCanonical $saved) -Depth 64 -Compress) -cne (ConvertTo-Json -InputObject (ConvertTo-CoverageFreshCanonical $Context) -Depth 64 -Compress)) {throw '证明上下文与当前实际合同不同'}
    Invoke-CoverageFreshAnalyzer $Context 'verify' $contextPath $commandsPath $ProofRef
    Assert-CoverageFreshContext $Context
    $commands=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($commandsPath))
    return [ordered]@{Accepted=$true;Mode='FreshHashZeroDuplicateMappingProof';StrongZeroMismatch=$false;Proof=$ProofRef;Commands=$commands}
}
