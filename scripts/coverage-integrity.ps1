#Requires -Version 5.1
# 零警告是默认合同；Hash0 分类例外只接受本轮完整证明，不能更改四报告的真实退出码。
function Get-CoverageNativeContext([string]$Root,[string]$Name,[string]$ReceiptSha,[string]$InputsSha,[string]$Policy,[string]$ProofDirectory) {
    if (!$Name -and !$ReceiptSha -and !$InputsSha) { if ($Policy -cne 'ZeroMismatchOnly') { throw '显式几何证明必须绑定实际 Native 验收' }; return $null }
    if ($Name -cnotmatch '^backend-verification-v[1-9][0-9]*\.json$' -or $ReceiptSha -cnotmatch '^[0-9A-F]{64}$' -or $InputsSha -cnotmatch '^[0-9A-F]{64}$') { throw 'Native 三参数必须完整提供' }
    if (!$Root) { $Root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')) }
    $task=if ($ProofDirectory) { [IO.Path]::GetFullPath($ProofDirectory) } else { Join-Path $Root '.tmp\coverage-native' }
    $receiptPath=Join-Path $task $Name; Assert-CoverageCacheSha $receiptPath $ReceiptSha
    $receipt=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($receiptPath))
    $inputsPath=Join-Path $task ($Name.Replace('.json','-inputs.json')); Assert-CoverageCacheSha $inputsPath $InputsSha
    if ($receipt.Status -cne 'PASS' -or $receipt.Completed -isnot [bool] -or !$receipt.Completed -or $receipt.RustInputsUnchanged -isnot [bool] -or !$receipt.RustInputsUnchanged -or $receipt.RustInputsManifest -cne $inputsPath -or $receipt.RustInputsManifestSha256 -cne $InputsSha) { throw 'Native 实际终态和输入绑定不符' }
    $names=@('clippy-default','clippy-loopback','lib-default','api-tests','lib-loopback','alicloud-transports','managed-api','gateway-deferred-transport','public-log-parsers','agent-tests','phase1-new-api','agent-core-docs')
    if (@($receipt.Gates).Count -ne $names.Count) { throw 'Native 十二门禁不完整' }
    foreach ($gateName in $names) {
        $gate=@($receipt.Gates | Where-Object {$_.Gate -ceq $gateName})
        $log=Join-Path $task ('backend-'+$Name.Replace('backend-verification-','').Replace('.json','')+'-'+$gateName+'.log')
        if ($gate.Count -ne 1 -or $gate[0].ExitCode -ne 0 -or $gate[0].Log -cne $log) { throw 'Native 门禁身份/退出码不符' }; Assert-CoverageCacheSha $log $gate[0].Sha256
    }
    $rows=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($inputsPath)); $seen=@{}
    if ($rows -isnot [array] -or $rows.Count -ne $receipt.RustInputCount -or !$rows.Count) { throw 'Native 输入计数不符' }
    foreach ($row in $rows) {
        $path=[IO.Path]::GetFullPath((Join-Path $Root $row.Path))
        if (!$path.StartsWith($Root+'\',[StringComparison]::Ordinal) -or $row.Path -cne $path.Substring($Root.Length+1).Replace('\','/') -or $seen.ContainsKey($path)) { throw 'Native 输入路径逃逸/重复' }
        $seen[$path]=$true; Assert-CoverageCacheSha $path $row.Sha256
    }
    return [ordered]@{ReceiptName=$Name;Receipt=[ordered]@{Path=$receiptPath;Sha256=$ReceiptSha};Inputs=[ordered]@{Path=$inputsPath;Sha256=$InputsSha};InputCount=$rows.Count;SourceRowsVerified=$true;SourceSetClosureResponsibility='OuterFrozenInputs'}
}
function New-CoverageIntegrityContext([string]$RunId,[string]$Root,[string]$Target,[string]$Reports,$Objects,$Artifacts,$Profiles,$Merged,$Llvm,$Native,$Commands,$Results,[string]$Policy,[string]$Tool) {
    $python='D:\Environment\pyenv-win\pyenv-win\versions\3.13.0\python.exe'; $pythonSha='62EBC90A2884BB63A0CD67E789CAFDD51E771EEE043587E2354327B4CCC9BB05'
    $analyzer=Join-Path $Root 'scripts\coverage-fresh-mapping.py'
    $reportCommands=@($Commands | Where-Object {$_.name -cin @('summary','summary-json','lcov','html')})
    return [ordered]@{RunId=$RunId;Root=$Root;Target=$Target;Reports=$Reports;Objects=$Objects;ObjectSetSha256=$Artifacts.ObjectSetSha256;CurrentArtifacts=[ordered]@{Path=$Artifacts.Path;Sha256=$Artifacts.Sha256};Profiles=$Profiles;ProfileSetSha256=$Merged.ProfileSetSha256;Merged=[ordered]@{Path=$Merged.Path;Sha256=$Merged.Sha256};ReviewedLlvmTools=$Llvm;NativeReceiptName=if($Native){$Native.ReceiptName}else{$null};NativeReceipt=if($Native){$Native.Receipt}else{$null};NativeInputs=if($Native){$Native.Inputs}else{$null};SourceState=if($Native){$Native.Inputs}else{$null};FourReportCommands=$reportCommands;FourReportResults=$Results;Policy=$Policy;Tool=$Tool;Python=[ordered]@{Path=$python;Sha256=$pythonSha};Analyzer=[ordered]@{Path=$analyzer;Sha256=(Get-FileHash -LiteralPath $analyzer).Hash}}
}
function Assert-CoverageRawReportFacts($Context) {
    $names=@('summary','summary-json','lcov','html'); $warnings=$false
    if (@($Context.FourReportCommands).Count -ne 4 -or @($Context.FourReportResults).Count -ne 4) { throw '四原始报告事实不完整' }
    for ($i=0;$i -lt $names.Count;$i++) {
        $command=$Context.FourReportCommands[$i]; $result=$Context.FourReportResults[$i]
        if ($command.name -cne $names[$i] -or $result.name -cne $names[$i] -or $command.exitCode -ne 0 -or $result.effectiveExitCode -ne 0 -or $result.zeroMismatchedData -isnot [bool]) { throw '报告实际非零退出不能豁免' }
        foreach ($kind in @('stdout','stderr')) { Assert-CoverageCacheSha $command.$kind $command.($kind+'Sha256') }
        $zero=$true; try { Assert-CoverageZeroMismatch $command.stderr } catch { $zero=$false }
        if ($zero -ne $result.zeroMismatchedData) { throw '原警告字段与真实 stderr 不符' }
        if (!$zero) { $warnings=$true }
    }
    return $warnings
}
function Invoke-CoverageReportIntegrity($Context) {
    $warnings=Assert-CoverageRawReportFacts $Context
    if (!$warnings) { return [ordered]@{Accepted=$true;Mode='ZeroMismatchOnly';StrongZeroMismatch=$true;Proof=$null;Commands=@()} }
    if ($Context.Policy -cne 'FreshHashZeroDuplicateMappingProof') { throw '默认零警告策略拒绝 LLVM mismatch，原四报告保留' }
    $proof=Invoke-CoverageFreshMappingProof $Context
    if ($proof.Accepted -isnot [bool] -or !$proof.Accepted -or $proof.Mode -cne 'FreshHashZeroDuplicateMappingProof' -or $proof.StrongZeroMismatch -isnot [bool] -or $proof.StrongZeroMismatch -or @($proof.Commands).Count -ne 3) { throw '本轮完整几何证明没有明确通过' }
    # 模块内部已重新计算完整证明；这里核引用原字节，outer 消费时再独立重算。
    if ($proof.Proof.Schema -cne 'agf.coverage-fresh-hash-zero-mapping.v1' -or $proof.Proof.Path -cne (Join-Path $Context.Reports 'fresh-mapping-proof.json')) { throw '本轮证明引用身份不符' }; Assert-CoverageCacheSha $proof.Proof.Path $proof.Proof.Sha256
    return $proof
}
function Assert-CoverageReportIntegrity($Context,$Receipt) {
    $warnings=Assert-CoverageRawReportFacts $Context
    if ($Receipt.reportIntegrityAccepted -isnot [bool] -or !$Receipt.reportIntegrityAccepted -or $Receipt.zeroMismatchedData -isnot [bool] -or $Receipt.zeroMismatchedData -ne (!$warnings) -or $Receipt.strongZeroMismatch -isnot [bool] -or $Receipt.reportIntegrityPolicy -cne $Context.Policy) { throw '报告完整性接受字段不符' }
    if (!$warnings) {
        if (!$Receipt.strongZeroMismatch -or $Receipt.reportIntegrityMode -cne 'ZeroMismatchOnly' -or $null -ne $Receipt.freshMappingProof -or @($Receipt.verificationCommands).Count -ne 0) { throw '零警告报告不得创造例外证明' }; return
    }
    if ($Context.Policy -cne 'FreshHashZeroDuplicateMappingProof' -or $Receipt.strongZeroMismatch -or $Receipt.reportIntegrityMode -cne $Context.Policy -or @($Receipt.verificationCommands).Count -ne 3) { throw '有警告报告必须如实声明专门证明策略' }
    $checked=Assert-CoverageFreshMappingProof $Context $Receipt.freshMappingProof
    if ($checked.Accepted -isnot [bool] -or !$checked.Accepted -or $checked.Mode -cne $Context.Policy -or $checked.StrongZeroMismatch -isnot [bool] -or $checked.StrongZeroMismatch) { throw '独立完整几何证明重算没有通过' }
    for ($i=0;$i -lt 3;$i++) { if ((ConvertTo-Json -InputObject $checked.Commands[$i] -Depth 8 -Compress) -cne (ConvertTo-Json -InputObject $Receipt.verificationCommands[$i] -Depth 8 -Compress)) { throw '三次原始证明命令与重算引用不同' } }
}
