#Requires -Version 5.1
# 明确 CurrentWorkspaceArtifacts 模式；对象集合与历史递归扫描不同，不宣称是等价 206 重试。
function Get-CoverageOfficialFilter([string]$Target,[string]$Root) {
    $userProfile=[Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    $rustupHome=if($env:RUSTUP_HOME){$env:RUSTUP_HOME}else{Join-Path $userProfile '.rustup'}
    $targetRegex=([regex]::Escape($Target)).Replace('-','\-')
    $profileRegex=[regex]::Escape($userProfile)
    $cargoRegex=[regex]::Escape((Join-Path $Root '.cargo'))
    $toolchainsRegex=[regex]::Escape((Join-Path $rustupHome 'toolchains'))
    return '(^|\\)(rustc\\([0-9a-f]+|[0-9]+\.[0-9]+\.[0-9]+)|tests|examples|benches)\\|\\(tests\.rs|[0-9a-zA-Z_-]+[_-]tests\.rs)$|^'+$targetRegex+'($|\\)|^'+$profileRegex+'($|\\)|^'+$cargoRegex+'\\(registry|git)\\|^'+$toolchainsRegex+'($|\\)'
}
function Invoke-CoverageCurrentProcess([string]$Name,[string]$Program,[string]$Subcommand,[string[]]$Arguments,[string]$Reports,[string]$Root,[ValidateRange(1,1800)][int]$TimeoutSeconds=1800,[ValidateRange(0,17179869184)][long]$MaxWorkingSetBytes=0,[ValidateRange(33554432,67108864)][long]$MaxStderrBytes=32MB) {
    Assert-CoverageReportPlain $Program
    $toolSha=if($Subcommand -ceq 'merge'){'9990E978D4523095174C901ED1D5ED688A0D84321BC37E831A5364910380CA6C'}else{'A00BE974FA188AEE2942C303145BC77CF5CD69ECD23135CF4A470E6517186D57'}
    if ((Get-FileHash -LiteralPath $Program).Hash -cne $toolSha) { throw '审定 LLVM22 工具字节改变' }
    foreach ($argument in $Arguments) { if ($argument -match '["\r\n\x00]' -or $argument.EndsWith('\')) { throw '响应文件参数不安全' } }
    $rsp=Join-Path $Reports ($Name+'.rsp'); $stdout=Join-Path $Reports ($Name+'.log'); $stderr=Join-Path $Reports ($Name+'.stderr.log')
    $bytes=([Text.UTF8Encoding]::new($false)).GetBytes((($Arguments | ForEach-Object {'"'+$_+'"'}) -join "`n")+"`n")
    $stream=[IO.File]::Open($rsp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    $outStream=$null; $errStream=$null; $child=$null; $started=[DateTimeOffset]::UtcNow.ToString('o'); $code=$null
    try {
        $outStream=[IO.File]::Open($stdout,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        $errStream=[IO.File]::Open($stderr,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        $start=New-Object Diagnostics.ProcessStartInfo
        $start.FileName=$Program; $start.Arguments=$Subcommand+' "@'+$rsp+'"'; $start.WorkingDirectory=$Root
        $start.UseShellExecute=$false; $start.CreateNoWindow=$true; $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
        # 保持官方 HTML 子进程的 demangler 合同；其余阶段明确清除此变量，不更改宿主环境。
        $start.EnvironmentVariables.Remove('__CARGO_LLVM_COV_DEMANGLER')
        if ($Name -ceq 'html') { $start.EnvironmentVariables['__CARGO_LLVM_COV_DEMANGLER']='1' }
        $child=New-Object Diagnostics.Process; $child.StartInfo=$start
        if (!$child.Start()) { throw 'LLVM 响应文件进程未启动' }
        $outCopy=$child.StandardOutput.BaseStream.CopyToAsync($outStream); $errCopy=$child.StandardError.BaseStream.CopyToAsync($errStream); $watch=[Diagnostics.Stopwatch]::StartNew()
        while (!$child.WaitForExit(250)) { $child.Refresh(); if ($watch.Elapsed.TotalSeconds -gt $TimeoutSeconds -or $outStream.Length -gt 512MB -or $errStream.Length -gt $MaxStderrBytes -or ($MaxWorkingSetBytes -gt 0 -and $child.WorkingSet64 -gt $MaxWorkingSetBytes)) { throw 'LLVM 响应文件进程超过时间/输出预算' } }
        $child.WaitForExit(); $null=$outCopy.GetAwaiter().GetResult(); $null=$errCopy.GetAwaiter().GetResult(); $code=$child.ExitCode
        if ($outStream.Length -gt 512MB -or $errStream.Length -gt $MaxStderrBytes) { throw 'LLVM 最终输出超过预算' }
        $outStream.Flush($true); $errStream.Flush($true)
    } finally {
        if ($child) { try { if (!$child.HasExited) { $child.Kill(); $child.WaitForExit() } } finally { $child.Dispose() } }
        if ($outStream) { $outStream.Dispose() }; if ($errStream) { $errStream.Dispose() }
    }
    if ((Get-FileHash -LiteralPath $Program).Hash -cne $toolSha) { throw 'LLVM22 执行期间工具字节改变' }
    return [ordered]@{name=$Name;program=$Program;programSha256=$toolSha;demanglerEnvironment=if($Name -ceq 'html'){'1'}else{$null};subcommand=$Subcommand;arguments=$Arguments;exitCode=$code;startedUtc=$started;finishedUtc=[DateTimeOffset]::UtcNow.ToString('o');timeoutSeconds=$TimeoutSeconds;maxWorkingSetBytes=$MaxWorkingSetBytes;maxStderrBytes=$MaxStderrBytes;stdout=$stdout;stderr=$stderr;response=$rsp;responseSha256=(Get-FileHash -LiteralPath $rsp).Hash;argvSha256=Get-CoverageArgvSha256 (@($Subcommand)+$Arguments);stdoutSha256=(Get-FileHash -LiteralPath $stdout).Hash;stderrSha256=(Get-FileHash -LiteralPath $stderr).Hash}
}
function Assert-CoverageZeroMismatch([string]$Stderr) {
    $text=[IO.File]::ReadAllText($Stderr)
    # 默认拒绝不匹配；显式策略只能用同轮完整几何证明接受，不能声称原警告消失。
    if ($text -match '(?i)mismatched?\s+(?:profile\s+)?data|hash[_ -]mismatch|profile.*(?:out.of.date|mismatch)|malformed instrumentation profile') { throw 'LLVM 数据不匹配，报告分母不可信；原 stderr 已保留' }
}
function Merge-CoverageCurrentProfiles([string]$Profdata,[string]$Reports,[string]$Root,$Profiles) {
    $merged=Join-Path $Reports 'current-workspace.profdata'
    if (Test-Path -LiteralPath $merged) { throw '本轮 merged 数据已存在' }
    $arguments=@('-sparse','-o',$merged)
    foreach ($path in @($Profiles.Keys | Sort-Object)) { Assert-CoverageReportPlain $path; if ((Get-FileHash -LiteralPath $path).Hash -cne $Profiles[$path]) { throw '合并前新 profile 改变' }; $arguments+=@($path) }
    if ($Profiles.Count -le 0) { throw '没有本轮 profile' }
    $result=Invoke-CoverageCurrentProcess 'merge-profiles' $Profdata 'merge' $arguments $Reports $Root
    if ($result.exitCode -ne 0) { throw '本轮 profile 合并失败，原输出已保留' }
    Assert-CoverageZeroMismatch $result.stderr; if ([IO.File]::ReadAllText($result.stderr) -match '(?im)\bwarning\b') { throw 'profile 合并必须没有警告，原始 stderr 保留' }; Assert-CoverageReportPlain $merged
    foreach ($path in $Profiles.Keys) { if ((Get-FileHash -LiteralPath $path).Hash -cne $Profiles[$path]) { throw '合并后新 profile 改变' } }
    return [ordered]@{Command=$result;Path=$merged;Sha256=(Get-FileHash -LiteralPath $merged).Hash;ProfileCount=$Profiles.Count;ProfileSetSha256=Get-CoverageArgvSha256 @($Profiles.Keys | Sort-Object | ForEach-Object {$_+'|'+$Profiles[$_]})}
}
function Get-CoverageCurrentRequest([string]$Name,[string]$Llvm,[string]$Tool,[string]$Root,[string]$Target,[string]$Reports,[string]$Merged,$Objects) {
    Assert-CoverageReportPlain $Tool
    if ((Get-FileHash -LiteralPath $Tool).Hash -cne 'BCE4A4FC9F68A7FED55FF32BAD2DD629506ED44D549E6A841088FDD891E46F4E') { throw '固定官方 demangler 工具改变' }
    $subcommand=switch($Name){'summary'{'report'} 'html'{'show'} 'summary-json'{'export'} 'lcov'{'export'} default{throw '未知报告格式'}}
    $format=switch($Name){'summary'{'-use-color=0'} 'html'{'-format=html'} 'lcov'{'-format=lcov'} default{'-format=text'}}
    $arguments=@($format,('-instr-profile='+$Merged)); $seen=@{}
    foreach ($object in $Objects) {
        $path=[string]$object.Path
        if (!$path.StartsWith($Target+'\',[StringComparison]::Ordinal) -or $seen.ContainsKey($path) -or [IO.Path]::GetExtension($path) -cnotin @('.exe','.dll')) { throw '当前报告对象重复或逃逸' }
        Assert-CoverageReportPlain $path
        if ((Get-FileHash -LiteralPath $path).Hash -cne $object.Sha256 -or (Get-Item -LiteralPath $path).Length -ne $object.Length) { throw '当前报告对象 SHA/长度改变' }
        $seen[$path]=$true; $arguments+=@('-object',$path.Substring($Root.Length+1))
    }
    if (!$seen.Count) { throw '报告对象为空' }
    $filter=Get-CoverageOfficialFilter $Target $Root; $arguments+=@('-ignore-filename-regex',$filter)
    if ($Name -ceq 'summary-json') { $arguments+=@('-summary-only') }
    if ($Name -ceq 'html') { $arguments+=@('-show-instantiations=false','-show-line-counts-or-regions','-show-expansions','-show-branches=count','-show-mcdc',('-Xdemangler='+$Tool),('-output-dir='+(Join-Path $Reports 'html'))) }
    return [ordered]@{Program=$Llvm;Subcommand=$subcommand;Arguments=$arguments;IgnoreSha256=Get-CoverageArgvSha256 @($filter);ObjectSetSha256=Get-CoverageArgvSha256 @($Objects | ForEach-Object {$_.Path+'|'+$_.Sha256+'|'+$_.Length})}
}
function Invoke-CoverageCurrentReport([string]$Name,$Request,[string]$Reports,[string]$Root,$Objects) {
    $command=Invoke-CoverageCurrentProcess $Name $Request.Program $Request.Subcommand $Request.Arguments $Reports $Root
    # 输出已保留；上层记录真实 exit。mismatch 不被转成 effective 成功。
    $mismatch=$false
    try { Assert-CoverageZeroMismatch $command.stderr } catch { $mismatch=$true }
    foreach ($object in $Objects) { if ((Get-FileHash -LiteralPath $object.Path).Hash -cne $object.Sha256) { throw '报告期间当前对象改变' } }
    return [ordered]@{Command=$command;Result=[ordered]@{name=$Name;mode='CurrentWorkspaceArtifacts';known206Fallback=$false;originalAttempted=$false;effectiveExitCode=$command.exitCode;zeroMismatchedData=(!$mismatch);argvSha256=$command.argvSha256;objectSetSha256=$Request.ObjectSetSha256;ignoreSha256=$Request.IgnoreSha256;objectCount=$Objects.Count;response=$command.response;responseSha256=$command.responseSha256;stdoutSha256=$command.stdoutSha256;stderrSha256=$command.stderrSha256}}
}
