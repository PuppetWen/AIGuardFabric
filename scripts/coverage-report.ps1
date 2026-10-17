#Requires -Version 5.1
# 仅处理官方工具在 Windows 创建 LLVM 进程前遇到的 206；原尝试日志与退出码保持不变。
function Get-CoverageArgvSha256([string[]]$Arguments) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash(([Text.UTF8Encoding]::new($false)).GetBytes((ConvertTo-Json -InputObject $Arguments -Compress))))).Replace('-','') }
    finally { $sha.Dispose() }
}
function Assert-CoverageReportPlain([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Coverage report reparse refused' }
        if ($item -is [IO.FileInfo]) { $item = $item.Directory } else { $item = $item.Parent }
    }
}
function Get-Coverage206Request([string]$Name, [string]$Diagnostic, [string]$Llvm, [string]$Tool, [string]$Root, [string]$Target, [string]$Reports, [string]$ExpectedLlvmSha256) {
    if ($Name -cnotin @('summary','summary-json','lcov','html')) { throw 'Unknown coverage report phase' }
    # PS5 的显示折行不属于官方 argv；只接受唯一反引号边界且完全无引号的当前固定形状。
    $flat = $Diagnostic.Replace("`r",'').Replace("`n",'')
    $matches = [regex]::Matches($flat, 'could not execute process\s+`([^`]+)` \(never executed\):[^`]*?\(os error 206\)')
    if ($matches.Count -ne 1 -or @([regex]::Matches($flat,'`')).Count -ne 2) { throw 'Not an exact never-executed os206 diagnostic' }
    $text = $matches[0].Groups[1].Value
    if ($text -match '["\x00\t]') { throw 'Unsupported displayed argv quoting' }
    $tokens = @($text.Split(' ') | Where-Object { $_ -cne '' })
    $subcommand = switch ($Name) { 'summary' {'report'} 'html' {'show'} default {'export'} }
    $format = switch ($Name) { 'summary' {'-use-color=0'} 'lcov' {'-format=lcov'} 'html' {'-format=html'} default {'-format=text'} }
    if ($tokens.Count -lt 8 -or $tokens[0] -cne $Llvm -or $tokens[1] -cne $subcommand -or $tokens[2] -cne $format -or $tokens[3] -cne ('-instr-profile='+(Join-Path $Target 'AIGuardFabric.profdata'))) { throw 'Unexpected LLVM executable/subcommand/profile' }
    foreach ($spec in @(@{Path=$Llvm;Sha=$ExpectedLlvmSha256},@{Path=$Tool;Sha='BCE4A4FC9F68A7FED55FF32BAD2DD629506ED44D549E6A841088FDD891E46F4E'})) {
        Assert-CoverageReportPlain $spec.Path
        if ($spec.Sha -cnotmatch '^[0-9A-F]{64}$' -or (Get-FileHash -LiteralPath $spec.Path).Hash -cne $spec.Sha) { throw 'Fixed official coverage tool differs' }
    }
    $index = 4; $objects = New-Object 'System.Collections.Generic.List[object]'; $seen = @{}
    while ($index -lt $tokens.Count -and $tokens[$index] -ceq '-object') {
        if ($index+1 -ge $tokens.Count) { throw 'Object argument absent' }
        $relative = $tokens[$index+1]; $absolute = [IO.Path]::GetFullPath((Join-Path $Root $relative))
        if ($relative -cne $absolute.Substring($Root.Length+1) -or !$absolute.StartsWith($Target+'\',[StringComparison]::Ordinal) -or $relative -match '(^|\\)\.\.?(\\|$)' -or [IO.Path]::GetExtension($absolute) -cnotin @('.exe','.dll') -or $seen.ContainsKey($absolute)) { throw 'Duplicate or escaped LLVM object' }
        Assert-CoverageReportPlain $absolute
        $objects.Add([ordered]@{Path=$absolute;RelativePath=$relative;Sha256=(Get-FileHash -LiteralPath $absolute).Hash})
        $seen[$absolute]=$true; $index+=2
    }
    if (!$objects.Count -or $index+1 -ge $tokens.Count -or $tokens[$index] -cne '-ignore-filename-regex') { throw 'Complete object list/filter absent' }
    $ignore = $tokens[$index+1]; $index+=2
    # 不增减官方过滤器；机器路径从项目、当前用户和现有 rustup 环境推导。
    $userProfile=[Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    $rustupHome=if($env:RUSTUP_HOME){$env:RUSTUP_HOME}else{Join-Path $userProfile '.rustup'}
    $targetRegex=([regex]::Escape($Target)).Replace('-','\-')
    $profileRegex=[regex]::Escape($userProfile)
    $cargoRegex=[regex]::Escape((Join-Path $Root '.cargo'))
    $toolchainsRegex=[regex]::Escape((Join-Path $rustupHome 'toolchains'))
    $expectedIgnore='(^|\\)(rustc\\([0-9a-f]+|[0-9]+\.[0-9]+\.[0-9]+)|tests|examples|benches)\\|\\(tests\.rs|[0-9a-zA-Z_-]+[_-]tests\.rs)$|^'+$targetRegex+'($|\\)|^'+$profileRegex+'($|\\)|^'+$cargoRegex+'\\(registry|git)\\|^'+$toolchainsRegex+'($|\\)'
    if ($ignore -cne $expectedIgnore) { throw 'Official source filter changed; review required' }
    $tail = @(); if ($index -lt $tokens.Count) { $tail = @($tokens[$index..($tokens.Count-1)]) }
    $expectedTail = @()
    if ($Name -ceq 'summary-json') { $expectedTail = @('-summary-only') }
    if ($Name -ceq 'html') { $expectedTail = @('-show-instantiations=false','-show-line-counts-or-regions','-show-expansions','-show-branches=count','-show-mcdc',('-Xdemangler='+$Tool),('-output-dir='+(Join-Path $Reports 'html'))) }
    if ($tail.Count -ne @($expectedTail).Count -or (Get-CoverageArgvSha256 $tail) -cne (Get-CoverageArgvSha256 @($expectedTail))) { throw 'Extra report options refused' }
    $arguments = @($tokens[2..($tokens.Count-1)])
    foreach ($argument in $arguments) { if ($argument -match '["\r\n\x00]' -or $argument.EndsWith('\')) { throw 'Unsafe response argument shape' } }
    return [ordered]@{Program=$Llvm;Subcommand=$subcommand;Arguments=$arguments;ArgvSha256=Get-CoverageArgvSha256 @($tokens[1..($tokens.Count-1)]);ObjectListSha256=Get-CoverageArgvSha256 @($objects | ForEach-Object {$_.RelativePath});Objects=$objects.ToArray();IgnoreSha256=Get-CoverageArgvSha256 @($ignore)}
}
function Invoke-Coverage206Response([string]$Name, $Request, [string]$Reports, [string]$Root) {
    $utf8 = New-Object Text.UTF8Encoding($false)
    $response = Join-Path $Reports ($Name+'.rsp')
    $stream = [IO.File]::Open($response,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $bytes=$utf8.GetBytes((($Request.Arguments | ForEach-Object {'"'+$_+'"'}) -join "`n")+"`n"); $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    $stdout = Join-Path $Reports ($Name+'.rsp.log'); $stderr = Join-Path $Reports ($Name+'.rsp.stderr.log')
    $outStream=$null; $errStream=$null; $child=$null
    $started=[DateTimeOffset]::UtcNow.ToString('o'); $code=$null
    try {
        $outStream=[IO.File]::Open($stdout,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        $errStream=[IO.File]::Open($stderr,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        $start=New-Object Diagnostics.ProcessStartInfo
        $start.FileName=$Request.Program; $start.Arguments=$Request.Subcommand+' "@'+$response+'"'; $start.WorkingDirectory=$Root
        $start.UseShellExecute=$false; $start.CreateNoWindow=$true; $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
        $child=New-Object Diagnostics.Process; $child.StartInfo=$start
        if (!$child.Start()) { throw 'LLVM response process did not start' }
        $outCopy=$child.StandardOutput.BaseStream.CopyToAsync($outStream); $errCopy=$child.StandardError.BaseStream.CopyToAsync($errStream)
        $watch=[Diagnostics.Stopwatch]::StartNew()
        while (!$child.WaitForExit(250)) { if ($watch.Elapsed.TotalMinutes -gt 30 -or $outStream.Length -gt 512MB -or $errStream.Length -gt 32MB) { throw 'LLVM response report budget exceeded' } }
        $child.WaitForExit(); $outCopy.GetAwaiter().GetResult(); $errCopy.GetAwaiter().GetResult(); $code=$child.ExitCode
        if ($outStream.Length -gt 512MB -or $errStream.Length -gt 32MB) { throw 'LLVM response final output budget exceeded' }
        $outStream.Flush($true); $errStream.Flush($true)
    } finally {
        if ($child) { try { if (!$child.HasExited) { $child.Kill(); $child.WaitForExit() } } finally { $child.Dispose() } }
        if ($outStream) { $outStream.Dispose() }; if ($errStream) { $errStream.Dispose() }
    }
    foreach ($object in $Request.Objects) { Assert-CoverageReportPlain $object.Path; if ((Get-FileHash -LiteralPath $object.Path).Hash -cne $object.Sha256) { throw 'LLVM object changed during response report' } }
    if ($code -eq 0 -and $Name -cin @('summary-json','lcov')) {
        $destination=Join-Path $Reports $(if($Name -ceq 'summary-json'){'summary.json'}else{'lcov.info'})
        # 初次 never-executed 分支不得已产出任何最终报告，避免覆盖未知字节。
        if (Test-Path -LiteralPath $destination) { throw 'Unexpected pre-existing final report' }
        [IO.File]::Copy($stdout,$destination,$false)
    }
    $warningText=[IO.File]::ReadAllText($stderr)
    $mismatch=@([regex]::Matches($warningText,'warning: ([0-9]+) functions have mismatched data'))
    return [ordered]@{name=$Name;known206Fallback=$true;originalExitCode=1;effectiveExitCode=$code;program=$Request.Program;subcommand=$Request.Subcommand;arguments=$Request.Arguments;originalArgvSha256=$Request.ArgvSha256;responseArgvSha256=$Request.ArgvSha256;objectListSha256=$Request.ObjectListSha256;ignoreSha256=$Request.IgnoreSha256;objectCount=$Request.Objects.Count;response=$response;responseSha256=(Get-FileHash -LiteralPath $response).Hash;stdout=$stdout;stderr=$stderr;stdoutSha256=(Get-FileHash -LiteralPath $stdout).Hash;stderrSha256=(Get-FileHash -LiteralPath $stderr).Hash;mismatchedFunctions=@($mismatch | ForEach-Object {[long]$_.Groups[1].Value});startedUtc=$started;finishedUtc=[DateTimeOffset]::UtcNow.ToString('o')}
}
