#Requires -Version 5.1
# 官方组件来源由独立审定清单固定；本函数只读核实路径、字节及实际版本，不下载安装。
function Get-CoverageReviewedLlvm([string]$Root,[string]$ManifestPath,[string]$ExpectedSha,$Fallback) {
    $proof=$null
    if ($ManifestPath) {
        $path=[IO.Path]::GetFullPath($ManifestPath)
        if ($path -cne $ManifestPath -or !$path.StartsWith((Join-Path $Root '.tmp\') , [StringComparison]::Ordinal)) { throw 'Reviewed LLVM manifest escaped project scratch' }
        Assert-CoverageCacheSha $path $ExpectedSha
        $proof=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($path))
        if ($proof.Schema -cne 'agf-reviewed-llvm-tools-v1' -or $proof.Status -cne 'PASS' -or $proof.Completed -isnot [bool] -or !$proof.Completed -or !$proof.IsolatedTaskOnly -or $proof.RustupOrSourceModified -or $proof.CargoExecuted -or $proof.ExpectedLlvmVersion -cne '22.1.6' -or $proof.OfficialComponentUrl -cnotmatch '^https://static\.rust-lang\.org/dist/[0-9-]+/llvm-tools-1\.97\.1-x86_64-pc-windows-msvc\.tar\.xz$') { throw 'Reviewed official LLVM provenance incomplete' }
        foreach ($spec in @($proof.Compiler,$proof.LlvmCov,$proof.LlvmProfdata,$proof.OfficialManifest,$proof.OfficialManifestChecksum,$proof.OfficialPackage)) { Assert-CoverageCacheSha $spec.Path $spec.Sha256; if ((Get-Item -LiteralPath $spec.Path).Length -ne $spec.Length) { throw 'Reviewed tool/source length differs' } }
        $llvm=[pscustomobject]@{cov=$proof.LlvmCov.Path;profdata=$proof.LlvmProfdata.Path;source='审定的官方 rustc 匹配 LLVM 组件'}
    } else {
        if ($ExpectedSha) { throw 'Reviewed tool SHA without manifest' }
        $llvm=$Fallback
    }
    if ($null -eq $llvm) { throw 'LLVM tools absent' }
    $rustc=Get-AgfTool -Name rustc
    foreach ($path in @($rustc,$llvm.cov,$llvm.profdata)) { Assert-CoverageCachePlain $path }
    $rustVersion=@(& $rustc --version --verbose); if ($LASTEXITCODE -ne 0) { throw 'Rustc version failed' }
    $covVersion=@(& $llvm.cov --version); if ($LASTEXITCODE -ne 0) { throw 'LLVM cov version failed' }
    $profVersion=@(& $llvm.profdata --version); if ($LASTEXITCODE -ne 0) { throw 'LLVM profdata version failed' }
    $versions=@()
    foreach ($lines in @(@{Lines=$rustVersion},@{Lines=$covVersion},@{Lines=$profVersion})) {
        $matches=@([regex]::Matches(($lines.Lines -join "`n"),'LLVM version:?\s+([0-9]+\.[0-9]+\.[0-9]+)'))
        if ($matches.Count -ne 1) { throw 'Exact LLVM version absent' }; $versions+=$matches[0].Groups[1].Value
    }
    if ($versions[0] -cne $versions[1] -or $versions[0] -cne $versions[2]) { throw 'Rustc/llvm-cov/llvm-profdata LLVM versions differ' }
    if ($proof) {
        if ($proof.Compiler.Path -cne $rustc -or $proof.ExpectedLlvmVersion -cne $versions[0]) { throw 'Actual reviewed tool identity/version differs' }
    }
    return [ordered]@{cov=$llvm.cov;profdata=$llvm.profdata;source=$llvm.source;manifest=$ManifestPath;manifestSha256=$ExpectedSha;llvmVersion=$versions[0];rustcVersion=$rustVersion;covVersion=$covVersion;profdataVersion=$profVersion;covSha256=(Get-FileHash -LiteralPath $llvm.cov).Hash;profdataSha256=(Get-FileHash -LiteralPath $llvm.profdata).Hash}
}
