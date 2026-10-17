#Requires -Version 5.1
<#
.SYNOPSIS
    全工作区行覆盖率门禁，默认 >=70%，报告来自本轮唯一 profiles。
.DESCRIPTION
    只读复用 tools/bin/cargo-llvm-cov.exe 与既有 LLVM 工具，不安装组件。
    先用官方 show-env 配置 instrumentation，构建插件 DLL/agent 真实夹具，
    先完整预编译 workspace all-targets，再固定夹具 SHA 并真实执行全部测试。report 只复用同轮 profiles。
    每轮报告保存 target/coverage/<UUID>；默认新编译目录，可显式复用已归档旧计数的本项目编译缓存。
    不复用历史 profiles；显式缓存复用仍完整重新执行所有测试，并透明记录原失败；当前对象报告模式不等价于历史递归扫描。
    RunId 可由验收包装器固定；默认新 GUID，已存在目录直接拒绝。
    忽略的 SQL/真实云专项仍须单独验收；稳定工具不启用 nightly doctest instrumentation。
#>
param(
    [ValidateRange(0, 100)][double]$Threshold = 70.0,
    [ValidateRange(1, 2)][int]$BuildJobs = 1,
    [ValidatePattern('^[0-9a-f]{32}$')][string]$RunId = ([Guid]::NewGuid().ToString('N')),
    [ValidatePattern('^(|[0-9a-f]{32})$')][string]$ReuseBuildCacheRunId = '',
    [ValidatePattern('^(|[0-9A-F]{64})$')][string]$ExpectedReuseArchiveReceiptSha256 = '',
    [string]$ReviewedLlvmToolsManifest = '',
    [ValidatePattern('^(|[0-9A-F]{64})$')][string]$ExpectedReviewedLlvmToolsSha256 = '',
    [ValidateSet('ZeroMismatchOnly','FreshHashZeroDuplicateMappingProof')][string]$ReportIntegrityPolicy='ZeroMismatchOnly',
    [string]$NativeReceiptName='',
    [ValidatePattern('^(|[0-9A-F]{64})$')][string]$ExpectedNativeReceiptSha256='',
    [ValidatePattern('^(|[0-9A-F]{64})$')][string]$ExpectedNativeInputsSha256='',
    [switch]$Open
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Include lib/env discovery and all early failures in process-environment restoration.
$coveragePreviousEnvironment = [Environment]::GetEnvironmentVariables('Process')
$coveragePreviousLocation = (Get-Location).Path
$coverageStatus = 'FAIL'
$coverageRun = $RunId
$coverageReportResults = New-Object 'System.Collections.Generic.List[object]'
$coverageArtifactProof = $null
$coverageMerge = $null
$coverageNativeContext=$null
$coverageIntegrity=[ordered]@{Accepted=$false;Mode=$null;StrongZeroMismatch=$false;Proof=$null;Commands=@()}
$coverageCacheReuse = $null
$coverageCommands = New-Object 'System.Collections.Generic.List[object]'
$coverageFailure = $null
$coverageOutDir = $null
$coverageDirectoriesOwned = $false
$coverageLines = 0L
$coverageCovered = 0L
$coveragePercent = $null
$coverageProfiles = @{}
$coveragePrerequisites = @{}
$coveragePrerequisiteBuildHashes = @{}
$compileExit = $null
$coveragePackages = @()
$coverageRuntime = $null
$coverageTarget = $null
$testExit = $null
function Invoke-CoverageCommand([string]$Name, [string]$Program, [string[]]$Arguments) {
    $stdout = Join-Path $coverageOutDir ($Name + '.log')
    $stderr = Join-Path $coverageOutDir ($Name + '.stderr.log')
    $previous = $ErrorActionPreference
    $started = [DateTimeOffset]::UtcNow.ToString('o')
    try {
        # PS5 treats native stderr as PowerShell errors; assess the native exit code explicitly.
        $ErrorActionPreference = 'Continue'
        & $Program @Arguments 1> $stdout 2> $stderr
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previous }
    $coverageCommands.Add([ordered]@{name=$Name;program=$Program;arguments=$Arguments;exitCode=$code;startedUtc=$started;finishedUtc=[DateTimeOffset]::UtcNow.ToString('o');stdout=$stdout;stderr=$stderr})
    return $code
}
function Assert-CoverageProfiles {
    $actual = @(Get-ChildItem -LiteralPath $coverageTarget -File -Filter '*.profraw' -Recurse)
    if ($actual.Count -eq 0 -or $actual.Count -ne $coverageProfiles.Count) { throw '同轮 profile 集合已改变或为空' }
    foreach ($file in $actual) {
        if (!$coverageProfiles.ContainsKey($file.FullName) -or (Get-FileHash -LiteralPath $file.FullName).Hash -cne $coverageProfiles[$file.FullName]) { throw '同轮 profile 字节已改变' }
    }
}
function Get-CoveragePrerequisiteHashes {
    $hashes=@{}
    foreach ($binary in @('agf_plugin_example.dll','agf-agent.exe')) {
        $path=Join-Path $coverageTarget ('debug\'+$binary)
        if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw ('同轮真实夹具缺失，拒绝 fallback/跳过：'+$binary) }
        $hashes[$path]=(Get-FileHash -LiteralPath $path).Hash
    }
    return $hashes
}
function ConvertFrom-CoverageEnvironment([string[]]$lines) {
    # cargo-llvm-cov 0.9.1 emits PowerShell 6 Unicode escapes; decode strictly on PS5, never evaluate it.
    $allowed = @('LLVM_PROFILE_FILE','CARGO_LLVM_COV_TARGET_DIR','CARGO_LLVM_COV_BUILD_DIR','CARGO_LLVM_COV','CARGO_LLVM_COV_SHOW_ENV','RUSTC_WRAPPER','__CARGO_LLVM_COV_RUSTC_WRAPPER','__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS','__CARGO_LLVM_COV_RUSTC_WRAPPER_CRATE_NAMES')
    $values = @{}
    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $match = [regex]::Match($line, '^\$env:([A-Z0-9_]+)="((?:`u\{[0-9a-fA-F]+\})*)"$')
        if (!$match.Success -or $allowed -cnotcontains $match.Groups[1].Value -or $values.ContainsKey($match.Groups[1].Value)) { throw 'Unexpected show-env output refused.' }
        $builder = New-Object Text.StringBuilder
        foreach ($part in [regex]::Matches($match.Groups[2].Value, '`u\{([0-9a-fA-F]+)\}')) {
            $scalar = [Convert]::ToInt32($part.Groups[1].Value, 16)
            if ($scalar -eq 0) { throw 'NUL in tool environment refused.' }
            $null = $builder.Append([char]::ConvertFromUtf32($scalar))
        }
        $values[$match.Groups[1].Value] = $builder.ToString()
    }
    if ($values.Count -ne $allowed.Count) { throw 'Required instrumentation environment absent.' }
    return $values
}
function Resolve-LlvmTools {
    <#
    .SYNOPSIS
        定位 llvm-cov / llvm-profdata。
    .OUTPUTS
        @{ cov = <路径>; profdata = <路径>; source = <来源说明> } 或 $null
    #>
    $pairs = New-Object System.Collections.Generic.List[object]

    # 1) 显式环境变量
    if ($env:LLVM_COV -and $env:LLVM_PROFDATA) {
        $pairs.Add([pscustomobject]@{ dir = (Split-Path -Parent $env:LLVM_COV); source = '环境变量 LLVM_COV/LLVM_PROFDATA' })
    }
    # 2) .env 指定的目录
    $explicit = Get-AgfEnv -Name 'AGF_LLVM_BIN' -Default ''
    if ($explicit) {
        $pairs.Add([pscustomobject]@{ dir = $explicit; source = "AGF_LLVM_BIN=$explicit" })
    }
    # 3) rustup sysroot（用户自行装过 llvm-tools-preview 时）
    try {
        $sysroot = (& rustc --print sysroot 2>$null | Select-Object -First 1)
        if ($sysroot) {
            $rlib = Join-Path $sysroot 'lib\rustlib'
            if (Test-Path -LiteralPath $rlib) {
                $hit = Get-ChildItem -LiteralPath $rlib -Recurse -Filter 'llvm-cov.exe' -ErrorAction SilentlyContinue |
                    Select-Object -First 1
                if ($null -ne $hit) {
                    $pairs.Add([pscustomobject]@{ dir = $hit.DirectoryName; source = 'rustup sysroot 的 llvm-tools-preview' })
                }
            }
        }
    }
    catch { }
    # 4) 本机既有只读 LLVM 安装
    $ndkRoot = Join-Path $global:AgfEnvRoot 'Android\sdk\ndk'
    if (Test-Path -LiteralPath $ndkRoot) {
        foreach ($d in (Get-ChildItem -LiteralPath $ndkRoot -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)) {
            $pairs.Add([pscustomobject]@{
                    dir    = Join-Path $d.FullName 'toolchains\llvm\prebuilt\windows-x86_64\bin'
                    source = "Android SDK NDK $($d.Name) 自带 LLVM"
                })
        }
    }
    # 系统级 LLVM 的兜底搜索路径：盘符由 $env:ProgramFiles 提供，脚本里不写死绝对路径（铁律 4）
    foreach ($extra in @((Join-Path $env:ProgramFiles 'LLVM\bin'), (Join-Path $global:AgfEnvRoot 'LLVM\bin'))) {
        $pairs.Add([pscustomobject]@{ dir = $extra; source = $extra })
    }

    foreach ($p in $pairs) {
        $cov = Join-Path $p.dir 'llvm-cov.exe'
        $prof = Join-Path $p.dir 'llvm-profdata.exe'
        if ((Test-Path -LiteralPath $cov) -and (Test-Path -LiteralPath $prof)) {
            return [pscustomobject]@{ cov = $cov; profdata = $prof; source = $p.source }
        }
    }
    return $null
}

try {
    . "$PSScriptRoot\lib.ps1"
    . "$PSScriptRoot\coverage-cache.ps1"
    . "$PSScriptRoot\coverage-report.ps1"
    . "$PSScriptRoot\coverage-tools.ps1"
    . "$PSScriptRoot\coverage-artifacts.ps1"
    . "$PSScriptRoot\coverage-current-report.ps1"
    . "$PSScriptRoot\coverage-integrity.ps1"
    . "$PSScriptRoot\coverage-fresh-mapping.ps1"
    $root = $global:AgfRoot
    $coverageNativeContext=Get-CoverageNativeContext $root $NativeReceiptName $ExpectedNativeReceiptSha256 $ExpectedNativeInputsSha256 $ReportIntegrityPolicy
    $tool = Join-Path $root 'tools\bin\cargo-llvm-cov.exe'
    if (!(Test-Path -LiteralPath $tool -PathType Leaf)) { throw '缺少项目内 tools/bin/cargo-llvm-cov.exe；请核对 PV-012' }
    $llvm = Get-CoverageReviewedLlvm $root $ReviewedLlvmToolsManifest $ExpectedReviewedLlvmToolsSha256 (Resolve-LlvmTools)
    if ($null -eq $llvm) { throw '未找到既有 llvm-cov/llvm-profdata；请配置 LLVM_COV/LLVM_PROFDATA 或 AGF_LLVM_BIN，不自动安装组件' }
    $cargo = Get-AgfTool -Name cargo
    if (!$cargo) { throw '未找到既有 Cargo' }
    $coverageOutDir = Join-Path $root ('target\coverage\' + $coverageRun)
    $coverageRuntime = Join-Path $root ('.tmp\owned-cov\' + $coverageRun)
    $coverageTarget = Join-Path $coverageRuntime 't'
    if ($ReuseBuildCacheRunId) {
        $coverageCacheReuse=Get-CoverageReuseCache $root $ReuseBuildCacheRunId $ExpectedReuseArchiveReceiptSha256 $coverageRun
        $coverageTarget=$coverageCacheReuse.CompileTarget
    } elseif ($ExpectedReuseArchiveReceiptSha256) { throw '仅有 archive SHA，缺少显式 cache origin' }
    if ((Test-Path -LiteralPath $coverageOutDir) -or (Test-Path -LiteralPath $coverageRuntime)) { throw '本轮唯一目录已存在，拒绝混用历史产物' }
    New-Item -ItemType Directory -Path $coverageOutDir, $coverageRuntime | Out-Null
    if (!$coverageCacheReuse) { New-Item -ItemType Directory -Path $coverageTarget | Out-Null }
    Write-AgfTextFile -Path (Join-Path $coverageRuntime '.task-owner') -Content ('AIGuardFabric coverage.ps1 ' + $coverageRun)
    Write-AgfTextFile -Path (Join-Path $coverageOutDir '.task-owner') -Content ('AIGuardFabric coverage.ps1 ' + $coverageRun)
    $coverageDirectoriesOwned = $true
    Write-AgfInfo ('LLVM 工具来源：{0}' -f $llvm.source)
    foreach ($entry in Get-ChildItem Env:) {
        if ($entry.Name -match '^(LLVM_|__CARGO_LLVM_COV_|CARGO_LLVM_COV|CARGO_TARGET_.*_RUSTFLAGS$|RUSTFLAGS$|CARGO_ENCODED_RUSTFLAGS$|RUSTDOCFLAGS$|CARGO_ENCODED_RUSTDOCFLAGS$|RUSTC_WRAPPER$|RUSTC_WORKSPACE_WRAPPER$|AGF_TEST_.*(?:DATABASE|NATS)|(?:AGF_)?DATABASE_URL$|(?:AGF_)?NATS_URL$|PGPASSWORD$|CARGO_BUILD_BUILD_DIR$)') { [Environment]::SetEnvironmentVariable($entry.Name,$null,'Process') }
    }
    $env:CARGO_HOME = Join-Path $root '.cargo'
    $env:CARGO_TARGET_DIR = $coverageTarget
    $env:CARGO_LLVM_COV_TARGET_DIR = $coverageTarget
    $env:CARGO_LLVM_COV_BUILD_DIR = $coverageTarget
    $env:CARGO_BUILD_JOBS = [string]$BuildJobs
    $env:CARGO_INCREMENTAL = '0'
    $env:CARGO_NET_OFFLINE = 'true'
    $env:CARGO_LLVM_COV_SETUP = 'no'
    $env:CARGO_TERM_COLOR = 'never'
    $env:LLVM_COV = $llvm.cov
    $env:LLVM_PROFDATA = $llvm.profdata
    $coverageLlvmSha256=(Get-FileHash -LiteralPath $llvm.cov).Hash
    $env:LLVM_PROFILE_FILE_NAME = $coverageRun + '-%p-%m.profraw'
    $env:TEMP = Join-Path $coverageRuntime 'tmp'
    $env:TMP = $env:TEMP
    $env:AGF_DATA_DIR = Join-Path $coverageRuntime 'd'
    $env:AGF_TEST_DATA_DIR = $env:AGF_DATA_DIR
    $env:AGF_RISK_HISTORY_PATH = Join-Path $env:AGF_DATA_DIR 'state\risk-history.json'
    $env:AGF_SEED_FIXTURES = '0'
    New-Item -ItemType Directory -Path $env:TEMP, $env:AGF_DATA_DIR | Out-Null
    Set-Location -LiteralPath $root
    if ((Invoke-CoverageCommand 'show-env' $tool @('llvm-cov','show-env','--pwsh','--remap-path-prefix')) -ne 0) { throw '无法取得官方 coverage 环境' }
    # .NET detects BOMs: PS5 redirects stdout as UTF16, while other hosts can emit UTF8.
    $instrument = ConvertFrom-CoverageEnvironment ([IO.File]::ReadAllLines((Join-Path $coverageOutDir 'show-env.log')))
    if ($instrument.LLVM_PROFILE_FILE -cne (Join-Path $coverageTarget ($coverageRun+'-%p-%m.profraw')) -or $instrument.CARGO_LLVM_COV_TARGET_DIR -cne $coverageTarget -or $instrument.CARGO_LLVM_COV_BUILD_DIR -cne $coverageTarget -or $instrument.RUSTC_WRAPPER -cne $tool -or $instrument.CARGO_LLVM_COV -cne '1' -or $instrument.CARGO_LLVM_COV_SHOW_ENV -cne '1' -or $instrument.__CARGO_LLVM_COV_RUSTC_WRAPPER -cne '1') { throw '官方 coverage target/wrapper 环境不符' }
    $flags = $instrument.__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS.Split([char]31)
    if ($flags -cnotcontains 'instrument-coverage' -or $flags -cnotcontains '--cfg=coverage' -or [string]::IsNullOrWhiteSpace($instrument.__CARGO_LLVM_COV_RUSTC_WRAPPER_CRATE_NAMES)) { throw '官方 instrumentation 标记缺失' }
    foreach ($key in $instrument.Keys) { [Environment]::SetEnvironmentVariable($key,$instrument[$key],'Process') }
    if ((Invoke-CoverageCommand 'metadata' $cargo @('metadata','--no-deps','--format-version','1','--offline','--locked')) -ne 0) { throw '工作区 metadata 读取失败' }
    $metadata = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $coverageOutDir 'metadata.log')))
    if ($metadata.target_directory -cne $coverageTarget) { throw '工作区 metadata target 与本轮目录不符' }
    $expectedCrates = @()
    foreach ($package in $metadata.packages) {
        if (@($metadata.workspace_members) -cnotcontains $package.id) { continue }
        $coveragePackages += [ordered]@{name=$package.name;manifestPath=$package.manifest_path}
        $expectedCrates += $package.name.Replace('-','_')
        $expectedCrates += $package.name.Replace('-','_')+'_tests'
        foreach ($cargoTarget in $package.targets) { $expectedCrates += $cargoTarget.name.Replace('-','_') }
    }
    $expectedCrates = @($expectedCrates | Sort-Object -Unique)
    $actualCrates = @($instrument.__CARGO_LLVM_COV_RUSTC_WRAPPER_CRATE_NAMES.Split(',') | Sort-Object -Unique)
    if ($actualCrates.Count -ne $expectedCrates.Count -or @($expectedCrates | Where-Object { $actualCrates -cnotcontains $_ }).Count -ne 0) { throw '官方 instrumentation 未覆盖完整工作区 crate/target 集合' }
    if ((Invoke-CoverageCommand 'prerequisites' $cargo @('build','--profile','test','--message-format=json','--offline','--locked','-j',[string]$BuildJobs,'-p','agf-plugin-example','-p','agf-agent')) -ne 0) { throw '同轮 instrumented 插件/agent 构建失败' }
    $coveragePrerequisiteBuildHashes=Get-CoveragePrerequisiteHashes
    $universe=Get-CoverageTargetUniverse $metadata $root $coverageTarget
    $prerequisiteStage=Get-CoverageCargoArtifacts (Join-Path $coverageOutDir 'prerequisites.log') $universe $coverageTarget
    # workspace 特性统一可能正常重编并覆盖 prereq 产物；完整预编译后才固定测试期间不变的 SHA。
    $workspaceArgs=@('test','--workspace','--all-targets','--message-format=json','--offline','--locked','-j',[string]$BuildJobs,'--no-fail-fast')
    $compileExit=Invoke-CoverageCommand 'workspace-compile' $cargo ($workspaceArgs+@('--no-run'))
    if ($compileExit -ne 0) { throw '完整 workspace/all-targets 预编译失败，未执行测试' }
    $coveragePrerequisites=Get-CoveragePrerequisiteHashes
    $compileStage=Get-CoverageCargoArtifacts (Join-Path $coverageOutDir 'workspace-compile.log') $universe $coverageTarget -RequireAllTargets
    $testExit=Invoke-CoverageCommand 'workspace-tests' $cargo ($workspaceArgs+@('--','--test-threads=2'))
    $testStage=Get-CoverageCargoArtifacts (Join-Path $coverageOutDir 'workspace-tests.log') $universe $coverageTarget -RequireAllTargets
    Assert-CoverageCurrentObjectSets $compileStage $testStage
    foreach ($path in $coveragePrerequisites.Keys) {
        $objectPaths=@($path)
        if ($path -ceq (Join-Path $coverageTarget 'debug\agf_plugin_example.dll')) { $objectPaths+=Join-Path $coverageTarget 'debug\deps\agf_plugin_example.dll' }
        Assert-CoverageReportPlain $path; $fixture=Get-Item -LiteralPath $path
        if ((Get-FileHash -LiteralPath $path).Hash -cne $coveragePrerequisites[$path] -or @($testStage.Objects | Where-Object {$objectPaths -ccontains $_.Path -and $_.Sha256 -ceq $coveragePrerequisites[$path] -and $_.Length -eq $fixture.Length}).Count -ne 1) { throw '最终插件/Agent 夹具不在当前报告集合' }
    }
    $artifactPath=Join-Path $coverageOutDir 'current-workspace-artifacts.json'
    $artifactManifest=[ordered]@{Schema='agf.coverage-current-workspace-artifacts.v1';Mode='CurrentWorkspaceArtifacts';MetadataSha256=(Get-FileHash -LiteralPath (Join-Path $coverageOutDir 'metadata.log')).Hash;EligibleTargets=@($universe.Targets.Keys | Sort-Object | ForEach-Object {$universe.Targets[$_]});ExcludedTargets=$universe.Excluded;Prerequisites=$prerequisiteStage;Compile=$compileStage;Tests=$testStage;HistoricalScanOnlyDiagnostic=$true;HistoricalScanDifference=@(Get-CoverageHistoricalObjectDifference $coverageTarget $testStage.Objects)}
    Write-AgfTextFile -Path $artifactPath -Content ($artifactManifest | ConvertTo-Json -Depth 16)
    $coverageArtifactProof=[ordered]@{Path=$artifactPath;Sha256=(Get-FileHash -LiteralPath $artifactPath).Hash;Mode='CurrentWorkspaceArtifacts';ObjectSetSha256=$testStage.ObjectSetSha256;ObjectCount=$testStage.Objects.Count;EligibleTargetCount=$universe.Targets.Count;PrerequisiteObjectCount=$prerequisiteStage.Objects.Count;CompileAndTestIdentical=$true;ProfileBasedObjectFiltering=$false}
    foreach ($file in Get-ChildItem -LiteralPath $coverageTarget -File -Filter '*.profraw' -Recurse) {
        if ($file.DirectoryName -cne $coverageTarget -or $file.Name -cnotmatch ('^'+$coverageRun+'-[0-9]+-[0-9]+_[0-9]+\.profraw$')) { throw '检测到本轮身份之外的 profile' }
        $coverageProfiles[$file.FullName] = (Get-FileHash -LiteralPath $file.FullName).Hash
    }
    Assert-CoverageProfiles
    $thresholdText = $Threshold.ToString('R',[Globalization.CultureInfo]::InvariantCulture)
    $reportsOk = $true
    $coverageMerge=Merge-CoverageCurrentProfiles $llvm.profdata $coverageOutDir $root $coverageProfiles
    $coverageCommands.Add($coverageMerge.Command)
    foreach ($name in @('summary','summary-json','lcov','html')) {
        Assert-CoverageProfiles; Assert-CoverageCurrentObjectSets $compileStage $testStage
        $request=Get-CoverageCurrentRequest $name $llvm.cov $tool $root $coverageTarget $coverageOutDir $coverageMerge.Path $testStage.Objects
        $report=Invoke-CoverageCurrentReport $name $request $coverageOutDir $root $testStage.Objects
        $coverageCommands.Add($report.Command); $coverageReportResults.Add($report.Result)
        if ($report.Result.effectiveExitCode -ne 0) { $reportsOk=$false }
        Assert-CoverageProfiles
    }
    if (!$reportsOk -or $testExit -ne 0) { throw '完整测试或四报告实际命令失败，原始退出码和日志完整保留' }
    $integrityContext=New-CoverageIntegrityContext $coverageRun $root $coverageTarget $coverageOutDir $testStage.Objects $coverageArtifactProof $coverageProfiles $coverageMerge $llvm $coverageNativeContext $coverageCommands.ToArray() $coverageReportResults.ToArray() $ReportIntegrityPolicy $tool
    $coverageIntegrity=Invoke-CoverageReportIntegrity $integrityContext
    if ($coverageIntegrity.Accepted -isnot [bool] -or !$coverageIntegrity.Accepted) { throw '同轮报告完整性未通过' }
    foreach ($spec in @(@{From='summary-json.log';To='summary.json'},@{From='lcov.log';To='lcov.info'})) { [IO.File]::Copy((Join-Path $coverageOutDir $spec.From),(Join-Path $coverageOutDir $spec.To),$false) }
    $summary = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $coverageOutDir 'summary.json')))
    if ($summary.type -cne 'llvm.coverage.json.export' -or @($summary.data).Count -eq 0) { throw 'LLVM JSON 汇总结构不符' }
    foreach ($data in $summary.data) {
        $coverageLines += [long]$data.totals.lines.count
        $coverageCovered += [long]$data.totals.lines.covered
    }
    if ($coverageLines -le 0 -or $coverageCovered -lt 0 -or $coverageCovered -gt $coverageLines) { throw 'LLVM JSON 行统计无效' }
    $coveragePercent = 100.0*$coverageCovered/$coverageLines
    foreach ($binaryPath in $coveragePrerequisites.Keys) { if ((Get-FileHash -LiteralPath $binaryPath).Hash -cne $coveragePrerequisites[$binaryPath]) { throw '同轮真实夹具字节已改变' } }
    $index = Join-Path $coverageOutDir 'html\index.html'
    if (!(Test-Path -LiteralPath $index -PathType Leaf)) { throw 'HTML 报告缺少 index.html' }
    Write-AgfInfo ('行覆盖率 {0:N2}%；本轮报告：{1}' -f $coveragePercent,$index)
    if ($Open) { Start-Process $index | Out-Null }
    if ($testExit -ne 0 -or !$reportsOk -or $coveragePercent -lt $Threshold) { throw ('测试、报告或覆盖率门禁失败；阈值 '+$thresholdText+'%；完整日志：'+$coverageOutDir) }
    $coverageStatus = 'PASS'
    Write-AgfOk ('覆盖率达标：{0:N2}% >= {1}%' -f $coveragePercent,$thresholdText)
} catch {
    $coverageFailure=$_.Exception.Message
    Write-Host ('覆盖率失败：'+$coverageFailure) -ForegroundColor Red
} finally {
    try {
        if ($coverageDirectoriesOwned) {
            foreach ($ownedDirectory in @($coverageRuntime,$coverageOutDir)) {
                if (([IO.File]::ReadAllText((Join-Path $ownedDirectory '.task-owner'))).TrimEnd("`r","`n") -cne ('AIGuardFabric coverage.ps1 '+$coverageRun)) { throw '本轮 coverage 目录归属已改变，拒绝写入' }
            }
            $receipt=[ordered]@{schema='agf.coverage-run.v5';reportIntegrityPolicy=$ReportIntegrityPolicy;reportIntegrityAccepted=$coverageIntegrity.Accepted;zeroMismatchedData=$coverageIntegrity.StrongZeroMismatch;reportIntegrityMode=$coverageIntegrity.Mode;strongZeroMismatch=$coverageIntegrity.StrongZeroMismatch;freshMappingProof=$coverageIntegrity.Proof;verificationCommands=$coverageIntegrity.Commands;nativeContext=$coverageNativeContext;reportMode='CurrentWorkspaceArtifacts';currentWorkspaceArtifacts=$coverageArtifactProof;mergedProfiles=$coverageMerge;profileRunId=$coverageRun;reviewedLlvmTools=$llvm;cacheReuse=$coverageCacheReuse;reportResults=$coverageReportResults.ToArray();status=$coverageStatus;runId=$coverageRun;threshold=$Threshold;lines=$coverageLines;coveredLines=$coverageCovered;linePercent=$coveragePercent;runtime=$coverageRuntime;target=$coverageTarget;profileCount=$coverageProfiles.Count;profileHashes=$coverageProfiles;prerequisiteBuildHashes=$coveragePrerequisiteBuildHashes;prerequisiteHashes=$coveragePrerequisites;prerequisiteSnapshotPhase='workspace-compile';workspaceCompileExitCode=$compileExit;buildJobs=$BuildJobs;workspacePackages=$coveragePackages;workspaceTestExitCode=$testExit;historicalProfilesUsed=$false;workspaceAllTargets=$true;ignoredSqlClaimedPassed=$false;commands=$coverageCommands.ToArray();failure=$coverageFailure}
            Write-AgfTextFile -Path (Join-Path $coverageOutDir 'coverage-run.json') -Content ($receipt | ConvertTo-Json -Depth 8)
            $entry=[ordered]@{runId=$coverageRun;status=$coverageStatus;reportDirectory=$coverageOutDir;html=Join-Path $coverageOutDir 'html\index.html';lcov=Join-Path $coverageOutDir 'lcov.info';summary=Join-Path $coverageOutDir 'summary.json';receipt=Join-Path $coverageOutDir 'coverage-run.json'}
            Write-AgfTextFile -Path (Join-Path $root 'target\coverage\latest.json') -Content ($entry | ConvertTo-Json -Depth 4)
            Write-AgfInfo ('本轮报告入口：{0}' -f (Join-Path $root 'target\coverage\latest.json'))
        }
    } finally {
        try { Set-Location -LiteralPath $coveragePreviousLocation } finally {
            foreach ($entry in Get-ChildItem Env:) { if (!$coveragePreviousEnvironment.Contains($entry.Name)) { [Environment]::SetEnvironmentVariable($entry.Name,$null,'Process') } }
            foreach ($key in $coveragePreviousEnvironment.Keys) { [Environment]::SetEnvironmentVariable([string]$key,[string]$coveragePreviousEnvironment[$key],'Process') }
        }
    }
}
if ($coverageStatus -cne 'PASS') { exit 1 }
exit 0
