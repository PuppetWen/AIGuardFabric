#Requires -Version 5.1
param(
    [switch]$Build,
    [switch]$NoBuild,
    [string]$ImageArchive,
    [switch]$Live,
    [switch]$Check,
    [switch]$InitOnly
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = [IO.Path]::GetFullPath($PSScriptRoot)
$envFile = Join-Path $root '.env.portable'
$composeFile = Join-Path $root 'deploy/portable/compose.yaml'
if ($Build -and ($NoBuild -or $ImageArchive)) { throw 'Choose -Build, -NoBuild or -ImageArchive.' }
if ($Check -and $InitOnly) { throw 'Choose -Check or -InitOnly.' }
if (!(Test-Path -LiteralPath $composeFile -PathType Leaf) -or !(Test-Path -LiteralPath (Join-Path $root 'Cargo.lock') -PathType Leaf)) { throw 'Use the complete source distribution.' }
function Assert-NoLink([string]$Path) {
    for ($parent = [IO.Path]::GetFullPath($Path); $parent; $parent = [IO.Path]::GetDirectoryName($parent)) {
        if ((Test-Path -LiteralPath $parent) -and ((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Links and reparse points are refused.' }
    }
}
Assert-NoLink $root
if (!(Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Install and start Docker Desktop with Linux containers first.' }
$os = & docker info --format '{{.OSType}}'
if ($LASTEXITCODE -ne 0 -or $os -cne 'linux') { throw 'A Linux-container Docker daemon is required.' }
$version = & docker compose version --short
if ($LASTEXITCODE -ne 0 -or $version -notmatch '^v?(\d+)\.(\d+)\.') { throw 'Cannot determine Docker Compose version.' }
if ([int]$Matches[1] -lt 2 -or ([int]$Matches[1] -eq 2 -and [int]$Matches[2] -lt 24)) { throw 'Docker Compose 2.24+ is required.' }
function New-RandomBytes([int]$Count) {
    $bytes = New-Object byte[] $Count
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return ,$bytes
}
function New-RandomHex { return ([BitConverter]::ToString((New-RandomBytes 32))).Replace('-', '').ToLowerInvariant() }
function New-AdminPassword {
    do { $random = New-RandomHex } while ($random -match 'abc123|123456|000000|111111')
    return 'Ag7!' + $random
}
Assert-NoLink $envFile
if (Test-Path -LiteralPath $envFile) {
    if (!(Test-Path -LiteralPath $envFile -PathType Leaf)) { throw '.env.portable must be a regular file.' }
} else {
    $mode = if ($Live) { '0' } else { '1' }
    $environment = 'dev'
    $lines = @(
        '# Generated locally. Do not publish or delete this file when upgrading.',
        ('AGF_PG_PASSWORD=' + (New-RandomHex)),
        ('AGF_S3_SECRET_KEY=' + (New-RandomHex)),
        ('AGF_JWT_SECRET=' + (New-RandomHex)),
        ('AGF_MASTER_KEY_BASE64=' + [Convert]::ToBase64String((New-RandomBytes 32))),
        ('AGF_BOOTSTRAP_ADMIN_PASSWORD=' + (New-AdminPassword)),
        ('AGF_MOCK_MODE=' + $mode),
        ('AGF_ENV=' + $environment), 'AGF_BOOTSTRAP_ADMIN_USER=agfadmin',
        'AGF_BIND_ADDRESS=127.0.0.1', 'AGF_WEB_PORT=8081', 'AGF_SERVER_PORT=8080',
        'AGF_INGEST_PORT=8090', 'AGF_SYSLOG_PORT=5514',
        'AGF_IMAGE_PREFIX=aiguardfabric', 'AGF_IMAGE_TAG=portable'
    )
    $stream = [IO.File]::Open($envFile, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $acl = New-Object Security.AccessControl.FileSecurity
        $acl.SetAccessRuleProtection($true, $false)
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl.SetOwner($identity)
        foreach ($sid in @($identity, (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')), (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))) {
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')))
        }
        Set-Acl -LiteralPath $envFile -AclObject $acl
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($lines -join "`n") + "`n")
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    $lines = $null; $bytes = $null
    Write-Host 'Created .env.portable with random secrets; admin password is stored there (not printed).'
}
$modeLines = @([IO.File]::ReadAllLines($envFile) | Where-Object { $_ -cmatch '^AGF_MOCK_MODE=[01]$' })
if ($modeLines.Count -ne 1) { throw '.env.portable must contain exactly one AGF_MOCK_MODE=0 or 1 line.' }
$mode = $modeLines[0].Substring($modeLines[0].Length - 1)
if ($Live -and $mode -cne '0') { throw 'Existing .env.portable is in MOCK mode. Set AGF_MOCK_MODE=0 explicitly; existing secrets were preserved.' }
$environmentLines = @([IO.File]::ReadAllLines($envFile) | Where-Object { $_ -cmatch '^AGF_ENV=dev$' })
$adminLines = @([IO.File]::ReadAllLines($envFile) | Where-Object { $_ -ceq 'AGF_BOOTSTRAP_ADMIN_USER=agfadmin' })
if ($adminLines.Count -ne 1 -or $environmentLines.Count -ne 1) { throw 'Existing .env.portable needs AGF_ENV and AGF_BOOTSTRAP_ADMIN_USER=agfadmin. Add fields explicitly; secrets were preserved.' }
$expectedEnvironment = 'AGF_ENV=dev'
if ($environmentLines[0] -cne $expectedEnvironment) { throw 'Portable local self-hosting requires AGF_ENV=dev even in live model mode. Production TLS deployment is separate; correct the field explicitly without replacing secrets.' }
foreach ($path in @((Join-Path $root 'data'), (Join-Path $root 'data/portable'))) {
    Assert-NoLink $path
    if (Test-Path -LiteralPath $path) { if (!(Test-Path -LiteralPath $path -PathType Container)) { throw 'Data path must be a directory.' } }
    else { [IO.Directory]::CreateDirectory($path) | Out-Null }
}
$dc = @('compose', '--project-directory', $root, '--env-file', $envFile, '-f', $composeFile)
function Invoke-Compose([string[]]$Arguments) {
    # The file is authoritative for its keys; a pre-existing terminal environment
    # must not silently override generated secrets or the displayed model mode.
    $saved = @{}
    foreach ($line in [IO.File]::ReadAllLines($envFile)) {
        if ($line -cmatch '^(AGF_[A-Z0-9_]+|POSTGRES_IMAGE|REDIS_IMAGE|NATS_IMAGE|MINIO_IMAGE|MINIO_MC_IMAGE)=') {
            $key = $Matches[1]
            if (!$saved.ContainsKey($key)) { $saved[$key] = [Environment]::GetEnvironmentVariable($key, 'Process') }
            [Environment]::SetEnvironmentVariable($key, $null, 'Process')
        }
    }
    try {
        & docker @dc @Arguments
        if ($LASTEXITCODE -ne 0) { throw 'Docker Compose failed; inspect service logs. Existing data and secrets are retained.' }
    } finally {
        foreach ($key in $saved.Keys) { [Environment]::SetEnvironmentVariable($key, $saved[$key], 'Process') }
    }
}
# Expanded compose configuration contains secrets, so only use --quiet.
Invoke-Compose -Arguments @('config', '--quiet')
if ($mode -ceq '1') { Write-Host 'MODEL MODE: MOCK. No real model, GPU or cloud service has been configured or verified.' }
else { Write-Host 'MODEL MODE: LIVE, but no model is installed. Configure an authorized OpenAI-compatible endpoint in the console.' }
Write-Host 'Container platform: linux/amd64. Apple Silicon emulation is not native arm64 or GPU-on-macOS support.'
if ($Check) { Write-Host 'Compose configuration is valid. No container was started.'; exit 0 }
if ($ImageArchive) {
    Assert-NoLink $ImageArchive
    if (!(Test-Path -LiteralPath $ImageArchive -PathType Leaf)) { throw 'Image archive must be an existing regular file.' }
    & docker image load --input ([IO.Path]::GetFullPath($ImageArchive))
    if ($LASTEXITCODE -ne 0) { throw 'Image archive load failed.' }
}
$init = @('run', '--rm', '--no-deps')
if ($ImageArchive) { $init += @('--pull', 'never') }
$init += 'init-data'
# Initialize before Compose creates the other services' bind directories.
Invoke-Compose -Arguments $init
if ($InitOnly) { Write-Host 'Data initialized. No application service was started.'; exit 0 }
if (!$NoBuild -and !$ImageArchive) {
    Write-Host 'Building source can take a long time and tens of GiB. A release image archive avoids compilation.'
    Invoke-Compose -Arguments @('build', 'agf-server', 'agf-ingest', 'agf-scheduler', 'agf-web')
}
$up = @('up', '-d', '--no-build', '--wait', '--wait-timeout', '300')
if ($ImageArchive) { $up += @('--pull', 'never') }
Invoke-Compose -Arguments $up
$portLine = @([IO.File]::ReadAllLines($envFile) | Where-Object { $_ -cmatch '^AGF_WEB_PORT=\d+$' })
if ($portLine.Count -ne 1) { throw 'Set one AGF_WEB_PORT value in .env.portable.' }
Write-Host ('Core stack is healthy. Console: http://localhost:' + $portLine[0].Split('=')[1])
Write-Host 'Login user: agfadmin. Read AGF_BOOTSTRAP_ADMIN_PASSWORD from .env.portable; the console requires a password change.'
Write-Host 'Rerunning preserves .env.portable and data/portable. Core health does not imply real-model functionality.'
