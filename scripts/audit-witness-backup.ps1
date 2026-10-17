#Requires -Version 5.1
# 审计见证是数据库之外的持久证据；这些函数只复制原字节，不签名或重建检查点。
$script:AgfWitnessOwner = "AIGuardFabric durable audit witnesses v1`n"
$script:AgfWitnessUtf8 = New-Object Text.UTF8Encoding($false, $true)

function Assert-AgfBackupPath([string]$Project, [string]$Path) {
    $projectPath = [IO.Path]::GetFullPath($Project).TrimEnd('\', '/')
    $absolute = [IO.Path]::GetFullPath($Path)
    if (!$absolute.StartsWith($projectPath + [IO.Path]::DirectorySeparatorChar, $(if ([Environment]::OSVersion.Platform -eq [PlatformID]::Unix) { [StringComparison]::Ordinal } else { [StringComparison]::OrdinalIgnoreCase }))) {
        throw '备份路径必须位于项目内。'
    }
    $current = $absolute
    while ($current) {
        $item = $null
        try { $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop }
        catch [Management.Automation.ItemNotFoundException] { $item = $null }
        if ($null -ne $item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw '拒绝链接或重解析路径。' }
        $parent = [IO.Directory]::GetParent($current)
        if ($null -eq $parent) { break }
        $current = $parent.FullName
    }
    return $absolute
}
function Get-AgfAuditDataRoot([string]$Project, [string]$Configured) {
    if ([string]::IsNullOrWhiteSpace($Configured)) { $Configured = 'data' }
    $path = if ([IO.Path]::IsPathRooted($Configured)) { $Configured } else { Join-Path $Project $Configured }
    $absolute = Assert-AgfBackupPath $Project $path
    $comparison = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Unix) { [StringComparison]::Ordinal } else { [StringComparison]::OrdinalIgnoreCase }
    foreach ($name in @('seed', 'uploads', 'fixtures')) {
        $ordinary = [IO.Path]::GetFullPath((Join-Path $Project ('data/' + $name))).TrimEnd('\', '/')
        if ($absolute.TrimEnd('\', '/').Equals($ordinary, $comparison) -or
            $absolute.StartsWith($ordinary + [IO.Path]::DirectorySeparatorChar, $comparison)) {
            throw '审计持久目录不能位于普通数据归档子树，避免-WithData覆盖实时见证。'
        }
    }
    $relative = $absolute.Substring([IO.Path]::GetFullPath($Project).TrimEnd('\', '/').Length + 1)
    if (@($relative -split '[\\/]' | Where-Object { $_ -in @('target', '.tmp', '.codex-tmp', 'tests', 'test-data', '.cargo', 'node_modules', 'dist') }).Count) {
        throw '审计持久目录不能位于编译、测试或缓存目录。'
    }
    return $absolute
}
function Get-AgfWitnessHash([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '') } finally { $sha.Dispose() }
}
function Set-AgfWitnessMode([string]$Path, [bool]$Directory) {
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Unix) {
        $type = [IO.File].Assembly.GetType('System.IO.UnixFileMode', $true)
        $mode = [Enum]::ToObject($type, $(if ($Directory) { 448 } else { 384 }))
        [IO.File]::SetUnixFileMode($Path, $mode)
    }
    # Windows 与生产 Rust 路径一致，继承运维方控制的 AGF_DATA_DIR ACL。
}
function Read-AgfWitnessBytes([string]$Project, [string]$Path, [int]$Limit) {
    $null = Assert-AgfBackupPath $Project $Path
    $item = Get-Item -LiteralPath $Path -Force
    if ($item -isnot [IO.FileInfo] -or $item.Length -gt $Limit) { throw '见证文件类型或大小越界。' }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $buffer = New-Object byte[] ($Limit + 1)
        $used = 0
        while ($used -lt $buffer.Length) {
            $read = $stream.Read($buffer, $used, $buffer.Length - $used)
            if ($read -eq 0) { break }
            $used += $read
        }
        if ($used -gt $Limit) { throw '读取期间见证超过大小限制。' }
        [Array]::Resize([ref]$buffer, $used)
        return ,$buffer
    } finally { $stream.Dispose() }
}
function Write-AgfBackupNew([string]$Path, [byte[]]$Bytes) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { Set-AgfWitnessMode $Path $false; $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}
function Get-AgfWitnessSnapshot([string]$Project, [string]$DataRoot) {
    $root = Assert-AgfBackupPath $Project (Join-Path $DataRoot 'audit-witnesses-v1')
    if (!(Test-Path -LiteralPath $root)) { return [pscustomobject]@{ State = 'ABSENT_UNINITIALIZED'; Root = $root; Files = @(); Fingerprint = 'ABSENT_UNINITIALIZED' } }
    if (!(Test-Path -LiteralPath $root -PathType Container)) { throw '见证根不是目录。' }
    $entries = @(Get-ChildItem -LiteralPath $root -Force | Select-Object -First 4097)
    if ($entries.Count -gt 4096) { throw '见证文件数超过4096，拒绝无界备份。' }
    $uuid = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    $files = @(foreach ($entry in @($entries | Sort-Object Name)) {
        $name = $entry.Name
        if ($name -ceq '.owner') { $limit = 256 }
        elseif ($name -cmatch ('^' + $uuid + '-(?:management|agent-' + $uuid + ')\.(json|lock)$')) {
            $limit = if ($Matches[1] -ceq 'lock') { 0 } else { 16384 }
        } else { throw '见证目录含未知或未完成文件；请核查并在写入静止时重试。' }
        $bytes = Read-AgfWitnessBytes $Project $entry.FullName $limit
        if ($name -ceq '.owner' -and $script:AgfWitnessUtf8.GetString($bytes) -cne $script:AgfWitnessOwner) { throw '见证归属标记不匹配。' }
        [ordered]@{ Name = $name; Length = $bytes.Length; Sha256 = Get-AgfWitnessHash $bytes }
    })
    if (@($files | Where-Object { $_.Name -ceq '.owner' }).Count -ne 1) { throw '缺少精确见证归属标记，不能接管目录。' }
    $fingerprint = Get-AgfWitnessHash ($script:AgfWitnessUtf8.GetBytes((ConvertTo-Json -InputObject $files -Depth 4 -Compress)))
    return [pscustomobject]@{ State = 'PRESENT'; Root = $root; Files = $files; Fingerprint = $fingerprint }
}
function Initialize-AgfAuditWitnessDirectory([string]$Project, [string]$DataRoot) {
    $root = Assert-AgfBackupPath $Project (Join-Path $DataRoot 'audit-witnesses-v1')
    if (Test-Path -LiteralPath $root) { $null = Get-AgfWitnessSnapshot $Project $DataRoot; return }
    $null = Assert-AgfBackupPath $Project $DataRoot
    $null = [IO.Directory]::CreateDirectory($DataRoot)
    $null = Assert-AgfBackupPath $Project $DataRoot
    $null = New-Item -ItemType Directory -Path $root
    Set-AgfWitnessMode $root $true
    Write-AgfBackupNew (Join-Path $root '.owner') ($script:AgfWitnessUtf8.GetBytes($script:AgfWitnessOwner))
    $null = Get-AgfWitnessSnapshot $Project $DataRoot
}
function Save-AgfWitnessBackup([string]$Project, [string]$DataRoot, [string]$Destination, $Before) {
    $current = Get-AgfWitnessSnapshot $Project $DataRoot
    if ($current.Fingerprint -cne $Before.Fingerprint) { throw '数据库导出期间见证改变，备份不完整；请静止写入后重试。' }
    $null = Assert-AgfBackupPath $Project $Destination
    if ($Before.State -ceq 'PRESENT') {
        $copy = Join-Path $Destination 'audit-witnesses-v1'
        if (Test-Path -LiteralPath $copy) { throw '保留已有备份见证目录。' }
        $null = New-Item -ItemType Directory -Path $copy
        Set-AgfWitnessMode $copy $true
        foreach ($row in $Before.Files) {
            $bytes = Read-AgfWitnessBytes $Project (Join-Path $Before.Root $row.Name) 16384
            if ($bytes.Length -ne $row.Length -or (Get-AgfWitnessHash $bytes) -cne $row.Sha256) { throw '复制期间见证改变。' }
            Write-AgfBackupNew (Join-Path $copy $row.Name) $bytes
        }
        if ((Get-AgfWitnessSnapshot $Project $Destination).Fingerprint -cne $Before.Fingerprint) { throw '备份见证原字节不匹配。' }
    }
    if ((Get-AgfWitnessSnapshot $Project $DataRoot).Fingerprint -cne $Before.Fingerprint) { throw '见证在备份中推进，请重试。' }
    $manifest = [ordered]@{ Version = 1; State = $Before.State; Files = @($Before.Files); Fingerprint = $Before.Fingerprint; CreatedUtc = [DateTime]::UtcNow.ToString('o'); CryptographicVerification = 'Runtime requires original trusted master key; archive SHA is transport integrity only' }
    Write-AgfBackupNew (Join-Path $Destination 'AUDIT-WITNESSES.json') ($script:AgfWitnessUtf8.GetBytes(($manifest | ConvertTo-Json -Depth 6)))
}
function Get-AgfWitnessRestorePlan([string]$Project, [string]$DataRoot, [string]$BackupRoot, [bool]$AllowUnanchoredLegacy) {
    $live = Get-AgfWitnessSnapshot $Project $DataRoot
    $manifestPath = Assert-AgfBackupPath $Project (Join-Path $BackupRoot 'AUDIT-WITNESSES.json')
    if (!(Test-Path -LiteralPath $manifestPath)) {
        if ($live.State -cne 'PRESENT' -and !$AllowUnanchoredLegacy) { throw '旧备份无见证且当前无见证；需显式-AllowUnanchoredLegacy，不能当作已锚定恢复。' }
        return [pscustomobject]@{ Live = $live; Archive = $null; LegacyUnanchored = $true }
    }
    $raw = Read-AgfWitnessBytes $Project $manifestPath 2097152
    $manifest = ConvertFrom-Json -InputObject ($script:AgfWitnessUtf8.GetString($raw))
    if ($manifest.Version -ne 1 -or $manifest.State -cnotin @('PRESENT', 'ABSENT_UNINITIALIZED') -or @($manifest.Files).Count -gt 4096) { throw '见证清单格式错误。' }
    $archive = Get-AgfWitnessSnapshot $Project $BackupRoot
    if ($archive.State -cne $manifest.State -or $archive.Fingerprint -cne $manifest.Fingerprint -or @($archive.Files).Count -ne @($manifest.Files).Count) { throw '备份见证完整集合或SHA不匹配。' }
    foreach ($row in $archive.Files) {
        $expected = @($manifest.Files | Where-Object { $_.Name -ceq $row.Name })
        if ($expected.Count -ne 1 -or $expected[0].Length -ne $row.Length -or $expected[0].Sha256 -cne $row.Sha256) { throw '备份见证文件清单不匹配。' }
    }
    if ($live.State -ceq 'PRESENT' -and $archive.State -ceq 'PRESENT') {
        foreach ($row in @($archive.Files | Where-Object { $_.Name.EndsWith('.json', [StringComparison]::Ordinal) })) {
            if (@($live.Files | Where-Object { $_.Name -ceq $row.Name }).Count -ne 1) {
                throw '现场见证缺少备份已有的审计链，拒绝恢复；不能以.owner当作链见证或自动补链。全新恢复应先恢复至尚未初始化的目标，再执行prepare验证。'
            }
        }
    }
    if ($archive.State -cne 'PRESENT' -and $live.State -cne 'PRESENT' -and !$AllowUnanchoredLegacy) { throw '该备份明确未初始化见证；需显式-AllowUnanchoredLegacy。' }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT -and $live.State -cne 'PRESENT' -and $archive.State -ceq 'PRESENT') {
        foreach ($row in $archive.Files) {
            $future = Join-Path $DataRoot ('.wr-' + ('0' * 32) + '/audit-witnesses-v1/' + $row.Name)
            if ($future.Length -ge 260) { throw '恢复暂存路径超过Windows限制；数据库恢复前请使用项目内较短持久数据目录。' }
        }
    }
    return [pscustomobject]@{ Live = $live; Archive = $archive; LegacyUnanchored = ($archive.State -cne 'PRESENT') }
}
function Complete-AgfWitnessRestore([string]$Project, [string]$DataRoot, $Plan) {
    $live = Get-AgfWitnessSnapshot $Project $DataRoot
    if ($live.Fingerprint -cne $Plan.Live.Fingerprint) { throw '恢复期间实时见证改变，保留原目录并停止。' }
    if ($live.State -ceq 'PRESENT') { return 'PRESERVED_CURRENT_WITNESS_NO_DOWNGRADE' }
    if ($null -eq $Plan.Archive -or $Plan.Archive.State -cne 'PRESENT') { return 'LEGACY_UNANCHORED_NO_WITNESS_CREATED' }
    $null = Assert-AgfBackupPath $Project $DataRoot
    $null = [IO.Directory]::CreateDirectory($DataRoot)
    $temporary = Join-Path $DataRoot ('.wr-' + [Guid]::NewGuid().ToString('N'))
    $null = Assert-AgfBackupPath $Project $temporary
    $null = New-Item -ItemType Directory -Path $temporary
    Set-AgfWitnessMode $temporary $true
    $owner = [Guid]::NewGuid().ToString('N')
    Write-AgfBackupNew (Join-Path $temporary '.restore-owner') ($script:AgfWitnessUtf8.GetBytes($owner))
    $copy = Join-Path $temporary 'audit-witnesses-v1'
    try {
        $null = New-Item -ItemType Directory -Path $copy
        Set-AgfWitnessMode $copy $true
        foreach ($row in $Plan.Archive.Files) {
            $bytes = Read-AgfWitnessBytes $Project (Join-Path $Plan.Archive.Root $row.Name) 16384
            if ((Get-AgfWitnessHash $bytes) -cne $row.Sha256 -or $bytes.Length -ne $row.Length) { throw '备份见证在恢复期间改变。' }
            Write-AgfBackupNew (Join-Path $copy $row.Name) $bytes
        }
        if ((Get-AgfWitnessSnapshot $Project $temporary).Fingerprint -cne $Plan.Archive.Fingerprint) { throw '暂存见证不匹配。' }
        $null = Assert-AgfBackupPath $Project $live.Root
        if (Test-Path -LiteralPath $live.Root) { throw '实时见证目录已出现，绝不覆盖。' }
        [IO.Directory]::Move($copy, $live.Root)
        if ((Get-AgfWitnessSnapshot $Project $DataRoot).Fingerprint -cne $Plan.Archive.Fingerprint) { throw '恢复后的见证不匹配。' }
        return 'RESTORED_ORIGINAL_WITNESS_BYTES_TO_ABSENT_TARGET'
    } finally {
        # 仅删除本轮自己的空暂存包装；失败的原字节留供核查，绝不递归吞掉见证。
        $null = Assert-AgfBackupPath $Project $temporary
        if ($script:AgfWitnessUtf8.GetString((Read-AgfWitnessBytes $Project (Join-Path $temporary '.restore-owner') 32)) -cne $owner) { throw '恢复暂存归属改变。' }
        $remaining = @(Get-ChildItem -LiteralPath $temporary -Force)
        if ($remaining.Count -eq 1 -and $remaining[0].Name -ceq '.restore-owner') {
            Remove-Item -LiteralPath (Join-Path $temporary '.restore-owner')
            [IO.Directory]::Delete($temporary, $false)
        }
    }
}
function Test-AgfLegacyDataArchive([string]$Project, [string]$Zip) {
    $null = Assert-AgfBackupPath $Project $Zip
    Add-Type -AssemblyName System.IO.Compression.FileSystem, System.IO.Compression
    $archive = [IO.Compression.ZipFile]::OpenRead($Zip)
    try {
        $layout = $null
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName.Replace('\', '/')
            if ($name -match '(^/|:|(^|/)\.\.?(/|$))' -or (($entry.ExternalAttributes -shr 16) -band 61440) -eq 40960) { throw '数据压缩包包含越界或链接条目。' }
            if ($name -match '(?i)(^|/)audit-witnesses-v1[ .]*(/|$)') { throw '普通数据压缩包不得包含任何审计见证路径段。' }
            $kind = if ($name -cmatch '^(seed|uploads|fixtures)(/|$)') { 'leaf' } elseif ($name -cmatch '^data/(seed|uploads|fixtures)(/|$)') { 'data' } else { throw '普通数据包只允许seed/uploads/fixtures，不能覆盖审计见证。' }
            if ($null -ne $layout -and $layout -cne $kind) { throw '普通数据包布局混用。' }
            $targetName = if ($kind -ceq 'leaf') { 'data/' + $name } else { $name }
            $null = Assert-AgfBackupPath $Project (Join-Path $Project $targetName)
            $layout = $kind
        }
        return $layout
    } finally { $archive.Dispose() }
}

function Assert-AgfOrdinaryDataTree([string]$Project, [string]$Root) {
    $absolute = Assert-AgfBackupPath $Project $Root
    if (!(Test-Path -LiteralPath $absolute -PathType Container)) { throw '普通数据归档源必须是目录。' }
    $pending = New-Object 'Collections.Generic.Stack[string]'
    $pending.Push($absolute)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        $null = Assert-AgfBackupPath $Project $directory
        # 只枚举当前层；先核查每个子项，再决定是否进入，不能递归跟随junction。
        foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
            $null = Assert-AgfBackupPath $Project $entry
            $item = Get-Item -LiteralPath $entry -Force -ErrorAction Stop
            if ($item -is [IO.DirectoryInfo]) { $pending.Push($item.FullName) }
            elseif ($item -isnot [IO.FileInfo]) { throw '普通数据归档源含不支持的条目。' }
            if ($item.Name.TrimEnd(' ', '.').Equals('audit-witnesses-v1', [StringComparison]::OrdinalIgnoreCase)) {
                throw '普通数据归档源不得包含审计见证目录。'
            }
        }
    }
}
