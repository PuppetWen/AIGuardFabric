#Requires -Version 5.1
<#
.SYNOPSIS
    AIGuardFabric 首次环境初始化：从 .env.example 生成 .env，注入强随机密钥，创建数据卷目录。

.DESCRIPTION
    本脚本是整个项目的"第 0 步"，其它脚本都假定 <root>\.env 已存在。

    做四件事：
      1. 若 <root>\.env 不存在，则由 <root>\.env.example 生成（**幂等**：已存在则不改，
         除非显式 -Force；-Force 会先把旧文件备份为 .env.bak-<时间戳>）；
      2. 生成/校验密钥类配置（AGF_JWT_SECRET / AGF_MASTER_KEY_BASE64 / AGF_PG_PASSWORD /
         AGF_S3_SECRET_KEY / AGF_GRAFANA_ADMIN_PASSWORD / AGF_BOOTSTRAP_ADMIN_PASSWORD）：
         * 仍是 CHANGE_ME / 空值的，替换为强随机值；
         * 已是真实值的，**保留不动**（避免覆盖用户凭据）；
      3. 把 .env 中的绝对路径（AGF_PROJECT_ROOT / AGF_DATA_DIR / AGF_TOOLS_DIR /
         AGF_VENDOR_DIR / AGF_MODELS_DIR / AGF_ENV_ROOT / AGF_REPLAY_DIR /
         AGF_REDTEAM_CASE_DIR / AGF_RULES_DIR）重写为当前项目根推导值——
         仓库可从任意路径克隆（铁律 4：不硬编码绝对路径）；
      4. 创建 data/ 下各数据卷子目录与 data/seed、data/backup。

    破坏性操作：-Force 覆盖 .env（会先备份）。默认 -WhatIf 只打印计划。

.PARAMETER Force
    即使 .env 已存在也重新生成（旧文件备份为 .env.bak-<yyyyMMddHHmmss>）。

.PARAMETER WhatIf
    只打印将要执行的动作，不写盘。

.PARAMETER ShowSecrets
    在末尾回显生成的密钥（默认只回显指纹前 8 位）。仅在你自己的终端里用。

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\init-env.ps1

.EXAMPLE
    # 先看计划，不落盘
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\init-env.ps1 -WhatIf

.NOTES
    退出码：0 = 成功（含"已存在，未修改"）；1 = 失败。
#>

[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$WhatIf,
    [switch]$ShowSecrets
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# 环境摘要是噪音，这里静默；dot-source 必须在 param() 之后（见 env.ps1 顶部注释）
$env:AGF_ENV_QUIET = '1'
. "$PSScriptRoot\env.ps1"

# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------
function New-AgfRandomSecret {
    <#
    .SYNOPSIS
        生成高强度随机口令（默认 48 字符，基数 62）。
    .NOTES
        用 RandomNumberGenerator 逐字节取模——模偏差在 256 % 62 下不可忽略，
        因此拒绝采样（>=248 的字节丢弃）保证均匀分布。
        字符集只含 [A-Za-z0-9]，避免 '/'、'+'、'=' 与 shell/URL/compose 插值冲突。
    #>
    param([int]$Length = 48)
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    $limit = 248   # 62 * 4 = 248，>248 的字节丢弃以保证均匀
    # 注意：Windows PowerShell 5.1（.NET Framework 4.0）下 RandomNumberGenerator 是抽象类，
    # New-Object 会报 "Cannot find an appropriate constructor"；必须走静态工厂 Create()。
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $sb = New-Object System.Text.StringBuilder
    $buf = New-Object byte[] 64
    try {
        while ($sb.Length -lt $Length) {
            $rng.GetBytes($buf)
            foreach ($b in $buf) {
                if ($b -ge $limit) { continue }
                [void]$sb.Append($alphabet[$b % $alphabet.Length])
                if ($sb.Length -ge $Length) { break }
            }
        }
    }
    finally {
        $rng.Dispose()
    }
    return $sb.ToString()
}

function New-AgfRandomBase64Key {
    <#
    .SYNOPSIS
        生成 base64 编码的 32 字节密钥（AES-256-GCM 主密钥用）。
    #>
    param([int]$Bytes = 32)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buf = New-Object byte[] $Bytes
    try { $rng.GetBytes($buf) } finally { $rng.Dispose() }
    return [Convert]::ToBase64String($buf)
}

function Write-AgfEnvLine {
    <#
    .SYNOPSIS
        按 .env 文本行改写键值：仅当该行是 `KEY=` 或 `KEY=<值>` 时替换，保留注释与空行。
    #>
    param(
        # AllowEmptyString：.env 里含空行，string[] 绑定时会因"空字符串"被拒
        [Parameter(Mandatory)][AllowEmptyString()][AllowEmptyCollection()][string[]]$Lines,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value
    )
    $pattern = '^\s*' + [regex]::Escape($Key) + '\s*='
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($line in $Lines) {
        if ($line -match $pattern) {
            $out.Add(("{0}={1}" -f $Key, $Value))
        }
        else {
            $out.Add($line)
        }
    }
    return $out.ToArray()
}

function Get-AgfEnvLineValue {
    <#
    .SYNOPSIS
        从 .env 文本行里取某个键的当前值（不存在返回空串）。
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][AllowEmptyCollection()][string[]]$Lines,
        [Parameter(Mandatory)][string]$Key
    )
    $pattern = '^\s*' + [regex]::Escape($Key) + '\s*=(.*)$'
    foreach ($line in $Lines) {
        if ($line -match $pattern) { return $Matches[1].Trim() }
    }
    return ''
}

# ---------------------------------------------------------------------------
# 0. 路径与前置检查
# ---------------------------------------------------------------------------
$envPath = Join-Path $AgfRoot '.env'
$examplePath = Join-Path $AgfRoot '.env.example'
$dataDir = Join-Path $AgfRoot 'data'

Write-AgfBanner 'AIGuardFabric 环境初始化（init-env）'
Write-Host ("  项目根   : {0}" -f $AgfRoot)
Write-Host ("  目标配置 : {0}" -f $envPath)
Write-Host ("  数据卷   : {0}" -f $dataDir)
Write-Host ("  模式     : {0}" -f $(if ($WhatIf) { 'WhatIf（只打印，不写盘）' } else { '执行' }))
Write-Host ''

if (-not (Test-Path -LiteralPath $examplePath)) {
    throw "缺少模板 $examplePath，无法初始化（该文件应随仓库提供）"
}

$envExists = Test-Path -LiteralPath $envPath

if ($envExists -and -not $Force) {
    Write-AgfStep '1/4 .env 已存在 —— 保持不动（幂等）'
    Write-Host "      未覆盖: $envPath" -ForegroundColor DarkGray
    Write-Host "      如需重新生成: -Force（旧文件会备份为 .env.bak-<时间戳>）" -ForegroundColor DarkGray
}
elseif ($envExists -and $Force) {
    Write-AgfStep '1/4 .env 已存在且指定 -Force —— 重新生成（先备份旧文件）'
    $stamp = (Get-Date).ToString('yyyyMMddHHmmss')
    $backup = Join-Path $AgfRoot (".env.bak-$stamp")
    if ($WhatIf) {
        Write-Host "      [WhatIf] 备份 $envPath -> $backup" -ForegroundColor DarkYellow
    }
    else {
        Copy-Item -LiteralPath $envPath -Destination $backup -Force
        Write-Host "      已备份旧配置: $backup" -ForegroundColor Green
    }
}
else {
    Write-AgfStep '1/4 .env 不存在 —— 由 .env.example 生成'
}

# ---------------------------------------------------------------------------
# 1. 读取模板并重写路径（即使不改 .env 也要算出"期望值"，用于校验）
# ---------------------------------------------------------------------------
$useExample = (-not $envExists) -or $Force
$lines = if ($useExample) { @(Get-Content -LiteralPath $examplePath -Encoding UTF8) } else { @() }

if ($useExample) {
    # 1.1 路径重写：全部从 $AgfRoot 推导，保证仓库可迁移
    $slash = $AgfRoot -replace '\\', '/'
    $pathKeys = [ordered]@{
        'AGF_PROJECT_ROOT'   = $slash
        'AGF_TOOLS_DIR'      = "$slash/tools"
        'AGF_DATA_DIR'       = "$slash/data"
        'AGF_VENDOR_DIR'     = "$slash/vendor"
        'AGF_MODELS_DIR'     = "$slash/models"
        'AGF_REPLAY_DIR'     = "$slash/tests/replay"
        'AGF_REDTEAM_CASE_DIR' = "$slash/redteam"
        'AGF_RULES_DIR'      = "$slash/rules"
    }
    foreach ($kv in $pathKeys.GetEnumerator()) {
        $lines = Write-AgfEnvLine -Lines $lines -Key $kv.Key -Value $kv.Value
    }
    # AGF_ENV_ROOT 保持模板值（只读工具链根，可能确实在项目外）
    Write-Host '      · 已按当前项目根重写 8 个路径项（AGF_PROJECT_ROOT/TOOLS/DATA/VENDOR/MODELS/REPLAY/REDTEAM/RULES）' -ForegroundColor DarkGray

    # 1.2 密钥生成/替换
    Write-AgfStep '2/4 生成/校验密钥'
    $secretSpecs = @(
        @{ key = 'AGF_JWT_SECRET'; generator = 'secret'; min = 32; note = 'JWT 签名密钥' },
        @{ key = 'AGF_PG_PASSWORD'; generator = 'secret'; min = 24; note = 'PostgreSQL 口令' },
        @{ key = 'AGF_S3_SECRET_KEY'; generator = 'secret'; min = 24; note = 'MinIO/S3 密钥' },
        @{ key = 'AGF_GRAFANA_ADMIN_PASSWORD'; generator = 'secret'; min = 24; note = 'Grafana 管理员口令' },
        @{ key = 'AGF_BOOTSTRAP_ADMIN_PASSWORD'; generator = 'secret'; min = 16; note = '引导管理员初始口令' },
        @{ key = 'AGF_MASTER_KEY_BASE64'; generator = 'base64'; min = 0; note = 'AES-256 主密钥' }
    )

    $generated = [ordered]@{}
    $preserved = [ordered]@{}

    foreach ($spec in $secretSpecs) {
        $current = Get-AgfEnvLineValue -Lines $lines -Key $spec.key
        $looksPlaceholder = [string]::IsNullOrEmpty($current) -or ($current -match 'CHANGE_ME')
        if ($looksPlaceholder) {
            $newValue = if ($spec.generator -eq 'base64') { New-AgfRandomBase64Key } else { New-AgfRandomSecret -Length 48 }
            $lines = Write-AgfEnvLine -Lines $lines -Key $spec.key -Value $newValue
            $generated[$spec.key] = $newValue
            Write-Host ("      + {0,-30} 已生成新值（{1}）" -f $spec.key, $spec.note) -ForegroundColor Green
        }
        else {
            $preserved[$spec.key] = $current
            Write-Host ("      = {0,-30} 保留既有真实值（{1}）" -f $spec.key, $spec.note) -ForegroundColor DarkGray
        }
    }

    # 1.3 DATABASE_URL 同步为新口令（sqlx-cli / agfctl migrate 用）
    if ($generated.Contains('AGF_PG_PASSWORD') -or $preserved.Contains('AGF_PG_PASSWORD')) {
        $pgUser = Get-AgfEnvLineValue -Lines $lines -Key 'AGF_PG_USER'
        if ([string]::IsNullOrEmpty($pgUser)) { $pgUser = 'agf' }
        $pgDb = Get-AgfEnvLineValue -Lines $lines -Key 'AGF_PG_DB'
        if ([string]::IsNullOrEmpty($pgDb)) { $pgDb = 'aiguardfabric' }
        $pgPort = Get-AgfEnvLineValue -Lines $lines -Key 'AGF_PG_PORT'
        if ([string]::IsNullOrEmpty($pgPort)) { $pgPort = '5432' }
        $pgHost = Get-AgfEnvLineValue -Lines $lines -Key 'AGF_PG_HOST'
        if ([string]::IsNullOrEmpty($pgHost)) { $pgHost = '127.0.0.1' }
        $pgPass = Get-AgfEnvLineValue -Lines $lines -Key 'AGF_PG_PASSWORD'
        $dbUrl = "postgres://{0}:{1}@{2}:{3}/{4}" -f $pgUser, $pgPass, $pgHost, $pgPort, $pgDb
        $lines = Write-AgfEnvLine -Lines $lines -Key 'DATABASE_URL' -Value $dbUrl
        Write-Host ('      · DATABASE_URL 已同步为新的连接串（口令随 AGF_PG_PASSWORD）') -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------------------
# 2. 落盘（先写 .tmp 再重命名，避免半个文件）
# ---------------------------------------------------------------------------
if ($useExample) {
    Write-AgfStep '3/4 写入 .env'
    if ($WhatIf) {
        Write-Host "      [WhatIf] 将写入 $envPath（$($lines.Count) 行）" -ForegroundColor DarkYellow
    }
    else {
        $tmp = "$envPath.tmp"
        # .env 用 UTF-8**无 BOM**（docker compose / dotenvy 对 BOM 敏感）
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllLines($tmp, [string[]]$lines, $utf8NoBom)
        Move-Item -LiteralPath $tmp -Destination $envPath -Force
        Write-Host "      已写入 $envPath（$($lines.Count) 行，UTF-8 无 BOM）" -ForegroundColor Green
    }
}
else {
    Write-AgfStep '3/4 跳过写入（.env 已存在且未指定 -Force）'
}

# ---------------------------------------------------------------------------
# 3. 数据卷目录
# ---------------------------------------------------------------------------
Write-AgfStep '4/4 创建数据卷目录'
$volumeDirs = @(
    'pg', 'redis', 'nats', 'minio', 'clickhouse', 'grafana',   # 容器 bind mount 目标
    'evidence', 'seed', 'backup', 'datasets', 'models'          # 平台自身数据
)
$created = 0
$notPermitted = @()
foreach ($v in $volumeDirs) {
    $p = Join-Path $dataDir $v
    if (Test-Path -LiteralPath $p) { continue }
    if ($WhatIf) {
        Write-Host "      [WhatIf] 新建 $p" -ForegroundColor DarkYellow
        $created++
        continue
    }
    try {
        New-Item -ItemType Directory -Force -Path $p | Out-Null
        $created++
    }
    catch {
        $notPermitted += $p
    }
}
if ($WhatIf) {
    Write-Host "      计划创建 $created 个目录（已有 $($volumeDirs.Count - $created) 个）" -ForegroundColor DarkYellow
}
else {
    Write-Host "      新建 $created 个目录，已存在 $($volumeDirs.Count - $created) 个" -ForegroundColor Green
    if ($notPermitted.Count -gt 0) {
        Write-AgfWarn ("以下目录创建失败（不影响脚本，但 Docker bind mount 会报错）: " + ($notPermitted -join ', '))
    }
}

# 数据卷占位文件：bind mount 需要宿主目录存在且可写
if (-not $WhatIf) {
    $keep = Join-Path $dataDir '.gitkeep'
    if (-not (Test-Path -LiteralPath $keep)) { New-Item -ItemType File -Force -Path $keep | Out-Null }
}

# ---------------------------------------------------------------------------
# 4. 校验与摘要
# ---------------------------------------------------------------------------
Write-Host ''
Write-AgfBanner '校验结果'

$finalLines = if ($WhatIf -and $useExample) { $lines } else { @(Get-Content -LiteralPath $envPath -Encoding UTF8) }
$checks = @(
    @{ key = 'AGF_JWT_SECRET'; kind = 'secret'; min = 32 },
    @{ key = 'AGF_PG_PASSWORD'; kind = 'secret'; min = 24 },
    @{ key = 'AGF_S3_SECRET_KEY'; kind = 'secret'; min = 24 },
    @{ key = 'AGF_MASTER_KEY_BASE64'; kind = 'base64'; min = 32 },
    @{ key = 'AGF_GRAFANA_ADMIN_PASSWORD'; kind = 'secret'; min = 24 }
)
$bad = 0
foreach ($c in $checks) {
    $v = Get-AgfEnvLineValue -Lines $finalLines -Key $c.key
    $ok = $false
    $detail = ''
    if ($c.kind -eq 'base64') {
        try {
            $bytes = [Convert]::FromBase64String($v)
            $ok = ($bytes.Length -eq 32)
            $detail = "$($bytes.Length) 字节"
        }
        catch { $detail = '非法 base64' }
    }
    else {
        $ok = ($v.Length -ge $c.min) -and ($v -notmatch 'CHANGE_ME')
        $detail = "$($v.Length) 字符"
    }
    $shown = if ($ShowSecrets) { $v } else { if ($v.Length -ge 8) { $v.Substring(0, 8) + '…' } else { '(空/过短)' } }
    if ($ok) {
        Write-Host ("  [ OK ] {0,-30} {1,-12} {2}" -f $c.key, $detail, $shown) -ForegroundColor Green
    }
    else {
        Write-Host ("  [FAIL] {0,-30} {1,-12} {2}" -f $c.key, $detail, $shown) -ForegroundColor Red
        $bad++
    }
}

# 引导管理员口令（供 demo/seed 或首登使用）
$adminUser = Get-AgfEnvLineValue -Lines $finalLines -Key 'AGF_BOOTSTRAP_ADMIN_USER'
$adminPass = Get-AgfEnvLineValue -Lines $finalLines -Key 'AGF_BOOTSTRAP_ADMIN_PASSWORD'
if ([string]::IsNullOrEmpty($adminUser)) { $adminUser = 'admin' }
$adminShown = if ($ShowSecrets) { $adminPass } else { if ($adminPass.Length -ge 4) { $adminPass.Substring(0, 4) + '…' } else { '(空)' } }
Write-Host ("  [INFO] 引导管理员                {0} / {1}（首登强制改密 AGF_FORCE_PASSWORD_CHANGE）" -f $adminUser, $adminShown) -ForegroundColor Cyan

Write-Host ''
Write-Host '下一步：' -ForegroundColor Cyan
Write-Host '  1) 启动依赖（Postgres/Redis/NATS/MinIO）  : powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\dev-up.ps1'
Write-Host '  2) 灌入演示数据                            : powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\seed.ps1'
Write-Host '  3) 全链路演示（离线 fixtures）             : powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\demo.ps1'
Write-Host '  4) 环境自检                                : powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\selfcheck.ps1'
Write-Host '  5) 全部门禁                                : powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\gate.ps1'
Write-Host '  6) 备份 / 覆盖率                           : scripts\backup.ps1 / scripts\coverage.ps1'
Write-Host ''
Write-Host '提示：.env 已被 .gitignore 排除，切勿提交；密钥只在本机保存。' -ForegroundColor DarkGray

if ($bad -gt 0) {
    Write-AgfError "有 $bad 项密钥校验失败，请检查上面的 [FAIL] 行"
    exit 1
}

Write-Host ''
Write-Host '初始化完成。' -ForegroundColor Green
exit 0
