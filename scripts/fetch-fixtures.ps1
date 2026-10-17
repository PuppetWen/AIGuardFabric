#Requires -Version 5.1
<#
.SYNOPSIS
    从**公开来源**抓取真实解析样本（默认干跑，必须显式 -Execute 才联网下载）。

.DESCRIPTION
    与 scripts/gen-fixtures.ps1 的分工：
      * gen-fixtures.ps1 生成**合成**样本（离线、可复现、synthetic=true）；
      * 本脚本抓取**公开真实**样本，落到 tests/fixtures/downloaded/，
        并登记来源 URL、HTTP 状态、抓取日期、sha256 到该目录的 SOURCES.md 与 manifest.json。

    安全默认值：**不带 -Execute 就是干跑**——只打印"计划抓取的 URL → 目标路径"，
    不发任何下载请求（-Verify 时会发 HEAD 探活，仍不下载正文）。

    失败处理：任何一个来源下载失败都会**明确报错**（红色 [FAIL] 行 + 非零退出码），
    绝不静默跳过、绝不用合成内容冒充真实来源。

    所有 URL 都是本仓库在 2026-02-21 实测 HTTP 200 的公开地址；若上游变更导致 404，
    脚本会如实报告失败并保留原有文件（不删不改）。

.PARAMETER Execute
    真正执行下载。缺省为干跑（等价于 -WhatIf）。

.PARAMETER WhatIf
    干跑：只打印计划。与 -Execute 互斥。

.PARAMETER Source
    只处理指定来源名（可多个）。缺省处理全部。用 -ListSources 查看可用名字。

.PARAMETER ListSources
    只列出内置来源清单（名字 / URL / 目标文件 / 用途），不做任何网络请求、不写盘。

.PARAMETER Verify
    干跑时额外对每个 URL 发 HEAD 请求探活并打印状态码（不下载正文）。

.PARAMETER Force
    即使目标文件已存在且内容相同也重新下载（默认：内容相同则跳过写入，保持幂等）。

.PARAMETER TimeoutSec
    单次请求超时（默认 30 秒）。

.EXAMPLE
    # 干跑：看计划抓什么（默认行为）
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\fetch-fixtures.ps1

.EXAMPLE
    # 干跑 + 探活，确认上游是否还在
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\fetch-fixtures.ps1 -Verify

.EXAMPLE
    # 真正下载
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\fetch-fixtures.ps1 -Execute

.NOTES
    退出码：0 = 成功（或干跑完成）；1 = 有来源下载失败；2 = 参数错误。
#>

[CmdletBinding()]
param(
    [switch]$Execute,
    [switch]$WhatIf,
    [string[]]$Source = @(),
    [switch]$ListSources,
    [switch]$Verify,
    [switch]$Force,
    [int]$TimeoutSec = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$env:AGF_ENV_QUIET = '1'
. "$PSScriptRoot\lib.ps1"

# 参数互斥：-Execute 与 -WhatIf 不能同用
if ($Execute -and $WhatIf) {
    Write-AgfError '-Execute 与 -WhatIf 互斥：要么干跑，要么真抓'
    exit 2
}

# ---------------------------------------------------------------------------
# 内置来源清单
#
# 选取标准：**与平台解析/接入直接相关**的公开原文（不含任何客户数据），
# 全部在 2026-02-21 由本脚本的 -Verify 模式实测 HTTP 200。
# 宁缺毋滥：抓不到的一律不写 URL（不用编造来源）。
# ---------------------------------------------------------------------------
$script:Sources = @(
    [ordered]@{
        name    = 'suricata-eve-json'
        url     = 'https://raw.githubusercontent.com/OISF/suricata/master/doc/userguide/output/eve/eve-json-format.rst'
        file    = 'suricata/eve-json-format.rst'
        purpose = 'Suricata eve.json 事件字段集与枚举原文（校验 agf-ingest 解析模板）'
        vendor  = 'Suricata / OISF'
    }
    [ordered]@{
        name    = 'zeek-conn-log'
        url     = 'https://raw.githubusercontent.com/zeek/zeek-docs/master/logs/conn.rst'
        file    = 'zeek/conn-log.rst'
        purpose = 'Zeek conn.log 字段集与 TSV 头格式原文'
        vendor  = 'Zeek'
    }
    [ordered]@{
        name    = 'fluentbit-parsers'
        url     = 'https://raw.githubusercontent.com/fluent/fluent-bit/master/conf/parsers.conf'
        file    = 'fluentbit/parsers.conf'
        purpose = 'Fluent Bit 官方解析器定义（regex/JSON 解析器的真实配置形态）'
        vendor  = 'Fluent Bit'
    }
    [ordered]@{
        name    = 'prometheus-scrape-config'
        url     = 'https://raw.githubusercontent.com/prometheus/prometheus/main/documentation/examples/prometheus.yml'
        file    = 'prometheus/prometheus.yml'
        purpose = 'Prometheus 官方抓取配置样例（指标门禁与自监控接入参考）'
        vendor  = 'Prometheus'
    }
    [ordered]@{
        name    = 'minio-config-doc'
        url     = 'https://raw.githubusercontent.com/minio/minio/master/docs/config/README.md'
        file    = 'minio/config-README.md'
        purpose = 'MinIO 配置项原文（证据包对象存储接入参考）'
        vendor  = 'MinIO'
    }
    [ordered]@{
        name    = 'timescaledb-readme'
        url     = 'https://raw.githubusercontent.com/timescale/timescaledb/main/README.md'
        file    = 'timescaledb/README.md'
        purpose = 'TimescaleDB 能力与版本说明（时序事件表设计参考）'
        vendor  = 'TimescaleDB'
    }
    [ordered]@{
        name    = 'nats-server-readme'
        url     = 'https://raw.githubusercontent.com/nats-io/nats-server/main/README.md'
        file    = 'nats/README.md'
        purpose = 'NATS JetStream 说明（事件总线接入参考）'
        vendor  = 'NATS'
    }
)

$outDir = Get-AgfPath 'tests\fixtures\downloaded'

Write-AgfBanner 'AIGuardFabric 公开样本抓取（fetch-fixtures）'
Write-Host ("  目标目录 : {0}" -f $outDir)
Write-Host ("  模式     : {0}" -f $(if ($Execute) { '执行（会联网下载）' } else { '干跑（只打印计划，不下载）' }))
Write-Host ("  来源数   : {0}" -f $script:Sources.Count)
Write-Host ''

# ---------------------------------------------------------------------------
# -ListSources：只列清单
# ---------------------------------------------------------------------------
if ($ListSources) {
    Write-AgfStep '内置公开来源清单'
    $i = 0
    foreach ($s in $script:Sources) {
        $i++
        Write-Host ("  [{0}] {1}" -f $i, $s.name) -ForegroundColor Cyan
        Write-Host ("      URL  : {0}" -f $s.url)
        Write-Host ("      目标 : tests/fixtures/downloaded/{0}" -f $s.file)
        Write-Host ("      用途 : {0}" -f $s.purpose)
    }
    Write-Host ''
    Write-AgfInfo '用 -Source <名字>[,<名字>] 只抓其中几个；真正下载需 -Execute。'
    exit 0
}

# 过滤
# 注意：powershell.exe -File 传参时 `-Source a,b` 会被当成**单个字符串** 'a,b' 绑定，
# 因此这里显式按逗号/分号再拆一次，保证两种调用方式都能用。
$Source = @($Source | ForEach-Object { $_ -split '[,;]' } | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 })
$selected = $script:Sources
if ($Source.Count -gt 0) {
    $known = @($script:Sources | ForEach-Object { $_.name })
    $unknown = @($Source | Where-Object { $known -notcontains $_ })
    if ($unknown.Count -gt 0) {
        Write-AgfError ("未知来源名: " + ($unknown -join ', '))
        Write-Host ("可用: " + ($known -join ', ')) -ForegroundColor Yellow
        exit 2
    }
    $selected = @($script:Sources | Where-Object { $Source -contains $_.name })
    Write-AgfInfo ("已按 -Source 过滤，保留 {0}/{1} 个来源" -f $selected.Count, $script:Sources.Count)
}

# ---------------------------------------------------------------------------
# 计划（干跑必打印；执行时也打印清单便于日志留痕）
# ---------------------------------------------------------------------------
Write-AgfStep ("抓取计划（{0} 个来源）" -f $selected.Count)
Write-Host ('  {0,-26} {1,-10} {2}' -f '来源', '动作', 'URL → 目标')
Write-Host ('  ' + ('-' * 118)) -ForegroundColor DarkGray
$plan = New-Object System.Collections.Generic.List[object]
foreach ($s in $selected) {
    $target = Join-Path $outDir ($s.file -replace '/', '\')
    $exists = Test-Path -LiteralPath $target
    $action = if (-not $Execute) { 'DRY-RUN' } elseif ($exists -and -not $Force) { 'FETCH/比对' } else { 'FETCH' }
    Write-Host ('  {0,-26} {1,-10} {2}' -f $s.name, $action, $s.url) -ForegroundColor Gray
    Write-Host ('  {0,-26} {1,-10} → {2}' -f '', '', ($target.Substring($AgfRoot.Length + 1))) -ForegroundColor DarkGray
    $plan.Add([pscustomobject]@{ source = $s; target = $target; existed = $exists })
}
Write-Host ''

# ---------------------------------------------------------------------------
# -Verify：探活（干跑友好；不发下载请求）
# ---------------------------------------------------------------------------
if ($Verify -and -not $Execute) {
    Write-AgfStep '上游探活（HEAD，不下载正文）'
    foreach ($p in $plan) {
        Write-Host ("  探测 {0} ... " -f $p.source.url) -NoNewline
        $code = Test-AgfHttpStatus -Uri $p.source.url -TimeoutSec $TimeoutSec
        if ($code -eq 200) {
            Write-Host "HTTP $code" -ForegroundColor Green
        }
        elseif ($code -eq 0) {
            Write-Host '连接失败/超时' -ForegroundColor Yellow
        }
        else {
            Write-Host "HTTP $code" -ForegroundColor Yellow
        }
    }
    Write-Host ''
}

# ---------------------------------------------------------------------------
# 干跑结束
# ---------------------------------------------------------------------------
if (-not $Execute) {
    Write-AgfInfo '干跑结束：未发出任何下载请求、未写盘。'
    Write-Host ''
    Write-Host '  真正抓取请执行：' -ForegroundColor Cyan
    Write-Host '    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\fetch-fixtures.ps1 -Execute'
    Write-Host ''
    Write-Host '  只抓指定来源：' -ForegroundColor Cyan
    Write-Host '    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\fetch-fixtures.ps1 -Execute -Source suricata-eve-json,zeek-conn-log'
    Write-Host ''
    Write-Host '  查看全部来源名：' -ForegroundColor Cyan
    Write-Host '    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\fetch-fixtures.ps1 -ListSources'
    exit 0
}

# ---------------------------------------------------------------------------
# 执行下载
# ---------------------------------------------------------------------------
Write-AgfStep '执行下载'
[void](New-AgfDirectory -Path $outDir)

$results = New-Object System.Collections.Generic.List[object]
$failures = New-Object System.Collections.Generic.List[string]

foreach ($p in $plan) {
    $s = $p.source
    $rel = $p.target.Substring($AgfRoot.Length + 1)
    $started = Get-Date
    $status = 0
    $errMsg = ''
    $sha = ''
    $bytes = 0
    $changed = $false
    try {
        $tmp = "$($p.target).download"
        # 先下到临时文件，成功后再原子替换（失败不会留下半个文件）
        Get-AgfWebRequest -Uri $s.url -OutFile $tmp -TimeoutSec $TimeoutSec | Out-Null
        $status = 200
        $newText = Get-Content -LiteralPath $tmp -Raw -Encoding UTF8
        $sha = (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash.ToLowerInvariant()
        $bytes = (Get-Item -LiteralPath $tmp).Length
        if ($p.existed) {
            $oldSha = (Get-FileHash -LiteralPath $p.target -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($oldSha -eq $sha -and -not $Force) {
                Remove-Item -LiteralPath $tmp -Force
                Write-Host ("  [ = ] {0,-40} 与上游一致，未改写（sha256:{1}）" -f $rel, $sha.Substring(0, 16)) -ForegroundColor DarkGray
            }
            else {
                Move-Item -LiteralPath $tmp -Destination $p.target -Force
                $changed = $true
                Write-Host ("  [ + ] {0,-40} 已更新 {1} 字节（sha256:{2}）" -f $rel, $bytes, $sha.Substring(0, 16)) -ForegroundColor Green
            }
        }
        else {
            Move-Item -LiteralPath $tmp -Destination $p.target -Force
            $changed = $true
            Write-Host ("  [ + ] {0,-40} 已抓取 {1} 字节（sha256:{2}）" -f $rel, $bytes, $sha.Substring(0, 16)) -ForegroundColor Green
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        Write-AgfFail ("{0} 抓取失败: {1}" -f $s.name, $errMsg)
        Write-Host ("         URL: {0}" -f $s.url) -ForegroundColor Red
        $failures.Add($s.name)
        # 清理临时文件
        $tmpPath = "$($p.target).download"
        if (Test-Path -LiteralPath $tmpPath) { Remove-Item -LiteralPath $tmpPath -Force -ErrorAction SilentlyContinue }
    }
    $elapsed = [math]::Round(((Get-Date) - $started).TotalSeconds, 2)
    $results.Add([pscustomobject]@{
            name     = $s.name
            vendor   = $s.vendor
            purpose  = $s.purpose
            url      = $s.url
            relPath  = $rel
            httpCode = $status
            sha256   = $sha
            bytes    = $bytes
            changed  = $changed
            elapsed  = $elapsed
            error    = $errMsg
        })
}

# ---------------------------------------------------------------------------
# 更新 SOURCES.md / manifest.json（只登记本次实际成功抓到的 URL）
# ---------------------------------------------------------------------------
Write-AgfStep '更新来源登记（SOURCES.md / manifest.json）'

$today = (Get-Date).ToString('yyyy-MM-dd')
$okResults = @($results | Where-Object { $_.httpCode -eq 200 })

$md = New-Object System.Collections.Generic.List[string]
$md.Add('# 公开样本来源登记（tests/fixtures/downloaded/SOURCES.md）')
$md.Add('')
$md.Add('> 本目录文件由 `scripts/fetch-fixtures.ps1 -Execute` 从**公开来源**抓取，逐字保存（不改写内容）。')
$md.Add('> 本文件与 `manifest.json` 由脚本自动维护：**只登记实际抓取成功的 URL**，失败项不写来源。')
$md.Add('')
$md.Add(('最后抓取时间：{0}（本机时间）' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')))
$md.Add('')
$md.Add('## 来源清单')
$md.Add('')
$md.Add('| 来源名 | 厂商 | URL | 本地文件 | HTTP | 字节 | sha256(前 16) | 抓取日期 | 用途 |')
$md.Add('|---|---|---|---|---|---|---|---|---|')
foreach ($r in $results) {
    $shortSha = if ($r.sha256) { $r.sha256.Substring(0, 16) } else { '—' }
    $code = if ($r.httpCode -eq 200) { '200' } else { '失败' }
    $md.Add(('| `{0}` | {1} | {2} | `{3}` | {4} | {5} | `{6}` | {7} | {8} |' -f `
                $r.name, $r.vendor, $r.url, $r.relPath, $code, $r.bytes, $shortSha, $today, $r.purpose))
}
$md.Add('')
if ($failures.Count -gt 0) {
    $md.Add('## 本次失败项（未登记来源，保留原有文件）')
    $md.Add('')
    $md.Add('| 来源名 | URL | 错误 |')
    $md.Add('|---|---|---|')
    foreach ($r in @($results | Where-Object { $_.httpCode -ne 200 })) {
        $md.Add(('| `{0}` | {1} | {2} |' -f $r.name, $r.url, ($r.error -replace '\|', '/')))
    }
    $md.Add('')
}
$md.Add('## 使用与替换说明')
$md.Add('')
$md.Add('* 这些文件是**上游公开原文**（多为文档 / 配置样例），用于校验解析模板的字段集与格式；')
$md.Add('  它们不是客户日志。解析器上线前必须用**客户真实日志**或者本仓库')
$md.Add('  `tests/fixtures/logs/`（含 real/synthetic 标注）与 `tests/fixtures/synthetic/`（纯合成）替换。')
$md.Add('* 上游文件可能随时变更：`sha256` 与抓取日期用于判断本地副本是否过期，')
$md.Add('  重新执行 `fetch-fixtures.ps1 -Execute` 即可刷新（内容一致则不改写）。')
$md.Add('* 任何来源抓取失败时脚本会明确报错并非零退出，**不会**用合成内容冒充真实来源。')
Write-AgfTextFile -Path (Join-Path $outDir 'SOURCES.md') -Content (($md -join "`n") + "`n")

$manifest = [ordered]@{
    version     = 1
    generator   = 'scripts/fetch-fixtures.ps1'
    fetchedAt   = (Get-Date).ToString('o')
    note        = '公开来源真实样本清单；只登记实际抓取成功的来源。失败项见 failures。'
    successCount = $okResults.Count
    failureCount = $failures.Count
    sources     = @($results | ForEach-Object {
            [ordered]@{
                name     = $_.name
                vendor   = $_.vendor
                url      = $_.url
                path     = $_.relPath
                httpCode = $_.httpCode
                sha256   = $_.sha256
                bytes    = $_.bytes
                fetchedAt = $today
                purpose  = $_.purpose
                error    = $_.error
            }
        })
}
Write-AgfJsonFile -Path (Join-Path $outDir 'manifest.json') -Object $manifest

# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------
Write-Host ''
Write-AgfBanner '抓取结果'
Write-Host ("  成功 {0} 个 / 失败 {1} 个" -f $okResults.Count, $failures.Count)
Write-Host ("  SOURCES.md : {0}" -f (Join-Path $outDir 'SOURCES.md'))
Write-Host ("  manifest   : {0}" -f (Join-Path $outDir 'manifest.json'))
Write-Host ''
foreach ($r in $okResults) {
    Write-Host ("  [ OK ] {0,-26} {1,8} 字节  {2}s" -f $r.name, $r.bytes, $r.elapsed) -ForegroundColor Green
}
foreach ($f in $failures) {
    Write-Host ("  [FAIL] {0}" -f $f) -ForegroundColor Red
}

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-AgfError ("有 {0} 个来源抓取失败：{1}" -f $failures.Count, ($failures -join ', '))
    Write-Host '  可能原因：上游文件被移动/重命名、网络不可达、代理拦截、TLS 握手失败。' -ForegroundColor Yellow
    Write-Host '  处置：更新本脚本 $script:Sources 里的 URL（先用 -Verify 确认 HTTP 200）后重试；' -ForegroundColor Yellow
    Write-Host '        既有本地文件未被破坏；该缺陷应登记到 docs/pending-verification.scripts.md。' -ForegroundColor Yellow
    exit 1
}

Write-AgfOk '全部来源抓取成功，来源与抓取日期已写入 SOURCES.md。'
exit 0
