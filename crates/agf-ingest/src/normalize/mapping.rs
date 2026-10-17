//! 归一化映射底座：日志源元信息 `SourceMeta`、解析器 id、类别/动作/方向/严重度取值转换与 JSON 取值小工具。

use super::*;

/// 解析器 id 的 UUIDv5 命名空间（模板 key → 稳定 id）。
pub const NS_PARSER: &str = "aiguardfabric.parser";

/// 由模板 key 计算稳定解析器 id（回放/审计可跨重启对齐）。
#[must_use]
pub fn parser_id_for(key: &str) -> Id {
    deterministic_id(NS_PARSER, key)
}

/// 归一化所需的日志源元数据（从 [`agf_core::source::LogSource`] 抽取，避免耦合）。
#[derive(Debug, Clone)]
pub struct SourceMeta {
    /// 租户。
    pub tenant_id: TenantId,
    /// 日志源 id。
    pub source_id: Id,
    /// 日志源名称。
    pub source_name: String,
    /// 厂商（模板优先，其次日志源配置）。
    pub vendor: String,
    /// 产品。
    pub product: String,
    /// 接入协议。
    pub protocol: IngestProtocol,
    /// 附加标签。
    pub tags: Vec<String>,
    /// 接入时间（用于时间缺失时的兜底与延迟统计）。
    pub ingested_at: Timestamp,
}

impl SourceMeta {
    /// 由日志源构造。
    #[must_use]
    pub fn from_source(source: &agf_core::source::LogSource) -> Self {
        Self {
            tenant_id: source.tenant_id,
            source_id: source.id,
            source_name: source.name.clone(),
            vendor: source.vendor.clone(),
            product: source.product.clone(),
            protocol: source.protocol,
            tags: source.tags.clone(),
            ingested_at: Timestamp::now(),
        }
    }
}

/// 事件类别文本 → [`EventCategory`]（含厂商常见别名）。
#[must_use]
pub fn event_category_from(value: &str) -> EventCategory {
    let v = value.trim().to_lowercase().replace(['_', ' '], "-");
    for candidate in EventCategory::all() {
        if candidate.as_str() == v {
            return candidate;
        }
    }
    match v.as_str() {
        "auth" | "authentication-failed" | "login" | "logon" | "account" | "iam" => EventCategory::Authentication,
        "web-attack" | "waf" | "http" | "xss" | "sqli" | "webshell" | "web攻击" => EventCategory::Web,
        "attack" | "exploit" | "c2" | "intrusion-detection" | "ips" | "ids" | "入侵检测" | "攻击" => {
            EventCategory::Intrusion
        }
        "virus" | "trojan" | "ransomware" | "malicious" | "病毒" | "木马" => EventCategory::Malware,
        "network-traffic" | "traffic" | "flow" | "dns" | "ssl" => EventCategory::Network,
        "process-start" | "process-stop" | "endpoint" | "edr" => EventCategory::Process,
        "file-change" | "file-access" => EventCategory::File,
        "audit" | "config" | "baseline" => EventCategory::Configuration,
        "cloud" | "cloud-audit" | "control-plane" => EventCategory::CloudControl,
        "policy-hit" | "rule-hit" => EventCategory::Policy,
        "ai" | "llm" | "prompt" | "mcp" | "tool-call" | "agent" => EventCategory::AiToolCall,
        _ => EventCategory::Other,
    }
}

/// 动作文本 → [`EventAction`]（含允许/拒绝/隔离等厂商同义词）。
#[must_use]
pub fn event_action_from(value: &str) -> EventAction {
    let v = value.trim().to_lowercase().replace(['_', ' '], "-");
    match v.as_str() {
        "allow" | "allowed" | "accept" | "accepted" | "permit" | "pass" | "放行" => EventAction::Allowed,
        "deny" | "denied" | "block" | "blocked" | "drop" | "dropped" | "reject" | "rejected" | "reset-both"
        | "quarantine" | "isolate" | "isolated" | "contain" | "contained" | "阻断" | "隔离" => EventAction::Denied,
        "create" | "created" | "add" | "added" | "new" => EventAction::Created,
        "update" | "updated" | "modify" | "modified" | "change" | "changed" => EventAction::Updated,
        "delete" | "deleted" | "remove" | "removed" => EventAction::Deleted,
        "login" | "logon" | "signin" | "sign-in" | "authenticate" => EventAction::Login,
        "logout" | "logoff" | "signout" | "sign-out" => EventAction::Logout,
        "read" | "get" | "access" | "open" => EventAction::Read,
        "write" | "put" | "upload" => EventAction::Write,
        "execute" | "exec" | "spawn" | "run" | "process-start" => EventAction::Execute,
        "connect" | "connection" | "established" | "start" => EventAction::Connect,
        "disconnect" | "closed" | "end" | "stop" => EventAction::Disconnect,
        "alert" | "alerted" | "notify" | "告警" => EventAction::Alert,
        "detect" | "detected" | "observe" | "observed" | "检测" => EventAction::Detect,
        "exfiltrate" | "exfil" | "leak" | "外传" => EventAction::Exfiltrate,
        "elevate" | "privilege-escalation" | "sudo" | "提权" => EventAction::Elevate,
        _ => EventAction::Unknown,
    }
}

/// 网络方向文本 → [`NetworkDirection`]。
#[must_use]
pub fn direction_from(value: &str) -> NetworkDirection {
    match value.trim().to_lowercase().as_str() {
        "inbound" | "in" | "ingress" => NetworkDirection::Inbound,
        "outbound" | "out" | "egress" => NetworkDirection::Outbound,
        "internal" | "lateral" | "east-west" => NetworkDirection::Internal,
        _ => NetworkDirection::Unknown,
    }
}

/// 依据严重等级文本解析；无法识别时为 [`Severity::Info`]。
#[must_use]
pub fn severity_from_text(value: &str) -> Severity {
    Severity::parse(value.trim()).unwrap_or(Severity::Info)
}

/// 无 `event.category` 时依据消息关键字推断（保守，默认 `Other`）。
///
/// 判定顺序很重要：攻击类（`Intrusion`）必须排在 Web 之前，否则
/// "SQL 注入攻击"这类文本会因为含 `sql` 而被误判为 Web。
/// 厂商/产品只在消息体没有任何线索时才作为**窄词典**兜底——
/// `WAF`/`AF` 这类泛词不能单独决定类别（否则一条无关日志也会被归到 Web）。
#[must_use]
pub fn infer_category(vendor: &str, product: &str, message: &str) -> EventCategory {
    let haystack = message.to_lowercase();
    let rules: &[(EventCategory, &[&str])] = &[
        (EventCategory::AiToolCall, &["mcp", "tool_call", "tool call", "大模型", "prompt"]),
        (EventCategory::Authentication, &["login", "logon", "登录", "认证", "password", "口令", "ssh", "brute"]),
        (EventCategory::Malware, &["malware", "virus", "trojan", "ransom", "webshell", "病毒", "木马", "恶意", "蠕虫"]),
        (
            EventCategory::Intrusion,
            &["attack", "exploit", "intrusion", "攻击", "入侵", "注入", "scan", "c2", "命令执行"],
        ),
        (EventCategory::Web, &["web", "http", "sql", "xss", "csrf", "url", "waf"]),
        (EventCategory::Network, &["firewall", "flow", "traffic", "conn", "netflow", "防火墙", "流量", "acl"]),
        (EventCategory::CloudControl, &["cloud", "oss", "s3", "control plane", "云平台"]),
        (EventCategory::Process, &["process", "command", "exec", "进程", "audit"]),
    ];
    for (category, keys) in rules {
        if keys.iter().any(|k| haystack.contains(k)) {
            return *category;
        }
    }

    // 兜底词典：只认语义明确的产品/厂商名，避免泛词误判
    let vendor_haystack = format!("{vendor} {product}").to_lowercase();
    let vendor_rules: &[(EventCategory, &[&str])] = &[
        (EventCategory::AiToolCall, &["大模型", "mcp"]),
        (EventCategory::Process, &["edr", "hids", "终端检测", "auditd"]),
        (EventCategory::Intrusion, &["ips", "ids", "天眼", "蜂巢", "falcon", "soc"]),
        (EventCategory::Network, &["防火墙", "firewall", "netflow"]),
    ];
    for (category, keys) in vendor_rules {
        if keys.iter().any(|k| vendor_haystack.contains(k)) {
            return *category;
        }
    }
    EventCategory::Other
}

/// 值 → 字符串（数字保留原样，便于端口/等级字段）。
#[must_use]
pub fn as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// 值 → u64。
#[must_use]
pub fn as_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// 值 → u16（端口等）。
#[must_use]
pub fn as_u16(value: &Value) -> Option<u16> {
    as_u64(value).and_then(|v| u16::try_from(v).ok())
}

/// 值 → 字符串数组（兼容单值与数组两种形态）。
#[must_use]
pub fn as_string_list(value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) => items.iter().filter_map(as_string).collect(),
        other => as_string(other).into_iter().collect(),
    }
}
