//! 内置模板目录（第 B 段）：按原顺序承载 7 条模板，供 `builtin_templates()` 依序拼接。

use super::*;

/// 追加本段内置模板（顺序即目录顺序，调用方见 [`super::builtin_templates`]）。
///
/// `#[allow(clippy::too_many_lines)]`：与拆分前的整段目录同一理由——模板目录天然很长，
/// 这里只是把它按段落切开，不做任何语义改写。
#[allow(clippy::too_many_lines)]
pub(super) fn push_builtin_b(out: &mut Vec<ParserDefinition>) {
    // 6) 腾讯云 云防火墙 —— JSONPath
    let mut t = base(
        "tencent-cfw-alert",
        "腾讯云云防火墙日志",
        "腾讯云",
        "云防火墙",
        ParserEngine::JsonPath,
        "$.log_time",
        &[IngestProtocol::Webhook, IngestProtocol::HttpPull, IngestProtocol::Kafka],
        "tencent-cfw-1.log",
        "腾讯云云防火墙 ACL 拒绝日志（JSON，Unix 秒时间戳）",
    );
    t.pattern = [
        "ts=$.log_time",
        "name=$.event_name",
        "src_ip=$.src_ip",
        "dst_ip=$.dst_ip",
        "dst_port=$.dst_port",
        "proto=$.protocol",
        "rule_id=$.rule_id",
        "action=$.action",
        "account=$.account_id",
        "region=$.region",
        "count=$.count",
        "topic=$.topic_id",
    ]
    .join("\n");
    t.mapping = FieldMapping {
        map: fmap(&[
            ("name", "rule.name"),
            ("src_ip", "source.ip"),
            ("dst_ip", "destination.ip"),
            ("dst_port", "destination.port"),
            ("proto", "network.transport"),
            ("rule_id", "rule.id"),
            ("account", "cloud.account.id"),
            ("region", "cloud.region"),
            ("count", "event.count"),
            ("topic", "event.reference"),
        ]),
        time_field: Some("ts".to_string()),
        time_format: Some("unix".to_string()),
        severity_field: None,
        severity_map: BTreeMap::new(),
        category_map: BTreeMap::new(),
        action_field: Some("action".to_string()),
        defaults: dmap(&[("event.severity", "low"), ("event.category", "network")]),
    };
    t.required_fields = vec!["rule_id".to_string()];
    out.push(t);

    // 7) 深信服 AF —— CEF
    let mut t = base(
        "sangfor-af-cef",
        "深信服下一代防火墙",
        "深信服",
        "AF",
        ParserEngine::Cef,
        "CEF:0",
        &[IngestProtocol::Syslog, IngestProtocol::Webhook, IngestProtocol::Beats],
        "sangfor-af-1.log",
        "深信服 AF IPS 模块 CEF 告警（syslog 信封包裹）",
    );
    t.mapping = FieldMapping {
        map: fmap(&[("request", "url.full"), ("cs1", "rule.name")]),
        time_field: None,
        time_format: None,
        severity_field: None,
        severity_map: BTreeMap::new(),
        category_map: cmap(&[("入侵检测", "intrusion"), ("Web攻击", "web"), ("病毒", "malware")]),
        action_field: None,
        defaults: BTreeMap::new(),
    };
    // required_fields 按**引擎输出的字段名**匹配：CEF/LEEF 引擎已把标准键改写为 ECS 路径
    t.required_fields = vec!["source.ip".to_string()];
    out.push(t);

    // 8) 奇安信 天眼 —— CEF
    let mut t = base(
        "qianxin-tianyan-cef",
        "奇安信天眼新一代威胁感知",
        "奇安信",
        "天眼",
        ParserEngine::Cef,
        "CEF:0",
        &[IngestProtocol::Syslog, IngestProtocol::Webhook],
        "qianxin-tianyan-1.log",
        "奇安信天眼 CEF 告警：命令注入",
    );
    t.mapping = FieldMapping {
        map: fmap(&[("request", "url.full"), ("cs1", "rule.name")]),
        time_field: None,
        time_format: None,
        severity_field: Some("cef.cs2".to_string()),
        severity_map: smap(&[
            ("critical", Severity::Critical),
            ("high", Severity::High),
            ("medium", Severity::Medium),
            ("low", Severity::Low),
        ]),
        category_map: cmap(&[("Web攻击", "web"), ("入侵检测", "intrusion"), ("恶意软件", "malware")]),
        action_field: None,
        defaults: BTreeMap::new(),
    };
    t.required_fields = vec!["user.name".to_string()];
    out.push(t);

    // 9) 绿盟 IPS —— LEEF 2.0
    let mut t = base(
        "nsfocus-ips-leef",
        "绿盟网络入侵防护系统",
        "绿盟",
        "IPS",
        ParserEngine::Leef,
        "LEEF:2.0",
        &[IngestProtocol::Syslog, IngestProtocol::Beats],
        "nsfocus-ips-1.log",
        "绿盟 IPS LEEF 2.0 告警（^ 分隔）：Log4j2 远程代码执行",
    );
    t.mapping = FieldMapping {
        map: fmap(&[("ruleId", "rule.name")]),
        time_field: Some("event.time_raw".to_string()),
        time_format: Some("%b %e %Y %H:%M:%S".to_string()),
        severity_field: None,
        severity_map: BTreeMap::new(),
        category_map: cmap(&[("Attack", "intrusion"), ("WebAttack", "web"), ("Virus", "malware")]),
        action_field: None,
        defaults: BTreeMap::new(),
    };
    t.required_fields = vec!["message".to_string()];
    out.push(t);

    // 10) 天融信 TopSAP —— LEEF 1.0（制表符）
    let mut t = base(
        "topsec-topsap-leef",
        "天融信安全审计系统",
        "天融信",
        "TopSAP",
        ParserEngine::Leef,
        "LEEF:1.0",
        &[IngestProtocol::Syslog],
        "topsec-topsap-1.log",
        "天融信 TopSAP 审计日志 LEEF 1.0（制表符分隔）：口令暴力破解",
    );
    t.mapping = FieldMapping {
        map: BTreeMap::new(),
        time_field: Some("event.time_raw".to_string()),
        time_format: Some("%Y-%m-%d %H:%M:%S".to_string()),
        severity_field: None,
        severity_map: BTreeMap::new(),
        category_map: cmap(&[("Authentication", "authentication"), ("Network", "network")]),
        action_field: None,
        defaults: BTreeMap::new(),
    };
    t.required_fields = vec!["user.name".to_string()];
    out.push(t);

    // 11) Fortinet FortiGate —— KV
    let mut t = base(
        "fortinet-fortigate-kv",
        "Fortinet FortiGate UTM",
        "Fortinet",
        "FortiGate",
        ParserEngine::Kv,
        "=",
        &[IngestProtocol::Syslog, IngestProtocol::Beats],
        "fortinet-fortigate-1.log",
        "FortiGate UTM/IPS syslog（key=value，含 quoted 值）",
    );
    t.mapping = FieldMapping {
        map: fmap(&[
            ("devname", "host.name"),
            ("devid", "host.id"),
            ("srcip", "source.ip"),
            ("srcport", "source.port"),
            ("dstip", "destination.ip"),
            ("dstport", "destination.port"),
            ("attack", "rule.name"),
            ("logid", "rule.id"),
            ("level", "log.level"),
            ("subtype", "event.category_raw"),
            ("proto", "network.iana_number"),
            ("msg", "message"),
        ]),
        time_field: Some("eventtime".to_string()),
        time_format: Some("unix".to_string()),
        severity_field: Some("severity".to_string()),
        severity_map: smap(&[
            ("critical", Severity::Critical),
            ("high", Severity::High),
            ("medium", Severity::Medium),
            ("low", Severity::Low),
        ]),
        category_map: cmap(&[
            ("ips", "intrusion"),
            ("virus", "malware"),
            ("webfilter", "web"),
            ("app-ctrl", "network"),
            ("vpn", "authentication"),
        ]),
        action_field: Some("action".to_string()),
        defaults: BTreeMap::new(),
    };
    t.required_fields = vec!["devname".to_string()];
    out.push(t);

    // 12) Palo Alto PAN-OS —— CSV
    let mut t = base(
        "paloalto-panos-csv",
        "Palo Alto PAN-OS 流量日志",
        "Palo Alto",
        "PAN-OS",
        ParserEngine::Csv,
        "start,gen_time,serial,type,subtype,config_ver,dev_time,src_ip,dst_ip,rule,rule_uuid,vsys,from_zone,to_zone,ingress_if,egress_if,session_id,src_port,dst_port,protocol,action,bytes_total,bytes_out,bytes_in,packets,app",
        &[IngestProtocol::Syslog, IngestProtocol::Beats],
        "paloalto-panos-1.log",
        "PAN-OS TRAFFIC 日志（syslog 头 + CSV 列）",
    );
    t.mapping = FieldMapping {
        map: fmap(&[
            ("dev_time", "event.time"),
            ("serial", "observer.serial_number"),
            ("type", "event.category_raw"),
            ("src_ip", "source.ip"),
            ("dst_ip", "destination.ip"),
            ("src_port", "source.port"),
            ("dst_port", "destination.port"),
            ("protocol", "network.transport"),
            ("rule", "rule.name"),
            ("app", "network.application"),
            ("bytes_out", "source.bytes"),
            ("bytes_in", "destination.bytes"),
        ]),
        time_field: Some("dev_time".to_string()),
        time_format: Some("%Y/%m/%d %H:%M:%S".to_string()),
        severity_field: None,
        severity_map: BTreeMap::new(),
        category_map: cmap(&[
            ("TRAFFIC", "network"),
            ("THREAT", "intrusion"),
            ("URL", "web"),
            ("SYSTEM", "configuration"),
        ]),
        action_field: Some("action".to_string()),
        defaults: dmap(&[("event.severity", "info")]),
    };
    t.required_fields = vec!["serial".to_string()];
    out.push(t);
}
