//! 内置模板目录（第 A 段）：按原顺序承载 5 条模板，供 `builtin_templates()` 依序拼接。

use super::*;

/// 追加本段内置模板（顺序即目录顺序，调用方见 [`super::builtin_templates`]）。
///
/// `#[allow(clippy::too_many_lines)]`：与拆分前的整段目录同一理由——模板目录天然很长，
/// 这里只是把它按段落切开，不做任何语义改写。
#[allow(clippy::too_many_lines)]
pub(super) fn push_builtin_a(out: &mut Vec<ParserDefinition>) {
    // 1) 青藤云 蜂巢（Hive）主机安全 —— Grok
    let mut t = base(
        "qingteng-hive-syslog",
        "青藤云蜂巢主机安全",
        "青藤云",
        "蜂巢",
        ParserEngine::Grok,
        r#"%{TIMESTAMP_ISO8601:ts} \[%{WORD:level}\] host=%{IPORHOST:host_ip} hostname=%{HOSTNAME:hostname} user=%{DATA:user} rule_id=%{NOTSPACE:rule_id} risk=%{WORD:risk} action=%{WORD:action} msg="%{DATA:msg}" path=%{NOTSPACE:path}"#,
        &[IngestProtocol::Syslog, IngestProtocol::Webhook],
        "qingteng-hive-1.log",
        "青藤云蜂巢（Hive）主机入侵检测 syslog：WebShell 写入告警",
    );
    t.mapping = FieldMapping {
        map: fmap(&[
            ("ts", "event.time"),
            ("level", "log.level"),
            ("host_ip", "source.ip"),
            ("hostname", "host.name"),
            ("user", "user.name"),
            ("rule_id", "rule.id"),
            ("msg", "message"),
            ("path", "file.path"),
        ]),
        time_field: Some("ts".to_string()),
        time_format: Some("%Y-%m-%d %H:%M:%S".to_string()),
        severity_field: Some("risk".to_string()),
        severity_map: smap(&[
            ("critical", Severity::Critical),
            ("high", Severity::High),
            ("medium", Severity::Medium),
            ("low", Severity::Low),
        ]),
        category_map: cmap(&[("block", "intrusion"), ("alert", "intrusion"), ("log", "policy")]),
        action_field: Some("action".to_string()),
        defaults: BTreeMap::new(),
    };
    t.required_fields = vec!["rule_id".to_string()];
    out.push(t);

    // 2) 阿里云 WAF 3.0 —— JSONPath
    let mut t = base(
        "aliyun-waf-webhook",
        "阿里云 WAF 拦截日志",
        "阿里云",
        "Web应用防火墙",
        ParserEngine::JsonPath,
        "$.time\n$.host",
        &[IngestProtocol::Webhook, IngestProtocol::HttpPull, IngestProtocol::Beats],
        "aliyun-waf-1.log",
        "阿里云 WAF 3.0 日志服务推送（JSON）：Web 攻击拦截",
    );
    t.pattern = [
        "ts=$.time",
        "host=$.host",
        "src_ip=$.real_client_ip",
        "method=$.request_method",
        "uri=$.request_uri",
        "ua=$.http_user_agent",
        "rule_id=$.rule_id",
        "action=$.acl_action",
        "status=$.status",
        "region=$.region",
        "trace=$.trace_id",
    ]
    .join("\n");
    t.mapping = FieldMapping {
        map: fmap(&[
            ("ts", "event.time"),
            ("host", "host.name"),
            ("src_ip", "source.ip"),
            ("method", "http.request.method"),
            ("uri", "url.path"),
            ("ua", "user_agent.original"),
            ("rule_id", "rule.id"),
            ("status", "http.response.status_code"),
            ("region", "cloud.region"),
            ("trace", "trace.id"),
        ]),
        time_field: None,
        time_format: None,
        severity_field: None,
        severity_map: BTreeMap::new(),
        category_map: BTreeMap::new(),
        action_field: Some("action".to_string()),
        defaults: dmap(&[("event.severity", "medium"), ("event.category", "web")]),
    };
    t.required_fields = vec!["rule_id".to_string()];
    out.push(t);

    // 3) 阿里云 云安全中心 —— JSONPath
    let mut t = base(
        "aliyun-sas-alert",
        "阿里云云安全中心告警",
        "阿里云",
        "云安全中心",
        ParserEngine::JsonPath,
        "$.occurrenceTime",
        &[IngestProtocol::Webhook, IngestProtocol::HttpPull],
        "aliyun-sas-1.log",
        "阿里云云安全中心（Security Center）告警推送：SSH 暴力破解",
    );
    t.pattern = [
        "ts=$.occurrenceTime",
        "name=$.alertName",
        "level=$.level",
        "uuid=$.uuid",
        "instance=$.instanceName",
        "internet_ip=$.internetIp",
        "intranet_ip=$.intranetIp",
        "detail=$.detail",
        "alert_type=$.alertType",
        "region=$.region",
    ]
    .join("\n");
    t.mapping = FieldMapping {
        map: fmap(&[
            ("ts", "event.time"),
            ("name", "rule.name"),
            ("uuid", "event.reference"),
            ("instance", "host.name"),
            ("internet_ip", "destination.ip"),
            ("intranet_ip", "host.ip"),
            ("detail", "message"),
            ("alert_type", "event.category_raw"),
            ("region", "cloud.region"),
        ]),
        time_field: Some("ts".to_string()),
        time_format: Some("%Y-%m-%d %H:%M:%S".to_string()),
        severity_field: Some("level".to_string()),
        severity_map: smap(&[("serious", Severity::High), ("suspicious", Severity::Medium), ("remind", Severity::Low)]),
        category_map: cmap(&[("crack", "authentication"), ("malware", "malware"), ("vuln", "intrusion")]),
        action_field: None,
        defaults: dmap(&[("event.category", "intrusion")]),
    };
    t.required_fields = vec!["uuid".to_string()];
    out.push(t);

    // 4) 华为云 WAF —— JSONPath
    let mut t = base(
        "huawei-waf-webhook",
        "华为云 WAF 攻击日志",
        "华为云",
        "Web应用防火墙",
        ParserEngine::JsonPath,
        "$.time",
        &[IngestProtocol::Webhook, IngestProtocol::HttpPull],
        "huawei-waf-1.log",
        "华为云 WAF 攻击日志（JSON）：SQL 注入拦截",
    );
    t.pattern = [
        "ts=$.time",
        "host=$.host",
        "src_ip=$.client_ip",
        "uri=$.request_uri",
        "method=$.request_method",
        "attack=$.attack_type",
        "action=$.action",
        "rule_id=$.rule_id",
        "status=$.status",
        "sev=$.severity",
    ]
    .join("\n");
    t.mapping = FieldMapping {
        map: fmap(&[
            ("ts", "event.time"),
            ("host", "host.name"),
            ("src_ip", "source.ip"),
            ("uri", "url.path"),
            ("method", "http.request.method"),
            ("attack", "rule.name"),
            ("rule_id", "rule.id"),
            ("status", "http.response.status_code"),
        ]),
        time_field: None,
        time_format: None,
        severity_field: Some("sev".to_string()),
        severity_map: smap(&[
            ("critical", Severity::Critical),
            ("high", Severity::High),
            ("medium", Severity::Medium),
            ("low", Severity::Low),
        ]),
        category_map: BTreeMap::new(),
        action_field: Some("action".to_string()),
        defaults: dmap(&[("event.category", "web")]),
    };
    t.required_fields = vec!["rule_id".to_string()];
    out.push(t);

    // 5) 华为云 HSS 主机安全 —— JSONPath
    let mut t = base(
        "huawei-hss-alert",
        "华为云 HSS 主机安全告警",
        "华为云",
        "主机安全服务",
        ParserEngine::JsonPath,
        "$.occur_time",
        &[IngestProtocol::Webhook, IngestProtocol::HttpPull],
        "huawei-hss-1.log",
        "华为云 HSS 恶意文件检测告警（JSON）",
    );
    t.pattern = [
        "ts=$.occur_time",
        "event_type=$.event_type",
        "host=$.host_name",
        "host_ip=$.host_ip",
        "sev=$.severity",
        "malware=$.malware_name",
        "file_path=$.file_path",
        "action=$.action",
        "user=$.user",
        "region=$.region",
    ]
    .join("\n");
    t.mapping = FieldMapping {
        map: fmap(&[
            ("ts", "event.time"),
            ("event_type", "event.category_raw"),
            ("host", "host.name"),
            ("host_ip", "host.ip"),
            ("malware", "threat.software.name"),
            ("file_path", "file.path"),
            ("user", "user.name"),
            ("region", "cloud.region"),
        ]),
        time_field: None,
        time_format: None,
        severity_field: Some("sev".to_string()),
        severity_map: smap(&[
            ("critical", Severity::Critical),
            ("high", Severity::High),
            ("medium", Severity::Medium),
            ("low", Severity::Low),
        ]),
        category_map: cmap(&[
            ("malware", "malware"),
            ("virus", "malware"),
            ("file_change", "file"),
            ("process", "process"),
        ]),
        action_field: Some("action".to_string()),
        defaults: BTreeMap::new(),
    };
    t.required_fields = vec!["malware".to_string()];
    out.push(t);
}
