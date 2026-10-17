//! 内置模板目录（第 C 段）：按原顺序承载 5 条模板，供 `builtin_templates()` 依序拼接。

use super::*;

/// 追加本段内置模板（顺序即目录顺序，调用方见 [`super::builtin_templates`]）。
///
/// `#[allow(clippy::too_many_lines)]`：与拆分前的整段目录同一理由——模板目录天然很长，
/// 这里只是把它按段落切开，不做任何语义改写。
#[allow(clippy::too_many_lines)]
pub(super) fn push_builtin_c(out: &mut Vec<ParserDefinition>) {
    // 13) CrowdStrike Falcon —— JSONPath
    let mut t = base(
        "crowdstrike-falcon-webhook",
        "CrowdStrike Falcon 检测事件",
        "CrowdStrike",
        "Falcon",
        ParserEngine::JsonPath,
        "$.metadata.eventType",
        &[IngestProtocol::Webhook, IngestProtocol::HttpPull],
        "crowdstrike-falcon-1.log",
        "Falcon DetectionSummaryEvent（Webhook JSON）：可疑 PowerShell 执行",
    );
    t.pattern = [
        "ts=$.metadata.eventCreationTime",
        "detect_id=$.event.DetectId",
        "detect_name=$.event.DetectName",
        "sev=$.event.SeverityName",
        "host=$.event.ComputerName",
        "host_ip=$.event.LocalIP",
        "user=$.event.UserName",
        "pid=$.event.ProcessId",
        "ppid=$.event.ParentProcessId",
        "cmdline=$.event.CommandLine",
        "file_name=$.event.FileName",
        "file_path=$.event.FilePath",
        "tactic=$.event.Tactic",
        "technique=$.event.Technique",
        "event_type=$.metadata.eventType",
    ]
    .join("\n");
    t.mapping = FieldMapping {
        map: fmap(&[
            ("detect_id", "rule.id"),
            ("detect_name", "rule.name"),
            ("host", "host.name"),
            ("host_ip", "host.ip"),
            ("user", "user.name"),
            ("pid", "process.pid"),
            ("ppid", "process.parent.pid"),
            ("cmdline", "process.command_line"),
            ("file_name", "file.name"),
            ("file_path", "file.path"),
            ("tactic", "threat.tactic.name"),
            ("technique", "threat.technique.name"),
            ("event_type", "event.category_raw"),
        ]),
        time_field: Some("ts".to_string()),
        time_format: Some("unix_millis".to_string()),
        severity_field: Some("sev".to_string()),
        severity_map: smap(&[
            ("Critical", Severity::Critical),
            ("High", Severity::High),
            ("Medium", Severity::Medium),
            ("Low", Severity::Low),
            ("Informational", Severity::Info),
        ]),
        category_map: BTreeMap::new(),
        action_field: None,
        defaults: dmap(&[("event.category", "intrusion")]),
    };
    t.required_fields = vec!["detect_name".to_string()];
    out.push(t);

    // 14) Wazuh —— JSONPath
    let mut t = base(
        "wazuh-alert-json",
        "Wazuh 告警",
        "Wazuh",
        "Wazuh Manager",
        ParserEngine::JsonPath,
        "$.rule.level",
        &[IngestProtocol::Webhook, IngestProtocol::File, IngestProtocol::Beats, IngestProtocol::HttpPull],
        "wazuh-alert-1.log",
        "Wazuh alerts.json 告警：SSH 暴力破解（rule.level 0-15 分级）",
    );
    t.pattern = [
        "ts=$.timestamp",
        "level=$.rule.level",
        "rule_desc=$.rule.description",
        "rule_id=$.rule.id",
        "agent_name=$.agent.name",
        "agent_ip=$.agent.ip",
        "src_ip=$.data.srcip",
        "src_user=$.data.srcuser",
        "proto=$.data.protocol",
        "location=$.location",
        "full_log=$.full_log",
    ]
    .join("\n");
    t.mapping = FieldMapping {
        map: fmap(&[
            ("ts", "event.time"),
            ("rule_desc", "rule.description"),
            ("rule_id", "rule.id"),
            ("agent_name", "host.name"),
            ("agent_ip", "host.ip"),
            ("src_ip", "source.ip"),
            ("src_user", "user.name"),
            ("proto", "network.transport"),
            ("location", "log.file.path"),
            ("full_log", "message"),
        ]),
        time_field: None,
        time_format: None,
        severity_field: Some("level".to_string()),
        severity_map: wazuh_severity_map(),
        category_map: cmap(&[("5710", "authentication"), ("5712", "authentication"), ("550", "file")]),
        action_field: None,
        defaults: dmap(&[("event.category", "authentication")]),
    };
    t.required_fields = vec!["rule_id".to_string()];
    out.push(t);

    // 15) Suricata —— JSONPath
    let mut t = base(
        "suricata-eve-json",
        "Suricata IDS 告警",
        "Suricata",
        "eve.json",
        ParserEngine::JsonPath,
        "$.event_type",
        &[IngestProtocol::File, IngestProtocol::Beats, IngestProtocol::Webhook],
        "suricata-eve-1.log",
        "Suricata eve.json alert 事件（JSON Lines）",
    );
    t.pattern = [
        "ts=$.timestamp",
        "kind=$.event_type",
        "src_ip=$.src_ip",
        "src_port=$.src_port",
        "dest_ip=$.dest_ip",
        "dest_port=$.dest_port",
        "proto=$.proto",
        "sig_id=$.alert.signature_id",
        "signature=$.alert.signature",
        "sig_category=$.alert.category",
        "sev=$.alert.severity",
        "action=$.alert.action",
        "host=$.host",
        "http_url=$.http.url",
        "http_method=$.http.http_method",
        "http_status=$.http.status",
    ]
    .join("\n");
    t.mapping = FieldMapping {
        map: fmap(&[
            ("ts", "event.time"),
            ("kind", "event.type"),
            ("src_ip", "source.ip"),
            ("src_port", "source.port"),
            ("dest_ip", "destination.ip"),
            ("dest_port", "destination.port"),
            ("proto", "network.transport"),
            ("sig_id", "rule.id"),
            ("signature", "rule.name"),
            ("sig_category", "rule.category"),
            ("host", "host.name"),
            ("http_url", "url.path"),
            ("http_method", "http.request.method"),
            ("http_status", "http.response.status_code"),
        ]),
        time_field: None,
        time_format: None,
        severity_field: Some("sev".to_string()),
        severity_map: smap(&[
            ("1", Severity::High),
            ("2", Severity::Medium),
            ("3", Severity::Low),
            ("4", Severity::Info),
        ]),
        category_map: BTreeMap::new(),
        action_field: Some("action".to_string()),
        defaults: dmap(&[("event.category", "intrusion")]),
    };
    t.required_fields = vec!["signature".to_string()];
    out.push(t);

    // 16) Zeek —— CSV/TSV
    let mut t = base(
        "zeek-conn-tsv",
        "Zeek conn.log 连接日志",
        "Zeek",
        "conn.log",
        ParserEngine::Csv,
        "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto,service,duration,orig_bytes,resp_bytes,conn_state,local_orig,local_resp,missed_bytes,history,orig_pkts,orig_ip_bytes,resp_pkts,resp_ip_bytes",
        &[IngestProtocol::File, IngestProtocol::Beats],
        "zeek-conn-1.log",
        "Zeek conn.log（TSV，字段顺序取自官方 #fields 头）",
    );
    t.mapping = FieldMapping {
        map: fmap(&[
            ("ts", "event.time"),
            ("uid", "event.reference"),
            ("id.orig_h", "source.ip"),
            ("id.orig_p", "source.port"),
            ("id.resp_h", "destination.ip"),
            ("id.resp_p", "destination.port"),
            ("proto", "network.transport"),
            ("service", "network.application"),
            ("duration", "event.duration"),
            ("orig_bytes", "source.bytes"),
            ("resp_bytes", "destination.bytes"),
            ("conn_state", "network.connection_state"),
            ("history", "network.history"),
            ("orig_pkts", "source.packets"),
            ("resp_pkts", "destination.packets"),
        ]),
        time_field: Some("ts".to_string()),
        time_format: Some("unix".to_string()),
        severity_field: None,
        severity_map: BTreeMap::new(),
        category_map: BTreeMap::new(),
        action_field: None,
        defaults: dmap(&[("event.severity", "info"), ("event.category", "network")]),
    };
    t.required_fields = vec!["uid".to_string()];
    out.push(t);

    // 17) Linux auditd EXECVE —— Regex（自定义 Rust 解析插件之外的"轻量扩展"路径）
    let mut t = base(
        "linux-auditd-execve",
        "Linux auditd 命令执行审计",
        "Linux",
        "auditd",
        ParserEngine::Regex,
        r#"type=EXECVE msg=audit\((?P<audit_ts>[\d.]+):(?P<serial>\d+)\): argc=\d+ a0="(?P<argv0>[^"]*)" a1="(?P<argv1>[^"]*)" a2="(?P<argv2>[^"]*)" uid=(?P<uid>\d+) auid=(?P<auid>\d+) ses=(?P<ses>\d+) comm="(?P<comm>[^"]*)" exe="(?P<exe>[^"]*)" addr=(?P<addr>[\d.]+)"#,
        &[IngestProtocol::Syslog, IngestProtocol::File],
        "linux-auditd-execve-1.log",
        "auditd EXECVE 记录（syslog 信封 + 正则命名组）：可疑下载执行",
    );
    t.mapping = FieldMapping {
        map: fmap(&[
            ("audit_ts", "event.time"),
            ("serial", "event.sequence"),
            ("uid", "user.id"),
            ("auid", "user.audit_id"),
            ("comm", "process.name"),
            ("exe", "process.executable"),
            ("argv1", "process.args"),
            ("argv2", "process.command_line"),
            ("addr", "source.ip"),
        ]),
        time_field: Some("audit_ts".to_string()),
        time_format: Some("unix".to_string()),
        severity_field: None,
        severity_map: BTreeMap::new(),
        category_map: BTreeMap::new(),
        action_field: None,
        defaults: dmap(&[("event.severity", "high"), ("event.category", "process"), ("event.action", "execute")]),
    };
    t.required_fields = vec!["comm".to_string()];
    out.push(t);
}
