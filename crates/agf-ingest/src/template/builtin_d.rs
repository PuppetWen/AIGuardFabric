//! 内置模板目录（第 D 段）：按原顺序承载 2 条模板，供 `builtin_templates()` 依序拼接。

use super::*;

/// 追加本段内置模板（顺序即目录顺序，调用方见 [`super::builtin_templates`]）。
///
/// `#[allow(clippy::too_many_lines)]`：与拆分前的整段目录同一理由——模板目录天然很长，
/// 这里只是把它按段落切开，不做任何语义改写。
#[allow(clippy::too_many_lines)]
pub(super) fn push_builtin_d(out: &mut Vec<ParserDefinition>) {
    // 18) 通用 Syslog 兜底 —— Syslog 引擎（不解析 MSG 内部结构，只取头部字段）
    let mut t = base(
        "syslog-generic",
        "通用 Syslog（RFC3164/5424）",
        "generic",
        "syslog",
        ParserEngine::Syslog,
        "",
        &[IngestProtocol::Syslog, IngestProtocol::Webhook, IngestProtocol::Mqtt],
        "syslog-rfc3164-1.log",
        "通用 syslog 兜底模板：PRI/时间戳/主机名/APP-NAME/PROCID/SD 结构化数据 + 消息体",
    );
    t.mapping = FieldMapping::default();
    out.push(t);

    // 19) OpenTelemetry OTLP（JSON）—— JSONPath
    //
    // **一个模板覆盖 OTLP/HTTP 三信号**（logs / traces / metrics）：三者的归一化载荷形状同源
    // （同一接收器家族产出），字段名不冲突，用同一份映射表即可；拆成三个模板反而要各自带
    // 样本与 manifest 条目，且三者的"唯一性判据"（`service.name` 恒存在）完全相同。
    //
    // 载荷形状取自 **本仓库 OTLP 接收器自己的产物**
    // （`crate::otlp::OtlpLogRecord::to_payload` / `crate::otlp::OtlpSpanRecord::span_payload` /
    // `crate::otlp::OtlpMetricRecord::to_payload`，见 `crates/agf-ingest/src/otlp/` 模块文档），
    // 不凭想象编字段：
    // * logs：`{"@timestamp","message","severity_text","severity_number","trace_id","span_id",
    //   "event_name","resource":{...},"attributes":{...},"scope":{...}}`
    // * traces：`{"@timestamp","event.category":"trace","message","span_name","span_kind",
    //   "status_code","duration_nano","trace.id","span.id","parent.span.id",...}`
    // * metrics：`{"@timestamp","event.category":"metric","message","metric.name","metric.type",
    //   "metric.value","metric.count",...}`
    //
    // 注意 `resource` 内是 **OTLP 原文点号键**（`host.name` / `service.name`，接收器不猜测语义），
    // 因此主用 `$['resource']['host.name']`；同时兼容"已嵌套展开"的 `$.resource.host.name`
    // 形态（两种形态都试，命不中不报错，最后写入的非空值胜出）。
    let mut t = base(
        "otlp-json-log",
        "OpenTelemetry OTLP（logs / traces / metrics）",
        "OpenTelemetry",
        // `product` 与 `tests/fixtures/logs/manifest.json` 的条目**必须逐字一致**
        // （`manifest_covers_every_template_and_fixture_exists` 会断言），
        // 而 manifest 不在本任务的允许改动范围内 ⇒ 保留历史上的 "OTLP Logs"。
        // 覆盖面已扩到三信号这件事写在 `name` / `description` 里（二者不与 manifest 比对）。
        "OTLP Logs",
        ParserEngine::JsonPath,
        "$['@timestamp']",
        &[IngestProtocol::Otlp],
        "otlp-json-1.log",
        "OTLP/HTTP 三信号（logs / traces / metrics）的归一化载荷（JSON）：severity_text 归一化到平台等级，\
         resource/attributes 与 traces/metrics 字段保真；`trace.id`/`duration_nano`/`metric.name` 等按 OTLP 原文键落库",
    );
    t.pattern = [
        "timestamp=$['@timestamp']",
        "message=$.message",
        // 同一个 JSONPath 取两次是有意的：`severity_text` 走 `severity_field` 归一化到平台等级，
        // `log_level` 保真原标签（`apply_mapping` 里 `map` 的优先级高于 `severity_field`，
        // 一个字段只能落一个目标）。
        "severity_text=$.severity_text",
        "log_level=$.severity_text",
        "severity_number=$.severity_number",
        "trace_id=$.trace_id",
        "span_id=$.span_id",
        "event_name=$.event_name",
        // `service` / `host` **各写两行同名规格是有意的**：`parse_jsonpath` 逐行求值、
        // 命中才 `insert`，因此"先 resource 内层、后顶层"就是一条 **OR 回退链**——
        // 三种载荷形态都能取到 service：
        //   * 既有日志样本/夹具：只有 `resource['service.name']`（顶层没有）；
        //   * 接收器真实产物：顶层 `service.name` **恒有**，resource 可能为空；
        //   * traces/metrics：两者都有（顶层由 `service.name` → scope → 兜底推得）。
        "service=$['resource']['service.name']",
        "service=$['service.name']",
        "host=$['resource']['host.name']",
        "host=$['host.name']",
        "host_nested=$.resource.host.name",
        "service_nested=$.resource.service.name",
        "scope=$.scope",
        "attributes=$.attributes",
        // 三信号共有的信号标签（traces = "trace" / metrics = "metric"；logs 载荷没有该键）。
        // 平台 `EventCategory` 词表里**没有** trace/metric 成员，因此这里**不**映射到
        // `event.category`（那会被归一成 `other`，把信号信息压没），而是保真落 `extra`。
        "signal_category=$['event.category']",
        "signal_action=$['event.action']",
        // ---- traces 专属（`otlp::span_payload` 的键，点号键用中括号访问）----
        "trace_dot=$['trace.id']",
        "span_dot=$['span.id']",
        "parent_span_dot=$['parent.span.id']",
        "span_name=$['span_name']",
        "span_kind=$['span_kind']",
        "span_status=$['status_code']",
        "duration_nano=$['duration_nano']",
        // ---- metrics 专属（`otlp::OtlpMetricRecord::to_payload` 的键）----
        "metric_name=$['metric.name']",
        "metric_type=$['metric.type']",
        "metric_value=$['metric.value']",
        "metric_count=$['metric.count']",
        "metric_unit=$['metric.unit']",
        "metric_temporality=$['aggregation_temporality']",
    ]
    .join("\n");
    t.mapping = FieldMapping {
        map: fmap(&[
            ("timestamp", "event.time"),
            ("message", "message"),
            // OTLP 原文等级标签（TRACE/DEBUG/INFO/WARN/ERROR/FATAL）保真留在 `log.level`；
            // `Event::severity` 是平台五级词表，归一化走下面的 severity_field/severity_map。
            ("log_level", "log.level"),
            ("severity_number", "log.severity_number"),
            ("trace_id", "trace.id"),
            ("span_id", "trace.span_id"),
            ("event_name", "event.name"),
            ("host", "host.name"),
            ("host_nested", "host.name"),
            ("service", "service.name"),
            ("service_nested", "service.name"),
            // `resource` / `attributes` / `scope` 整体保真：按既有口径（未识别路径一律进
            // `Event::extra`，绝不丢弃）落 `otel.*`，不做厂商语义猜测。
            ("scope", "otel.scope"),
            ("attributes", "otel.attributes"),
            // 信号标签与 traces/metrics 字段：同样按"未识别路径 → extra，绝不丢弃"落库。
            // 目标名一律带 `otel.` / OTLP 原文键前缀，避免与平台 ECS 字段混淆。
            ("signal_category", "otel.event.category"),
            ("signal_action", "otel.event.action"),
            ("trace_dot", "trace.id"),
            ("span_dot", "trace.span_id"),
            ("parent_span_dot", "parent.span.id"),
            ("span_name", "span.name"),
            ("span_kind", "span.kind"),
            ("span_status", "span.status_code"),
            ("duration_nano", "duration_nano"),
            ("metric_name", "metric.name"),
            ("metric_type", "metric.type"),
            ("metric_value", "metric.value"),
            ("metric_count", "metric.count"),
            ("metric_unit", "metric.unit"),
            ("metric_temporality", "metric.aggregation_temporality"),
        ]),
        time_field: None,
        time_format: None,
        severity_field: Some("severity_text".to_string()),
        // OTLP `severity_text` 六值词表（TRACE/DEBUG/INFO/WARN/ERROR/FATAL）→ 平台五级。
        // **大小写归一在这里显式登记**：OTLP 规范不强制大写（exporter 常见 `ERROR`，
        // 但 `error`/`Error` 同样合法），因此三种常见写法都写进表里；表外取值仍由
        // `engine::infer_severity`（大小写不敏感）兜底，最后按平台五级归一 —— 不臆造等级。
        severity_map: smap(&[
            ("TRACE", Severity::Info),
            ("trace", Severity::Info),
            ("Trace", Severity::Info),
            ("DEBUG", Severity::Info),
            ("debug", Severity::Info),
            ("Debug", Severity::Info),
            ("INFO", Severity::Info),
            ("info", Severity::Info),
            ("Info", Severity::Info),
            ("WARN", Severity::Medium),
            ("warn", Severity::Medium),
            ("Warn", Severity::Medium),
            ("WARNING", Severity::Medium),
            ("warning", Severity::Medium),
            ("ERROR", Severity::High),
            ("error", Severity::High),
            ("Error", Severity::High),
            ("FATAL", Severity::Critical),
            ("fatal", Severity::Critical),
            ("Fatal", Severity::Critical),
            ("CRITICAL", Severity::Critical),
            ("critical", Severity::Critical),
            ("UNSPECIFIED", Severity::Info),
            ("unspecified", Severity::Info),
        ]),
        category_map: BTreeMap::new(),
        action_field: None,
        defaults: BTreeMap::new(),
    };
    // 唯一性判据：归一化载荷里 **`service` 恒可取得**（先取 `resource['service.name']`，
    // 顶层 `service.name` 作为回退——接收器由 `service.name` 资源属性 → scope 名 →
    // 兜底 `otlp-logs`/`otlp-traces`/`otlp-metrics` 必定写入二者之一），而其他 JSON 日志
    // 格式没有这个字段——这条 required_fields 同时是放宽趟的"误匹配安全网"。
    //
    // 为什么不继续用 `severity_text`：traces/metrics 载荷**没有**该字段（日志专属），
    // 用它会把两个新信号挡在模板外（实测：改前 `/v1/traces` 落库事件 `matched=false`）。
    t.required_fields = vec!["service".to_string()];
    out.push(t);
}
