//! 由 `main.rs` 拆分：`metrics_text_always_renders_jdbc_snmp_usm_and_coldarchive_families` 函数（纯搬移，逻辑不变）。
use super::*;

/// `/metrics` 必须**无条件**包含三族协议专属计数器：
/// SQL（"JDBC"）拉取 / SNMP v3 USM / 冷归档。
///
/// 断言的是**纯函数** [`metrics_text`] 的输出，因此不依赖 HTTP 与任何外部服务；
/// `Stats::default()` + 空登记表 + 空分区列表等价于"三族都没配、零流量"——
/// 此时序列必须仍然存在（值为 0），否则"零流量 = 指标消失"就是观测空洞。
#[test]
pub(crate) fn metrics_text_always_renders_jdbc_snmp_usm_and_coldarchive_families() {
    let (status, headers, text) = metrics_text(
        &Stats::default(),
        &agf_ingest::receiver::WebhookCounters::default(),
        &MetricsRegistry::new(),
        &[],
    );
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[0].1, "text/plain; version=0.0.4");
    for family in [
        // ---- SQL（"JDBC"）拉取：拉取条数 / 丢弃 / 轮次 / 失败 / 游标推进 ----
        "agf_ingest_jdbc_rows_pulled_total",
        "agf_ingest_jdbc_rows_dropped_total",
        "agf_ingest_jdbc_batches_total",
        "agf_ingest_jdbc_errors_total",
        "agf_ingest_jdbc_cursor_advanced_total",
        // ---- SNMP v3 USM：6 类认证失败（usmStats）+ 通过 / 免认证通过 / Report ----
        "agf_ingest_snmp_usm_unsupported_sec_levels_total",
        "agf_ingest_snmp_usm_not_in_time_windows_total",
        "agf_ingest_snmp_usm_unknown_user_names_total",
        "agf_ingest_snmp_usm_unknown_engine_ids_total",
        "agf_ingest_snmp_usm_wrong_digests_total",
        "agf_ingest_snmp_usm_decryption_errors_total",
        "agf_ingest_snmp_usm_accepted_auth_total",
        "agf_ingest_snmp_usm_accepted_noauth_total",
        // ---- 冷归档：对象数 / 字节数 / 事件数 / 回落次数 ----
        "agf_ingest_coldarchive_objects_total",
        "agf_ingest_coldarchive_bytes_total",
        "agf_ingest_coldarchive_events_total",
        "agf_ingest_coldarchive_fallbacks_total",
    ] {
        assert!(text.contains(family), "/metrics 缺少 {family} 的 HELP/TYPE：\n{text}");
        // 序列行本身也要在（HELP/TYPE 行不算）：零流量时值为 0 也必须存在
        assert!(
            text.lines().any(|line| line.starts_with(family) && !line.trim_start().starts_with('#')),
            "/metrics 缺少 {family} 的样本行（零流量时也必须为 0）：\n{text}"
        );
    }
}
