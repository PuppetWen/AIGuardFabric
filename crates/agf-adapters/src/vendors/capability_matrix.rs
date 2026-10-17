//! 能力矩阵：12 个内置适配器 × 4 条语义（`send` / `push` / `pull` / `sync`）的**如实登记**。
//!
//! 本模块是文档（`docs/adapter-spec.md`）与控制台"接入管理"页的**同一数据源**：
//! 一行 = 一个适配器，档位来自 [`AdapterMetadata::semantics`]（各厂商自己声明），
//! "是否真测 / 证据"来自 [`EVIDENCE`]——证据里写的集成测试函数名由单测**逐条核对存在性**
//! （[`evidence_tests_exist_in_wiremock_suite`]），因此矩阵不能"声称已测但没测"。
//!
//! ## 现状（`real_implementation` 与语义能力分开登记）
//!
//! - **12 个适配器全部具备 `send` 真实传输**（HTTP / SMTP / UDP-TCP），`real_implementation=true`；
//! - `push`/`pull`/`sync` 只在**协议支持**的适配器上实现：3 个工单类 + EDR（`sync` 需要
//!   `pull` 与 `push` 同时可用）+ Slack（消息更新/撤回）；
//! - 其余通知类与 `syslog`/`email` 登记为 `Unsupported` + **具体原因**（不是"未实现"占位）。

use crate::contract::{AdapterMetadata, SemanticCapability, SemanticProfile};

/// 单条证据：(适配器名, 是否有 push/pull/sync 往返测试, 证据文本)。
///
/// 证据文本里的 `#<测试函数名>` 必须真实存在于
/// `tests/http_vendors/semantics_*.rs`（由单测逐条核对，见 [`tests::evidence_tests_exist_in_wiremock_suite`]）。
pub const EVIDENCE: [(&str, bool, &str); 12] = [
    ("feishu", false, "未测（push/pull/sync 均 Unsupported；send 见 tests/http_vendors/retry_once.rs）"),
    ("dingtalk", false, "未测（push/pull/sync 均 Unsupported；send 见 tests/http_vendors/retry_once.rs）"),
    (
        "wecom",
        false,
        "未测（push/pull/sync 均 Unsupported；send 见 tests/http_vendors/wecom_posts_markdown_and_reads_errcode.rs）",
    ),
    ("email", false, "未测（push/pull/sync 均 Unsupported；send 见 tests/email_smtp/impl_smtp_behavior.rs）"),
    (
        "webhook",
        false,
        "未测（push/pull/sync 均 Unsupported；send 见 tests/http_vendors/wecom_posts_markdown_and_reads_errcode.rs）",
    ),
    (
        "slack",
        true,
        "tests/http_vendors/semantics_edr_notify.rs#slack_push_updates_message_via_chat_update、\
         #slack_push_revoke_deletes_message_and_reports_business_error",
    ),
    (
        "jira",
        true,
        "tests/http_vendors/semantics_push_pull.rs#jira_push_posts_transition_then_comment_with_exact_method_path_and_body、\
         #jira_pull_searches_incrementally_with_jql_and_normalizes_items、\
         tests/http_vendors/semantics_sync.rs#jira_sync_reconciles_with_external_wins_then_local_wins",
    ),
    (
        "servicenow",
        true,
        "tests/http_vendors/semantics_push_pull.rs#servicenow_push_patches_incident_with_state_and_work_notes、\
         #servicenow_pull_queries_incremental_incidents_by_sys_updated_on、\
         tests/http_vendors/semantics_sync.rs#servicenow_sync_reconciles_local_case_conflicts",
    ),
    (
        "zentao",
        true,
        "tests/http_vendors/semantics_push_pull.rs#zentao_push_puts_bug_status_and_comment、\
         #zentao_pull_reads_bugs_and_filters_since_cursor_client_side、\
         tests/http_vendors/semantics_sync.rs#zentao_sync_reconciles_with_local_wins_policy、\
         #pull_deduplicates_repeated_items_across_pages",
    ),
    ("syslog-forwarder", false, "未测（push/pull/sync 均 Unsupported；send 见 tests/http_vendors/isolate_message.rs）"),
    (
        "edr-isolation",
        true,
        "tests/http_vendors/semantics_edr_notify.rs#edr_push_patches_host_isolation_state_with_dry_run_marker、\
         #edr_pull_reads_hosts_incrementally_and_normalizes_action、\
         #edr_sync_reconciles_local_assets_with_edr_hosts",
    ),
    ("iam-scim", false, "未测（push/pull/sync 均 Unsupported；send 见 src/vendors/iam.rs 单测）"),
];

/// 按注册名取证据（未登记 ⇒ `(false, "—")`）。
#[must_use]
pub fn evidence_for(adapter: &str) -> (bool, &'static str) {
    EVIDENCE.iter().find(|(name, _, _)| *name == adapter).map_or((false, "—"), |(_, tested, text)| (*tested, *text))
}

/// 每个内置适配器一行（顺序与 [`crate::vendors::BUILTIN_NAMES`] 一致）。
#[must_use]
pub fn capability_matrix() -> Vec<SemanticCapability> {
    crate::vendors::builtin()
        .into_iter()
        .map(|adapter| {
            let meta = adapter.metadata();
            let (tested, evidence) = evidence_for(&meta.name);
            SemanticCapability::from_metadata(&meta, tested, evidence)
        })
        .collect()
}

/// 能力矩阵的 Markdown 表（文档直接粘贴使用）。
#[must_use]
pub fn capability_table_markdown() -> String {
    SemanticCapability::markdown_table(&capability_matrix())
}

/// 由元信息构造一行（供外部（如控制台/文档生成）按已解析的元信息渲染）。
#[must_use]
pub fn row_of(meta: &AdapterMetadata) -> SemanticCapability {
    let (tested, evidence) = evidence_for(&meta.name);
    SemanticCapability::from_metadata(meta, tested, evidence)
}

/// 校验档位登记的自洽性：不允许"未登记"、不允许空原因、`sync` 必须具备 `pull` + `push`。
///
/// # Errors
/// 返回第一个不自洽的说明（供单测与控制台自检复用）。
pub fn validate_semantics(meta: &AdapterMetadata) -> Result<(), String> {
    let profile: &SemanticProfile = &meta.semantics;
    if profile.has_undeclared() {
        return Err(format!("{}：push/pull/sync 存在「未登记」档位（必须如实声明）", meta.name));
    }
    if profile.has_empty_reason() {
        return Err(format!("{}：Unsupported 档位的原因不得为空", meta.name));
    }
    if profile.is_implemented(crate::contract::Semantic::Sync)
        && !(profile.is_implemented(crate::contract::Semantic::Pull)
            && profile.is_implemented(crate::contract::Semantic::Push))
    {
        return Err(format!("{}：sync 依赖 pull + push，三者必须同时已实现", meta.name));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{Semantic, SemanticSupport};

    /// 集成测试源码（编译期嵌入）：用于核对证据里引用的测试函数真实存在。
    const WIREMOCK_SOURCES: [&str; 4] = [
        include_str!("../../tests/http_vendors/semantics_push_pull.rs"),
        include_str!("../../tests/http_vendors/semantics_sync.rs"),
        include_str!("../../tests/http_vendors/semantics_edr_notify.rs"),
        include_str!("../../tests/http_vendors/semantics_cross_cutting.rs"),
    ];

    #[test]
    fn matrix_covers_every_builtin_in_order() {
        let rows = capability_matrix();
        let names: Vec<&str> = rows.iter().map(|row| row.adapter.as_str()).collect();
        assert_eq!(names, crate::vendors::BUILTIN_NAMES.to_vec(), "顺序必须与注册名常量一致");
        for row in &rows {
            assert!(row.send.is_implemented(), "{} 的 send 主路径已实现且已真实传输", row.adapter);
            assert!(!row.display_name.is_empty());
        }
    }

    #[test]
    fn every_builtin_declares_its_semantics_honestly() {
        for adapter in crate::vendors::builtin() {
            let meta = adapter.metadata();
            validate_semantics(&meta).unwrap_or_else(|e| panic!("{e}"));
        }
    }

    #[test]
    fn unsupported_rows_carry_specific_reasons() {
        let rows = capability_matrix();
        let mut unsupported_count = 0_usize;
        for row in &rows {
            for semantic in Semantic::ALL {
                let support = row.support(semantic);
                if let Some(reason) = support.reason() {
                    unsupported_count += 1;
                    assert!(reason.chars().count() >= 10, "{} 的 {semantic} 原因过于笼统: {reason}", row.adapter);
                    assert!(
                        !reason.contains("尚未实现") && !reason.contains("TODO"),
                        "{} 的 {semantic} 必须是「不适用」而不是「未实现」占位: {reason}",
                        row.adapter
                    );
                }
            }
        }
        assert_eq!(
            unsupported_count, 23,
            "36 条语义中 13 条已实现（3 个工单类 ×3 + EDR ×3 + Slack push = 13），其余 23 条如实登记 Unsupported"
        );
    }

    #[test]
    fn implemented_semantics_are_covered_by_declared_tests() {
        for row in capability_matrix() {
            if !row.has_implemented_semantics() {
                assert!(!row.tested, "{} 没有已实现的 push/pull/sync，不得标记为已真测", row.adapter);
                continue;
            }
            assert!(row.tested, "{} 有已实现语义，必须标记为已真测并给出证据", row.adapter);
            assert_ne!(row.evidence, "—", "{} 缺少证据", row.adapter);
        }
    }

    #[test]
    fn evidence_tests_exist_in_wiremock_suite() {
        for row in capability_matrix() {
            if !row.has_implemented_semantics() {
                continue;
            }
            let mut cited = 0_usize;
            for fragment in row.evidence.split('#').skip(1) {
                // 片段形如 `<测试名>、<下一个文件路径>`：取第一个分隔符前的那一段才是测试名
                let name = fragment.split(['、', ',', '；', ';']).next().unwrap_or_default().trim();
                assert!(!name.is_empty(), "{} 的证据里有空引用: {}", row.adapter, row.evidence);
                assert!(
                    WIREMOCK_SOURCES.iter().any(|source| source.contains(&format!("fn {name}("))),
                    "{} 的证据引用了不存在的集成测试 {name}（能力矩阵不得声称未测的东西）",
                    row.adapter
                );
                cited += 1;
            }
            assert!(cited >= 1, "{} 的证据必须至少引用一个真实测试", row.adapter);
        }
    }

    #[test]
    fn implemented_sets_match_adapter_capability() {
        let rows = capability_matrix();
        let row = |name: &str| rows.iter().find(|r| r.adapter == name).cloned().expect("适配器必须存在");
        for name in ["jira", "servicenow", "zentao", "edr-isolation"] {
            let row = row(name);
            for semantic in Semantic::ALL {
                assert!(
                    matches!(row.support(semantic), SemanticSupport::Implemented),
                    "{name} 的 {semantic} 已实现（含真实往返测试）"
                );
            }
        }
        let slack = row("slack");
        assert!(slack.push.is_implemented());
        assert!(!slack.pull.is_implemented());
        assert!(!slack.sync.is_implemented());
        for name in ["feishu", "dingtalk", "wecom", "email", "webhook", "syslog-forwarder"] {
            let row = row(name);
            for semantic in Semantic::ALL {
                assert!(
                    !row.support(semantic).is_implemented(),
                    "{name} 的 {semantic} 语义不适用，必须如实登记 Unsupported"
                );
            }
        }
    }

    #[test]
    #[allow(clippy::print_stdout)]
    fn capability_table_renders_and_prints_for_docs() {
        let table = capability_table_markdown();
        assert!(table.starts_with("| 适配器 | send | push | pull | sync | 是否真测 | 证据 |"));
        assert_eq!(table.lines().count(), 2 + crate::vendors::BUILTIN_NAMES.len());
        assert!(table.contains("⛔ Unsupported："), "不适用档位必须带原因");
        println!("{table}");
    }

    #[test]
    fn validate_semantics_rejects_inconsistent_declarations() {
        let undeclared = AdapterMetadata::new("x", "X", "t", crate::contract::AdapterCategory::Notification);
        assert!(validate_semantics(&undeclared).is_err(), "未登记必须被拒绝");

        let empty_reason = AdapterMetadata::new("y", "Y", "t", crate::contract::AdapterCategory::Notification)
            .with_semantics(SemanticProfile::send_only("", "有原因的原因", "有原因的原因"));
        assert!(validate_semantics(&empty_reason).is_err(), "空原因必须被拒绝");

        let sync_without_push = AdapterMetadata::new("z", "Z", "t", crate::contract::AdapterCategory::Itsm)
            .with_semantics(SemanticProfile {
                push: SemanticSupport::unsupported("通道不支持回写"),
                pull: SemanticSupport::implemented(),
                sync: SemanticSupport::implemented(),
            });
        let error = validate_semantics(&sync_without_push).expect_err("sync 依赖 pull+push");
        assert!(error.contains("sync"), "{error}");
    }
}
