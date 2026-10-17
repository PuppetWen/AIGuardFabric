//! 测试支撑（仅 `cfg(test)` 编译）。
//!
//! 提供跨模块复用的测试数据构造器与断言宏。放在独立模块的原因：
//! `#[cfg(test)] mod tests` 内的 `pub(crate) fn` 无法被其它模块的 `tests` 模块导入
//! （`tests` 模块本身是私有的），因此共享件必须提升到模块层级。

/// 构造一条样例策略（结构化，命中 `rm -rf`）。
///
/// 各模块的测试共用它作为"最小可用策略"，避免每个测试文件重复 30 行构造代码。
#[must_use]
pub(crate) fn sample_policy(name: &str) -> agf_core::policy::Policy {
    use agf_core::enums::{InterceptPoint, PolicyAction};
    use agf_core::ids::{Id, TenantId};
    use agf_core::policy::{Policy, PolicyLanguage, StructuredCondition};
    use agf_core::time::Timestamp;

    let now = Timestamp::now();
    Policy {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: name.to_string(),
        description: String::new(),
        language: PolicyLanguage::Structured,
        source: String::new(),
        structured: StructuredCondition { command_deny: vec!["rm -rf".into()], ..StructuredCondition::default() },
        action: PolicyAction::Deny,
        priority: 10,
        intercept_points: vec![InterceptPoint::McpProxy],
        scope_agent_ids: vec![],
        scope_departments: vec![],
        enabled: true,
        dry_run: false,
        quota_id: None,
        degrade_endpoint_id: None,
        content_hash: String::new(),
        signature: String::new(),
        version: 1,
        created_at: now,
        updated_at: now,
        deleted_at: None,
    }
}

/// 断言 `Result::Ok` 的值等于期望值（**不要求 `T: PartialEq` 之外的任何 trait**）。
///
/// 之所以不用 `assert_eq!(result, Ok(v))`：`DomainError` 未实现 `PartialEq`
/// （含 `String` 载荷，实现它属于 `agf-core` 的跨 crate 变更），
/// 因此这里只比对 `Ok` 侧的值。
macro_rules! assert_ok_is {
    ($expr:expr, $expected:expr $(, $msg:literal)?) => {{
        let actual = $expr;
        match actual {
            Ok(v) => {
                let expected = $expected;
                assert!(v == expected, "期望 {:?}，实际 {:?}", expected, v $(, $msg)?);
            }
            Err(e) => panic!("期望 Ok，实际 Err({e})" $(, $msg)?),
        }
    }};
}

/// 断言 `Result::Err` 等于期望错误。
///
/// `DomainError` 已实现 `PartialEq`（见 `agf-core::error`），因此这里可以直接比对；
/// 保留宏是为了让"期望某个具体错误"的测试读起来更接近自然语言。
macro_rules! assert_err_is {
    ($expr:expr, $expected:expr $(, $msg:literal)?) => {{
        let actual = $expr;
        match actual {
            Ok(v) => panic!("期望 Err，实际 Ok({v:?})" $(, $msg)?),
            Err(e) => {
                let expected = $expected;
                assert!(e == expected, "期望 {:?}，实际 {:?}", expected, e $(, $msg)?);
            }
        }
    }};
}

pub(crate) use assert_err_is;
pub(crate) use assert_ok_is;
