//! 退出码常量（对外契约，测试与文档共用同一份定义）。
//!
//! 修改这里的取值等于修改 CI 的归因口径，因此单独成模块而不是散落的字面量。

/// 成功。
pub const SUCCESS: u8 = 0;
/// 判定失败：校验未通过 / 探针不健康 / 清单不一致（**内容问题**）。
pub const VALIDATION_FAILED: u8 = 1;
/// 外部依赖不可用或尚未验证：PG 不可达、`pg_dump`/`pg_restore` 不存在。
pub const DEPENDENCY_UNAVAILABLE: u8 = 2;
/// 意外错误（I/O、序列化等程序侧问题）。
pub const GENERAL_FAILURE: u8 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_values_are_stable() {
        assert_eq!(SUCCESS, 0);
        assert_eq!(VALIDATION_FAILED, 1);
        assert_eq!(DEPENDENCY_UNAVAILABLE, 2);
        assert_eq!(GENERAL_FAILURE, 1);
        assert_ne!(VALIDATION_FAILED, DEPENDENCY_UNAVAILABLE, "两类失败必须可区分");
    }
}
