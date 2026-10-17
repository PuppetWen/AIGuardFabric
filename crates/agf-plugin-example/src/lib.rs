#![deny(unsafe_code)]
//! AIGuardFabric **示例插件**（动态库形态）。
//!
//! 它是一个**真实可用**的插件，而不是"hello world"占位：
//!
//! 1. **自定义归一化器**（[`normalize_line`]）：把 `k=v` 形态的访问/安全日志行
//!    归一化成 **AGF-ECS 风格 JSON**（`@timestamp` / `source.ip` / `destination.port` /
//!    `event.action` / `labels.*` …），供宿主侧解析管线直接复用；
//! 2. **自定义通知渠道**（`ffi::notify_entry` → 追加写文件）：把一条消息投递到指定文件，
//!    效果可被端到端测试**直接观测**（读文件内容断言）。
//!
//! # 怎么被加载
//!
//! 宿主（`agf-plugin`）用 `libloading` 打开本 crate 产出的 `agf_plugin_example.dll`，
//! 取 `agf_plugin_descriptor_v1` 符号拿到描述符，再按函数指针表调用上面的能力：
//!
//! ```text
//! cargo build -p agf-plugin-example          # 产出 target/debug/agf_plugin_example.dll
//! ```
//!
//! # 安全边界
//!
//! 插件是**同进程代码**，与宿主**同等权限**——本示例就是活证据：它按需读写文件
//! （`notify` 直接 append 到任意路径）。宿主只应加载**可信来源**的插件；本 crate
//! 不做任何沙箱承诺（详见 `agf-plugin` 的 crate 文档）。
//!
//! `unsafe` 只出现在 [`ffi`] 模块：ABI 入口必须解引用宿主传来的裸指针，而且
//! edition 2024 下 `#[unsafe(no_mangle)]` 本身也归 `unsafe_code` lint 管。
//! 纯逻辑全在 [`normalize`] 里，零 `unsafe`（crate 根 `#![deny(unsafe_code)]` 依旧生效）。

// 插件 crate 的公开接口**就是**它的 FFI（导出的符号 + 描述符里的函数指针表），
// 因此这里刻意 `pub mod`：既如实反映"这些就是对外契约"，也让 `unreachable_pub` 不再误报。
pub mod ffi;
mod normalize;

pub use normalize::normalize_line;
pub use normalize::parse_kv;

/// 插件名（写进描述符，宿主用它索引插件）。
pub const PLUGIN_NAME: &str = "agf-plugin-example";

/// 插件版本（编译期从 `Cargo.toml` 注入）。
pub const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    // 测试里允许 unwrap/expect/panic（工作区默认 deny；这是仓库既有约定）。
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use agf_plugin::PluginKind;

    #[test]
    fn descriptor_is_self_consistent() {
        let descriptor = ffi::build_descriptor();
        assert_eq!(descriptor.abi_version, agf_plugin::AGF_PLUGIN_ABI_VERSION);
        assert_eq!(descriptor.kind, PluginKind::Normalizer.as_u32());
        assert_eq!(descriptor.reserved, 0);
        assert!(descriptor.vtable.normalize.is_some());
        assert!(descriptor.vtable.free_string.is_some());
        assert!(descriptor.vtable.notify.is_some());
        assert!(descriptor.vtable.last_error.is_some());
        assert!(!descriptor.name.is_null());
        assert!(!descriptor.version.is_null());
    }

    #[test]
    fn exported_symbol_returns_non_null_descriptor() {
        let pointer = ffi::agf_plugin_descriptor_v1();
        assert!(!pointer.is_null());
    }

    #[test]
    fn version_static_matches_cargo_version() {
        let text = std::str::from_utf8(&ffi::VERSION_C[..ffi::VERSION_C.len() - 1]).unwrap();
        assert_eq!(text, PLUGIN_VERSION);
    }
}
