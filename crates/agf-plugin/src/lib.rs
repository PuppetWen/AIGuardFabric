#![deny(unsafe_code)]
//! Rust 动态库插件加载器（`crates/agf-plugin`）。
//!
//! 用 [`libloading`] 在运行时加载 `.dll` / `.so` / `.dylib` 形态的插件，并通过一套
//! **版本化的稳定 C ABI**（[`abi`]）调用插件导出的函数。它解决的是"用户清单里的
//! **Rust 动态库插件**"这一项：宿主不必在编译期知道插件的存在，插件也不必与宿主
//! 同一次编译。
//!
//! # 怎么用
//!
//! ```
//! use std::path::Path;
//! use agf_plugin::PluginLoader;
//!
//! let loader = PluginLoader::new();
//! match loader.load(Path::new("target/debug/agf_plugin_example.dll")) {
//!     Ok(plugin) => {
//!         println!("已加载 {} v{}（ABI v{}）", plugin.name(), plugin.version(), plugin.abi_version());
//!     }
//!     Err(err) => eprintln!("加载失败（不 panic）：{err}"),
//! }
//! ```
//!
//! 批量加载（缺目录 / 单个坏插件都不影响宿主启动）见 [`PluginRegistry`]。
//!
//! # ABI 约定
//!
//! * 插件必须导出一个固定名字的符号 [`abi::AGF_PLUGIN_DESCRIPTOR_SYMBOL_NAME`]
//!   （`agf_plugin_descriptor_v1`），返回 `#[repr(C)]` 的 [`abi::PluginDescriptor`] 指针；
//! * 描述符里带 `abi_version`（[`AGF_PLUGIN_ABI_VERSION`]）与一张**函数指针表**；
//! * **ABI 版本不匹配 ⇒ 拒绝加载**（返回 [`PluginError::AbiMismatch`]，不 panic、不降级）；
//! * 插件文件不存在 / 加载失败 / 缺符号 / 描述符非法 ⇒ 全部返回**明确错误**，绝不 panic。
//!
//! # 安全边界（必读）
//!
//! **插件与宿主在同一个进程内运行，等同宿主权限。**
//!
//! 加载一个动态库就会执行它的初始化例程；插件一旦被加载，就能读宿主内存、改全局状态、
//! 读写任意文件、发起任意网络请求。本 crate **不做也不承诺任何沙箱**——ABI 版本门禁只防
//! "结构不匹配导致的未定义行为"，**完全不防恶意代码**。
//!
//! 因此：**只应加载可信来源的插件**（受控制品库 / 签名校验后的产物），不要把
//! "加载插件"当成"加载不可信输入"。需要真正隔离，必须换进程边界（子进程 + IPC/沙箱），
//! 那不是本 crate 的形态。
//!
//! 另外一条如实声明：ABI 版本校验**发生在读取描述符之后**（要先读出 `abi_version` 才能
//! 比对），也就是说插件代码在"被拒绝"之前**已经跑过一次**。这不削弱上面的结论，但必须写清。
//!
//! # `unsafe` 在哪
//!
//! crate 根 `#![deny(unsafe_code)]`；唯一的例外是 [`abi`] 模块（`#[allow(unsafe_code)]`），
//! 因为 `libloading::Library::new` / `Library::get` 与"按 C ABI 解引用插件指针"在 Rust 里
//! 必然是 `unsafe`。该模块内每个 `unsafe` 块都带 `SAFETY:` 注释。

// `abi` 是全 crate **唯一**放行 `unsafe` 的模块：装载动态库（`libloading::Library::new`）
// 与按 C ABI 解引用插件指针在 Rust 里必然是 unsafe。crate 根仍是 `#![deny(unsafe_code)]`。
#[allow(unsafe_code)]
pub mod abi;
mod error;
mod loader;
mod registry;

pub use abi::AGF_PLUGIN_ABI_VERSION;
pub use abi::PluginDescriptor;
pub use abi::PluginKind;
pub use abi::PluginMetadata;
pub use abi::PluginVTable;
pub use abi::plugin_file_name;
pub use abi::plugin_file_suffix;
pub use error::PluginError;
pub use loader::LoadedPlugin;
pub use loader::PluginLoader;
pub use registry::PluginLoadFailure;
pub use registry::PluginRegistry;
