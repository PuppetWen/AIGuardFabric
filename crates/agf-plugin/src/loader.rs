//! 插件装载器与"已加载插件"句柄。

use std::fmt;
use std::path::Path;
use std::path::PathBuf;

use libloading::Library;

use crate::abi;
use crate::abi::AGF_PLUGIN_ABI_VERSION;
use crate::abi::PluginKind;
use crate::abi::PluginMetadata;
use crate::abi::PluginVTable;
use crate::error::PluginError;

/// 一个已加载的插件。
///
/// **生命周期契约**：句柄持有动态库本身，函数指针在句柄存活期间有效；
/// 句柄 `drop` 时自动卸载动态库（`libloading::Library` 的 `Drop`）。
/// 因此**不要**把这里的方法返回的借用推迟到句柄之外使用——所有调用入口都借 `&self`，
/// 编译器会替你挡住这个错误。
pub struct LoadedPlugin {
    metadata: PluginMetadata,
    vtable: PluginVTable,
    path: PathBuf,
    /// 只为持有动态库（`Drop` 即卸载）；本 crate 不通过它另取符号。
    ///
    /// 刻意用 `_` 前缀命名：该字段**只**参与生命周期管理、不参与读取，
    /// 这样 `dead_code` 不会误报（一旦"读了它"，就等于绕开了
    /// 「函数指针不得活过动态库」的借用约束）。
    ///
    /// 字段 `drop` 顺序 = 声明顺序，`_library` 声明在最后 ⇒ 最后卸载。
    _library: Library,
}

impl fmt::Debug for LoadedPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 手写 Debug：函数指针没有可读表示，打出来只会是地址噪音。
        f.debug_struct("LoadedPlugin")
            .field("name", &self.metadata.name)
            .field("version", &self.metadata.version)
            .field("abis", &self.metadata.abi_version)
            .field("kind", &self.metadata.kind)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl LoadedPlugin {
    /// 描述符的纯数据视图（不含函数指针，可安全长期持有）。
    #[must_use]
    pub fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    /// 插件名（来自描述符，已通过字符集校验）。
    #[must_use]
    pub fn name(&self) -> &str {
        &self.metadata.name
    }

    /// 插件版本（来自描述符）。
    #[must_use]
    pub fn version(&self) -> &str {
        &self.metadata.version
    }

    /// 插件类型。
    #[must_use]
    pub fn kind(&self) -> PluginKind {
        self.metadata.kind
    }

    /// 插件声明的 ABI 版本（能走到这里说明已被宿主接受）。
    #[must_use]
    pub fn abi_version(&self) -> u32 {
        self.metadata.abi_version
    }

    /// 动态库文件路径。
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 调用插件的归一化函数：入参原始日志行，出参 AGF-ECS 风格 JSON 文本。
    ///
    /// 插件未提供该入口时返回 [`PluginError::Call`]（不是 panic）。
    pub fn normalize(&self, input: &str) -> Result<String, PluginError> {
        abi::call_normalize(self.vtable, input)
    }

    /// 调用插件的通知函数。成功返回 `Ok(())`，业务失败返回 [`PluginError::Call`]
    /// （原因取自插件的 `last_error`）。
    pub fn notify(&self, target: &str, message: &str) -> Result<(), PluginError> {
        abi::call_notify(self.vtable, target, message)
    }
}

/// 插件装载器：一条"宿主接受哪些 ABI 版本"的策略 + 加载入口。
///
/// **安全边界（不做沙箱承诺）**：装载的插件与宿主**同进程、同权限**。
/// 本类型只负责"按 ABI 约定校验并装载"，不提供任何隔离能力；只应加载可信插件。
#[derive(Debug, Clone)]
pub struct PluginLoader {
    supported_abi: Vec<u32>,
}

impl Default for PluginLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginLoader {
    /// 默认装载器：只接受当前 ABI 版本（[`AGF_PLUGIN_ABI_VERSION`]）。
    #[must_use]
    pub fn new() -> Self {
        Self { supported_abi: vec![AGF_PLUGIN_ABI_VERSION] }
    }

    /// 显式声明宿主接受的 ABI 版本集合（用于多版本共存，或**故意收紧**以验证门禁）。
    #[must_use]
    pub fn with_supported_abi(versions: impl IntoIterator<Item = u32>) -> Self {
        Self { supported_abi: versions.into_iter().collect() }
    }

    /// 宿主接受的 ABI 版本集合。
    #[must_use]
    pub fn supported_abi(&self) -> &[u32] {
        &self.supported_abi
    }

    /// 宿主是否接受某个 ABI 版本。
    #[must_use]
    pub fn accepts_abi(&self, abi_version: u32) -> bool {
        self.supported_abi.contains(&abi_version)
    }

    /// 按插件名在目录里解析动态库文件（平台后缀 + `lib` 前缀两种约定都试），命中返回路径。
    #[must_use]
    pub fn resolve_in_dir(dir: &Path, name: &str) -> Option<PathBuf> {
        let candidates = [abi::plugin_file_name(name), format!("{name}.{}", abi::plugin_file_suffix())];
        for candidate in candidates {
            let path = dir.join(candidate);
            if path.is_file() {
                return Some(path);
            }
        }
        None
    }

    /// 按插件名在目录里装载插件；解析不到文件返回 [`PluginError::NotFound`]。
    pub fn load_by_name(&self, dir: &Path, name: &str) -> Result<LoadedPlugin, PluginError> {
        let path = Self::resolve_in_dir(dir, name)
            .ok_or_else(|| PluginError::NotFound(dir.join(abi::plugin_file_name(name))))?;
        self.load(&path)
    }

    /// 装载插件。
    ///
    /// 错误分类（全部返回 `Err`，**绝不 panic**）：
    /// * 文件不存在 / 不是常规文件 ⇒ [`PluginError::NotFound`] / [`PluginError::NotAFile`]；
    /// * 不是合法动态库 / 缺依赖 ⇒ [`PluginError::Load`]；
    /// * 没有版本化符号 ⇒ [`PluginError::MissingSymbol`]；
    /// * 描述符字段非法 ⇒ [`PluginError::BadDescriptor`]；
    /// * ABI 版本不在接受集合内 ⇒ [`PluginError::AbiMismatch`]（**拒绝加载**，不降级）。
    ///
    /// 注意：ABI 版本校验必须在读完描述符之后，因此"被拒绝"的插件其实**已经跑过一次**
    /// （装载 + 描述符调用）。详见 crate 文档的安全边界一节。
    pub fn load(&self, path: &Path) -> Result<LoadedPlugin, PluginError> {
        let library = abi::open_library(path)?;
        let (metadata, vtable) = abi::read_descriptor(&library)?;

        if !self.accepts_abi(metadata.abi_version) {
            // 显式卸载：不要把一个"我们不认识其布局"的库留在进程里。
            drop(library);
            return Err(PluginError::AbiMismatch {
                plugin: metadata.name.clone(),
                found: metadata.abi_version,
                supported: self.supported_abi.clone(),
            });
        }

        tracing::info!(
            plugin = %metadata.name,
            version = %metadata.version,
            abi = metadata.abi_version,
            kind = metadata.kind.as_str(),
            path = %path.display(),
            "已加载 Rust 动态库插件（同进程、同权限：仅加载可信插件）"
        );

        Ok(LoadedPlugin { metadata, vtable, path: path.to_path_buf(), _library: library })
    }
}
