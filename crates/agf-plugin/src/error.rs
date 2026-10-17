//! 插件加载 / 调用的错误类型。
//!
//! 设计约束：**任何失败都是返回 `Err`，绝不 panic**（宿主缺插件、装载坏插件都必须能继续启动）。

use std::path::PathBuf;

/// 插件加载或调用失败的原因。
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    /// 插件文件不存在。
    #[error("插件文件不存在：{0}")]
    NotFound(PathBuf),

    /// 路径存在但不是常规文件（目录 / 设备 / 管道等）。
    #[error("插件路径不是常规文件：{0}")]
    NotAFile(PathBuf),

    /// 动态库装载失败：不是合法动态库、缺依赖库、架构不匹配、权限不足等。
    #[error("动态库加载失败（{path}）：{source}")]
    Load {
        /// 被加载的文件。
        path: PathBuf,
        /// 底层 `libloading` 错误（含系统错误码与文本）。
        #[source]
        source: libloading::Error,
    },

    /// 动态库装载成功，但没有导出 ABI 约定的版本化符号。
    #[error("插件缺少版本化符号 `{symbol}`：{source}")]
    MissingSymbol {
        /// 期望的符号名。
        symbol: String,
        /// 底层 `libloading` 错误。
        #[source]
        source: libloading::Error,
    },

    /// ABI 版本不匹配 —— **拒绝加载**（不 panic、不降级、不尝试兼容）。
    #[error("插件 ABI 版本不匹配，拒绝加载：插件 `{plugin}` 声明 v{found}，宿主只接受 {supported:?}")]
    AbiMismatch {
        /// 插件自报的名字（可能为空——校验没过时只用于报错）。
        plugin: String,
        /// 插件声明的 ABI 版本。
        found: u32,
        /// 宿主接受的 ABI 版本集合。
        supported: Vec<u32>,
    },

    /// 描述符字段非法（名字/版本为空或超长、保留位非 0、缺少该类型必需的函数指针…）。
    #[error("插件描述符非法：{0}")]
    BadDescriptor(String),

    /// 调用插件导出函数失败（返回错误码、返回空指针、返回非法 UTF-8…）。
    #[error("插件调用失败：{0}")]
    Call(String),

    /// 读取插件目录失败（权限不足、目录项损坏等）。
    #[error("读取插件目录失败（{path}）：{source}")]
    DirRead {
        /// 被读取的目录。
        path: PathBuf,
        /// 底层 IO 错误。
        #[source]
        source: std::io::Error,
    },
}

impl PluginError {
    /// 是否是 ABI 版本门禁拒绝。
    #[must_use]
    pub fn is_abi_mismatch(&self) -> bool {
        matches!(self, Self::AbiMismatch { .. })
    }

    /// 是否是"文件不存在"。
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound(_))
    }

    /// 是否是"缺版本化符号"。
    #[must_use]
    pub fn is_missing_symbol(&self) -> bool {
        matches!(self, Self::MissingSymbol { .. })
    }
}
