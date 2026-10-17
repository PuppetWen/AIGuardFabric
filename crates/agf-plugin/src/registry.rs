//! 插件注册表：一次装载一批插件，并把"失败的插件"如实记下来而不影响宿主启动。

use std::path::Path;
use std::path::PathBuf;

use crate::abi;
use crate::abi::AGF_PLUGIN_ABI_VERSION;
use crate::loader::LoadedPlugin;
use crate::loader::PluginLoader;

/// 一个装载失败的插件及其原因（**不抛异常、不 panic，只是记下来**）。
#[derive(Debug, Clone)]
pub struct PluginLoadFailure {
    /// 被尝试装载的文件。
    pub path: PathBuf,
    /// 失败原因（人类可读，含具体错误分类）。
    pub reason: String,
}

/// 插件注册表。
///
/// 降级语义（宿主启动路径的关键约束）：
/// * **目录不存在** ⇒ 记一条 warn，返回 `Ok(0)`——缺插件**不是错误**，宿主照常启动；
/// * **单个插件装载失败** ⇒ 计入 [`PluginRegistry::failures`] 并继续装载其余插件；
/// * **ABI 版本不匹配** ⇒ 该插件计入 failures 且**不会被加载**（不 panic、不降级）。
#[derive(Debug)]
pub struct PluginRegistry {
    loader: PluginLoader,
    plugins: Vec<LoadedPlugin>,
    failures: Vec<PluginLoadFailure>,
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginRegistry {
    /// 默认注册表：只接受当前 ABI 版本。
    #[must_use]
    pub fn new() -> Self {
        Self::with_supported_abi([AGF_PLUGIN_ABI_VERSION])
    }

    /// 显式声明接受的 ABI 版本集合。
    #[must_use]
    pub fn with_supported_abi(versions: impl IntoIterator<Item = u32>) -> Self {
        Self { loader: PluginLoader::with_supported_abi(versions), plugins: Vec::new(), failures: Vec::new() }
    }

    /// 宿主接受的 ABI 版本集合。
    #[must_use]
    pub fn supported_abi(&self) -> &[u32] {
        self.loader.supported_abi()
    }

    /// 已成功加载的插件。
    #[must_use]
    pub fn plugins(&self) -> &[LoadedPlugin] {
        &self.plugins
    }

    /// 装载失败的插件（含原因）。
    #[must_use]
    pub fn failures(&self) -> &[PluginLoadFailure] {
        &self.failures
    }

    /// 已加载插件数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// 是否一个插件都没加载。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// 按名字取插件。
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&LoadedPlugin> {
        self.plugins.iter().find(|plugin| plugin.name() == name)
    }

    /// 按名字装载单个插件文件；失败时登记到 [`PluginRegistry::failures`] 并返回错误。
    ///
    /// 注意：返回值只表示"这次装载是否成功"；失败已同时被登记，调用方可选择
    /// "记下来继续跑"（批量路径）或"立刻上报"（显式路径）。
    pub fn load_file(&mut self, path: &Path) -> Result<(), crate::error::PluginError> {
        match self.loader.load(path) {
            Ok(plugin) => {
                self.plugins.push(plugin);
                Ok(())
            }
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "插件装载失败（已登记，宿主继续）"
                );
                self.failures.push(PluginLoadFailure { path: path.to_path_buf(), reason: err.to_string() });
                Err(err)
            }
        }
    }

    /// 装载目录下的全部动态库插件。
    ///
    /// * 目录不存在 ⇒ `Ok(0)`（缺插件 = 降级，不是错误）；
    /// * 目录存在但为空 ⇒ `Ok(0)`；
    /// * 目录内非动态库后缀的文件（如 `.txt`、`.json`）直接跳过；
    /// * 单个插件失败 ⇒ 登记后继续，最终返回**成功装载的数量**。
    pub fn load_dir(&mut self, dir: &Path) -> Result<usize, crate::error::PluginError> {
        if !dir.exists() {
            tracing::warn!(
                dir = %dir.display(),
                "插件目录不存在：跳过插件加载（宿主按「无插件」降级启动）"
            );
            return Ok(0);
        }
        if !dir.is_dir() {
            return Err(crate::error::PluginError::NotAFile(dir.to_path_buf()));
        }

        let before = self.plugins.len();
        let mut entries = Vec::new();
        let read = std::fs::read_dir(dir)
            .map_err(|source| crate::error::PluginError::DirRead { path: dir.to_path_buf(), source })?;
        for entry in read {
            let entry =
                entry.map_err(|source| crate::error::PluginError::DirRead { path: dir.to_path_buf(), source })?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let suffix = abi::plugin_file_suffix();
            let matches =
                path.extension().and_then(std::ffi::OsStr::to_str).is_some_and(|ext| ext.eq_ignore_ascii_case(suffix));
            if matches {
                entries.push(path);
            }
        }
        entries.sort();

        for path in entries {
            // 单点失败不影响其它插件；`load_file` 已经登记 failures。
            let _ = self.load_file(&path);
        }
        Ok(self.plugins.len() - before)
    }
}
