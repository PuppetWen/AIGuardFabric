//! 平台能力矩阵：哪些采集项在本平台是**真实现**，哪些只是接口 + TODO。
//!
//! ## 事实边界（必须如实登记）
//!
//! - **Windows：真实现并在测试中用临时目录/夹具样本验证**（见各采集器模块的单测）；
//! - **Linux：七类采集均已接线**，监听端口读取 `/proc/net`；离线容器已测试。
//! - **macOS：七类采集已接线**，监听端口使用系统 `lsof`；真机待验，缺少命令或权限时如实报错。
//!
//! ## 降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 非 Windows 平台尚未接线的采集项 | 返回 `NotImplemented` + 平台 TODO 锚点 |
//! | 采集项所需的目录不存在 | 返回空结果 + scope 记录（**不是错误**） |
//! | 采集项执行失败 | 只记入 `CollectorStatus.error`，不中断其它采集项 |

use std::fmt;

/// 目标平台。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostPlatform {
    /// Windows。
    Windows,
    /// Linux。
    Linux,
    /// macOS。
    MacOs,
    /// 其它（如实登记为"未支持"）。
    Other,
}

impl HostPlatform {
    /// 文本形式（与发布资产 `platform` 字段一致）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::MacOs => "macos",
            Self::Other => "other",
        }
    }

    /// 是否 Windows。
    #[must_use]
    pub const fn is_windows(&self) -> bool {
        matches!(self, Self::Windows)
    }

    /// 该平台的 TODO 锚点（Windows 无锚点 = 已实现）。
    #[must_use]
    pub const fn todo_anchor(&self) -> Option<&'static str> {
        match self {
            Self::Windows => None,
            Self::Linux => Some("agent-linux"),
            Self::MacOs => Some("agent-macos"),
            Self::Other => Some("agent-other-platform"),
        }
    }
}

impl fmt::Display for HostPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 编译期平台。
#[must_use]
pub const fn current() -> HostPlatform {
    if cfg!(target_os = "windows") {
        HostPlatform::Windows
    } else if cfg!(target_os = "linux") {
        HostPlatform::Linux
    } else if cfg!(target_os = "macos") {
        HostPlatform::MacOs
    } else {
        HostPlatform::Other
    }
}

/// 编译期架构（`x86_64` / `aarch64` / …）。
#[must_use]
pub const fn current_arch() -> &'static str {
    std::env::consts::ARCH
}

/// 采集器支持级别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupportLevel {
    /// 本平台有实际采集实现；跨平台项目仍须目标系统验收。
    Implemented,
    /// 仅接口（返回 `NotImplemented` + TODO 锚点）。
    InterfaceOnly,
}

impl SupportLevel {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Implemented => "implemented",
            Self::InterfaceOnly => "interface-only",
        }
    }
}

/// 采集器描述（控制台"终端能力矩阵"页数据源）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CollectorDescriptor {
    /// 采集器名。
    pub name: &'static str,
    /// 显示名。
    pub display_name: &'static str,
    /// 支持级别。
    pub level: SupportLevel,
    /// 仅接口时的 TODO 锚点。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub todo_anchor: Option<&'static str>,
}

/// 采集器清单（按当前编译平台生成级别）。
#[must_use]
pub fn collector_roster() -> Vec<CollectorDescriptor> {
    collector_roster_for(current())
}

fn collector_roster_for(platform: HostPlatform) -> Vec<CollectorDescriptor> {
    [
        ("env-secrets", "环境变量硬编码密钥扫描"),
        ("mcp-config", "MCP 配置文件解析"),
        ("ide-plugins", "IDE / Agent 插件目录扫描"),
        ("skills", "工具与 Skill 目录扫描"),
        ("model-endpoints", "模型端点配置扫描"),
        ("processes", "AI 相关进程扫描"),
        ("listening-ports", "监听端口扫描"),
    ]
    .into_iter()
    .map(|(name, display_name)| {
        let implemented = matches!(platform, HostPlatform::Windows | HostPlatform::Linux | HostPlatform::MacOs);
        CollectorDescriptor {
            name,
            display_name,
            level: if implemented { SupportLevel::Implemented } else { SupportLevel::InterfaceOnly },
            todo_anchor: if implemented { None } else { platform.todo_anchor() },
        }
    })
    .collect()
}

/// 当前平台的"未实现采集项"错误（仅供未支持的平台使用）。
#[must_use]
pub fn unsupported_error(collector: &str) -> Option<agf_core::error::DomainError> {
    current().todo_anchor().map(|anchor| {
        agf_core::error::DomainError::NotImplemented(format!(
            "采集器 {collector} 在 {}/{} 上尚未实现（TODO({anchor})）：\
             该平台需按同一接口补齐采集实现和权限模型后再启用",
            current().as_str(),
            current_arch()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_identity_and_todo_anchors_are_stable() {
        assert_eq!(HostPlatform::Windows.todo_anchor(), None);
        assert_eq!(HostPlatform::Linux.todo_anchor(), Some("agent-linux"));
        assert_eq!(HostPlatform::MacOs.todo_anchor(), Some("agent-macos"));
        assert_eq!(HostPlatform::Other.as_str(), "other");
        assert!(HostPlatform::Windows.is_windows());
    }

    #[test]
    fn roster_covers_seven_collectors_and_portable_collectors() {
        for platform in [HostPlatform::Windows, HostPlatform::Linux, HostPlatform::MacOs, HostPlatform::Other] {
            let roster = collector_roster_for(platform);
            assert_eq!(roster.len(), 7);
            for descriptor in &roster {
                let implemented = matches!(platform, HostPlatform::Windows | HostPlatform::Linux | HostPlatform::MacOs);
                assert_eq!(descriptor.level == SupportLevel::Implemented, implemented);
                assert_eq!(descriptor.todo_anchor, if implemented { None } else { platform.todo_anchor() });
                assert!(!descriptor.name.is_empty());
                assert!(!descriptor.display_name.is_empty());
            }
        }
    }

    #[test]
    fn unsupported_error_only_on_non_windows() {
        let error = unsupported_error("processes");
        if current().is_windows() {
            assert!(error.is_none(), "Windows 已实测，不应有 TODO 锚点");
        } else {
            let text = error.map(|e| e.to_string()).unwrap_or_default();
            assert!(text.contains("TODO(agent-"), "{text}");
        }
    }

    #[test]
    fn support_level_and_platform_texts() {
        assert_eq!(SupportLevel::Implemented.as_str(), "implemented");
        assert_eq!(SupportLevel::InterfaceOnly.as_str(), "interface-only");
        assert!(!current_arch().is_empty());
        assert_eq!(current().to_string(), current().as_str());
    }
}
