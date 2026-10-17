//! 租户模型（多租户：逻辑隔离 + 可选物理隔离，§4.7）。

use serde::{Deserialize, Serialize};

use crate::enums::DataClass;
use crate::ids::{Id, TenantId};
use crate::time::Timestamp;

/// 隔离级别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum IsolationMode {
    /// 逻辑隔离：同库同表，强制 `tenant_id` 过滤 + RLS。
    #[default]
    Logical,
    /// 物理隔离：独立数据库/独立 schema（面向强合规客户）。
    Physical,
}

impl IsolationMode {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Logical => "logical",
            Self::Physical => "physical",
        }
    }
}

/// 租户。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    /// 主键。
    pub id: TenantId,
    /// 唯一 slug（URL 友好，登录时用于定位租户）。
    pub slug: String,
    /// 显示名。
    pub name: String,
    /// 隔离级别。
    pub isolation: IsolationMode,
    /// 物理隔离时的数据库 DSN 别名（不含明文凭据，凭据走 `credentials` 表加密存储）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physical_dsn_ref: Option<String>,
    /// 默认数据分级（影响是否允许外用大模型）。
    pub default_data_class: DataClass,
    /// 是否启用（停用后除超管外全部拒绝）。
    pub enabled: bool,
    /// 白标配置（§M9 商业化）。
    pub branding: TenantBranding,
    /// 计费埋点开关。
    pub billing_enabled: bool,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 更新时间。
    pub updated_at: Timestamp,
    /// 软删除时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<Timestamp>,
}

impl Tenant {
    /// 新建租户（默认值填充）。
    #[must_use]
    pub fn new(slug: impl Into<String>, name: impl Into<String>) -> Self {
        let now = Timestamp::now();
        Self {
            id: TenantId::new(),
            slug: slug.into(),
            name: name.into(),
            isolation: IsolationMode::default(),
            physical_dsn_ref: None,
            default_data_class: DataClass::Internal,
            enabled: true,
            branding: TenantBranding::default(),
            billing_enabled: true,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }

    /// 是否可用。
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.enabled && self.deleted_at.is_none()
    }
}

impl crate::ids::TenantScoped for Tenant {
    fn tenant_id(&self) -> TenantId {
        self.id
    }
}

/// 白标（多租户品牌定制）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantBranding {
    /// 产品名（默认 AIGuardFabric 智御矩阵）。
    pub product_name: String,
    /// 主色（HEX）。
    pub primary_color: String,
    /// Logo URL（走对象存储或 data URI）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    /// 页脚文本。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub footer_text: Option<String>,
    /// 默认语言。
    pub default_locale: String,
}

impl Default for TenantBranding {
    fn default() -> Self {
        Self {
            product_name: "AIGuardFabric 智御矩阵".to_string(),
            primary_color: "#1677ff".to_string(),
            logo_url: None,
            footer_text: None,
            default_locale: "zh-CN".to_string(),
        }
    }
}

/// 租户级设置（键值，含敏感值时不落明文）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantSetting {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 设置键（形如 `notify.dingtalk.enabled`）。
    pub key: String,
    /// 值（JSON）。
    pub value: serde_json::Value,
    /// 是否加密存储。
    pub encrypted: bool,
    /// 更新时间。
    pub updated_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::TenantScoped as _;

    #[test]
    fn new_tenant_is_active_and_logically_isolated() {
        let t = Tenant::new("acme", "ACME 公司");
        assert!(t.is_active());
        assert_eq!(t.isolation, IsolationMode::Logical);
        assert_eq!(t.tenant_id(), t.id);
        assert_eq!(t.branding.default_locale, "zh-CN");
    }

    #[test]
    fn disabled_tenant_is_inactive() {
        let mut t = Tenant::new("acme", "ACME");
        t.enabled = false;
        assert!(!t.is_active());
    }

    #[test]
    fn isolation_mode_str() {
        assert_eq!(IsolationMode::Physical.as_str(), "physical");
        assert_eq!(IsolationMode::default().as_str(), "logical");
    }
}
