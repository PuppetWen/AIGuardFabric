//! 通用标识类型。
//!
//! 平台所有实体主键统一使用 UUID v7（时间有序，利于 TimescaleDB/ClickHouse 分区裁剪）。
//! [`TenantId`] 是租户隔离的强类型锚点：任何跨租户访问都必须显式经过租户过滤。

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// 通用实体标识（UUID v7 包装）。
///
/// 使用 `#[serde(transparent)]`，对外表现为裸字符串，避免前端多一层嵌套。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Id(Uuid);

impl Id {
    /// 生成新的时间有序 ID（UUID v7）。生成失败时退化为 v4，保证不 panic。
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// 由已有 `Uuid` 构造。
    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    /// 由字节切片解析。
    ///
    /// # Errors
    /// 当字节长度不等于 16 时返回错误。
    pub fn from_slice(bytes: &[u8]) -> Result<Self, uuid::Error> {
        Uuid::from_slice(bytes).map(Self)
    }

    /// 由字符串解析。
    ///
    /// # Errors
    /// 非法 UUID 字符串返回 `uuid::Error`。
    pub fn parse(value: &str) -> Result<Self, uuid::Error> {
        Uuid::parse_str(value).map(Self)
    }

    /// 取出内部 `Uuid`。
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }

    /// 取字节数组。
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }

    /// nil 值（全零），用于表示"未设置"。
    #[must_use]
    pub const fn nil() -> Self {
        Self(Uuid::nil())
    }

    /// 是否 nil。
    #[must_use]
    pub const fn is_nil(&self) -> bool {
        self.0.is_nil()
    }
}

impl Default for Id {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Id {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl From<Uuid> for Id {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl From<Id> for Uuid {
    fn from(value: Id) -> Self {
        value.0
    }
}

impl AsRef<Uuid> for Id {
    fn as_ref(&self) -> &Uuid {
        &self.0
    }
}

/// 租户标识。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TenantId(Uuid);

impl TenantId {
    /// 生成新的租户 ID。
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// 由已有 `Uuid` 构造。
    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    /// 由 `Id` 构造。
    #[must_use]
    pub const fn from_id(value: Id) -> Self {
        Self(value.0)
    }

    /// 解析字符串。
    ///
    /// # Errors
    /// 非法 UUID 返回 `uuid::Error`。
    pub fn parse(value: &str) -> Result<Self, uuid::Error> {
        Uuid::parse_str(value).map(Self)
    }

    /// 内部 UUID。
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }

    /// 转 `Id`。
    #[must_use]
    pub const fn as_id(&self) -> Id {
        Id(self.0)
    }

    /// 平台内置默认租户（`00000000-0000-0000-0000-000000000001`）。
    ///
    /// 该常量与 `deploy/sql/migration_parts/` 内嵌 0001 迁移的种子数据保持一致。
    #[must_use]
    pub const fn default_tenant() -> Self {
        Self(Uuid::from_u128(1))
    }
}

impl Default for TenantId {
    fn default() -> Self {
        Self::default_tenant()
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for TenantId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl From<TenantId> for Uuid {
    fn from(value: TenantId) -> Self {
        value.0
    }
}

/// 带租户归属的实体。
///
/// 所有持久化实体都应实现本 trait，仓储层用它对 SQL 注入 `tenant_id` 过滤条件，
/// 保证"忘记加租户条件"这类越权在编译期就暴露（见 `agf-storage`）。
pub trait TenantScoped {
    /// 实体所属租户。
    fn tenant_id(&self) -> TenantId;
}

/// 由命名空间与业务键生成**确定性** ID（UUID v5，SHA-1）。
///
/// 用途：资产指纹去重（同一 MCP endpoint 重复上报归并为同一资产）、
/// 规则/剧本的稳定标识、Mock 数据的可复现 ID。
#[must_use]
pub fn deterministic_id(namespace: &str, key: &str) -> Id {
    let ns = Uuid::new_v5(&Uuid::NAMESPACE_URL, namespace.as_bytes());
    Id(Uuid::new_v5(&ns, key.as_bytes()))
}

/// 资产指纹命名空间常量（资产发现去重使用）。
pub const NS_ASSET: &str = "aiguardfabric.asset";
/// Agent 指纹命名空间。
pub const NS_AGENT: &str = "aiguardfabric.agent";
/// MCP 指纹命名空间。
pub const NS_MCP: &str = "aiguardfabric.mcp";
/// 规则指纹命名空间。
pub const NS_RULE: &str = "aiguardfabric.rule";
/// 红队用例指纹命名空间。
pub const NS_REDTEAM_CASE: &str = "aiguardfabric.redteam.case";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_roundtrip() {
        let id = Id::new();
        let text = id.to_string();
        let parsed = Id::parse(&text);
        assert!(parsed.is_ok());
        assert_eq!(parsed.map(|v| v.as_uuid()), Ok(id.as_uuid()));
    }

    #[test]
    fn id_serde_is_transparent() {
        let id = Id::parse("018f0a1e-0000-7000-8000-000000000000");
        assert!(id.is_ok());
        let Some(id) = id.ok() else { return };
        let json = serde_json::to_string(&id);
        assert_eq!(json.ok().as_deref(), Some("\"018f0a1e-0000-7000-8000-000000000000\""));
    }

    #[test]
    fn deterministic_id_is_stable() {
        let a = deterministic_id(NS_ASSET, "mcp://10.0.0.1:8080");
        let b = deterministic_id(NS_ASSET, "mcp://10.0.0.1:8080");
        let c = deterministic_id(NS_ASSET, "mcp://10.0.0.2:8080");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn default_tenant_matches_seed() {
        assert_eq!(TenantId::default_tenant().to_string(), "00000000-0000-0000-0000-000000000001");
    }
}
