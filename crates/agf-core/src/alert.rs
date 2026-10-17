//! 告警与聚合降噪模型（§4.6）。

use serde::{Deserialize, Serialize};

use crate::enums::{AlertState, RiskDomain, Severity};
use crate::ids::{Id, TenantId, TenantScoped};
use crate::time::Timestamp;

/// 告警。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 告警标题。
    pub title: String,
    /// 描述。
    #[serde(default)]
    pub description: String,
    /// 严重等级。
    pub severity: Severity,
    /// 安全域。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<RiskDomain>,
    /// 状态。
    pub state: AlertState,
    /// 关联 finding 列表。
    #[serde(default)]
    pub finding_ids: Vec<Id>,
    /// 聚合后的重复次数（去重降噪的核心指标）。
    pub dedup_count: u32,
    /// 聚合键（同键告警被合并）。
    pub dedup_key: String,
    /// 关联资产 id 列表。
    #[serde(default)]
    pub asset_ids: Vec<Id>,
    /// 关联事件 id 列表（证据）。
    #[serde(default)]
    pub event_ids: Vec<Id>,
    /// 影响的主机/用户（用于画像聚合）。
    #[serde(default)]
    pub affected_hosts: Vec<String>,
    /// 首次发生时间。
    pub first_seen_at: Timestamp,
    /// 最近发生时间。
    pub last_seen_at: Timestamp,
    /// 指派给。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    /// 关联案件 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_id: Option<Id>,
    /// 升级层级（0 = 未升级）。
    pub escalation_level: u8,
    /// SLA 截止时间（按等级计算）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sla_due_at: Option<Timestamp>,
    /// 是否已按 SLA 超时。
    #[serde(default)]
    pub sla_breached: bool,
    /// 标签。
    #[serde(default)]
    pub tags: Vec<String>,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 更新时间。
    pub updated_at: Timestamp,
}

impl TenantScoped for Alert {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl Alert {
    /// 计算升级键（用于聚合）。
    ///
    /// 设计：`租户 + 安全域 + 首要资产 + 标题归一`，避免把不相关告警合并。
    #[must_use]
    pub fn compute_dedup_key(
        tenant: TenantId,
        domain: Option<RiskDomain>,
        primary_asset: Option<&Id>,
        title: &str,
    ) -> String {
        let domain_part = match domain {
            Some(d) => d.as_str().to_string(),
            None => "-".to_string(),
        };
        let asset_part = match primary_asset {
            Some(a) => a.to_string(),
            None => "-".to_string(),
        };
        format!("{tenant}|{domain_part}|{asset_part}|{}", title.trim().to_lowercase())
    }

    /// 是否仍处于活动状态。
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.state, AlertState::Open | AlertState::Acknowledged | AlertState::Escalated)
    }

    /// 按严重等级计算 SLA 时长（秒）。
    ///
    /// 对齐常见 SOC 实践：严重 15 分钟、高 1 小时、中 4 小时、低 24 小时、信息 72 小时。
    #[must_use]
    pub const fn sla_secs(severity: Severity) -> i64 {
        match severity {
            Severity::Critical => 900,
            Severity::High => 3_600,
            Severity::Medium => 14_400,
            Severity::Low => 86_400,
            Severity::Info => 259_200,
        }
    }

    /// 重新计算 SLA 截止与超时标记。
    pub fn refresh_sla(&mut self, now: Timestamp) {
        let due = self.first_seen_at.offset_secs(Self::sla_secs(self.severity));
        self.sla_due_at = Some(due);
        self.sla_breached = self.is_active() && due.as_datetime() < now.as_datetime();
    }

    /// 距 SLA 截止的剩余秒数（已超时为负）。
    #[must_use]
    pub fn sla_remaining_secs(&self, now: Timestamp) -> Option<i64> {
        self.sla_due_at.map(|d| d.unix_secs() - now.unix_secs())
    }

    /// 合并一条新发生的同键告警（去重降噪）。
    pub fn merge_occurrence(&mut self, at: Timestamp, event_ids: &[Id]) {
        self.dedup_count = self.dedup_count.saturating_add(1);
        if at.as_datetime() > self.last_seen_at.as_datetime() {
            self.last_seen_at = at;
        }
        if at.as_datetime() < self.first_seen_at.as_datetime() {
            self.first_seen_at = at;
        }
        for id in event_ids {
            if !self.event_ids.contains(id) {
                self.event_ids.push(*id);
            }
        }
        self.updated_at = Timestamp::now();
    }
}

/// 告警聚合策略（抑制规则）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationPolicy {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 名称。
    pub name: String,
    /// 聚合窗口（秒）：窗口内同键只保留一条并累加计数。
    pub window_secs: i64,
    /// 是否抑制低等级（当更高等级同源告警存在时）。
    #[serde(default)]
    pub suppress_lower_severity: bool,
    /// 抑制的等级阈值。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppress_below: Option<Severity>,
    /// 维护窗口（如变更期），窗口内告警静默。
    #[serde(default)]
    pub maintenance_windows: Vec<MaintenanceWindow>,
    /// 是否启用。
    pub enabled: bool,
    /// 创建时间。
    pub created_at: Timestamp,
}

impl TenantScoped for AggregationPolicy {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

/// 维护窗口（静默期）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceWindow {
    /// 描述。
    pub reason: String,
    /// 开始。
    pub from: Timestamp,
    /// 结束。
    pub to: Timestamp,
    /// 仅静默这些资产（空 = 全部）。
    #[serde(default)]
    pub asset_ids: Vec<Id>,
}

impl MaintenanceWindow {
    /// 是否覆盖给定时间与资产。
    #[must_use]
    pub fn covers(&self, at: Timestamp, asset: Option<&Id>) -> bool {
        if at.as_datetime() < self.from.as_datetime() || at.as_datetime() > self.to.as_datetime() {
            return false;
        }
        self.asset_ids.is_empty() || asset.is_some_and(|a| self.asset_ids.iter().any(|x| x == a))
    }
}

/// 告警升级路由（§4.6 sla 计时、升级路由）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationRule {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 名称。
    pub name: String,
    /// 适用的最低等级。
    pub min_severity: Severity,
    /// 触发延迟（秒；超时未确认即升级）。
    pub after_secs: i64,
    /// 目标订阅者（用户/组/渠道）。
    #[serde(default)]
    pub notify_user_ids: Vec<Id>,
    /// 通知渠道 id。
    #[serde(default)]
    pub channel_ids: Vec<Id>,
    /// 升级层级。
    pub level: u8,
    /// 是否启用。
    pub enabled: bool,
    /// 创建时间。
    pub created_at: Timestamp,
}

impl TenantScoped for EscalationRule {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl EscalationRule {
    /// 是否应触发升级。
    #[must_use]
    pub fn should_escalate(&self, alert: &Alert, now: Timestamp) -> bool {
        if !self.enabled || !alert.is_active() {
            return false;
        }
        if alert.severity.weight() < self.min_severity.weight() {
            return false;
        }
        if alert.escalation_level >= self.level {
            return false;
        }
        now.since_secs(&alert.last_seen_at) >= self.after_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert() -> Alert {
        let now = Timestamp::now();
        let tenant = TenantId::default_tenant();
        let asset = Id::new();
        Alert {
            id: Id::new(),
            tenant_id: tenant,
            title: "提示词注入尝试".into(),
            description: String::new(),
            severity: Severity::High,
            domain: Some(RiskDomain::PromptAttack),
            state: AlertState::Open,
            finding_ids: vec![],
            dedup_count: 1,
            dedup_key: Alert::compute_dedup_key(tenant, Some(RiskDomain::PromptAttack), Some(&asset), "提示词注入尝试"),
            asset_ids: vec![asset],
            event_ids: vec![],
            affected_hosts: vec![],
            first_seen_at: now,
            last_seen_at: now,
            assignee: None,
            case_id: None,
            escalation_level: 0,
            sla_due_at: None,
            sla_breached: false,
            tags: vec![],
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn dedup_key_normalizes_title() {
        let tenant = TenantId::default_tenant();
        let a = Alert::compute_dedup_key(tenant, Some(RiskDomain::PromptAttack), None, "  Attack  ");
        let b = Alert::compute_dedup_key(tenant, Some(RiskDomain::PromptAttack), None, "attack");
        assert_eq!(a, b);
    }

    #[test]
    fn dedup_key_changes_with_asset_and_domain() {
        let tenant = TenantId::default_tenant();
        let id1 = Id::new();
        let id2 = Id::new();
        let a = Alert::compute_dedup_key(tenant, Some(RiskDomain::PromptAttack), Some(&id1), "t");
        let b = Alert::compute_dedup_key(tenant, Some(RiskDomain::PromptAttack), Some(&id2), "t");
        let c = Alert::compute_dedup_key(tenant, Some(RiskDomain::RagPoison), Some(&id1), "t");
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn sla_seconds_by_severity_are_monotonic() {
        assert!(Alert::sla_secs(Severity::Critical) < Alert::sla_secs(Severity::High));
        assert!(Alert::sla_secs(Severity::High) < Alert::sla_secs(Severity::Medium));
        assert_eq!(Alert::sla_secs(Severity::Critical), 900);
    }

    #[test]
    fn sla_breach_detection() {
        let now = Timestamp::now();
        let mut a = alert();
        a.first_seen_at = now.offset_secs(-7_200);
        a.refresh_sla(now);
        assert!(a.sla_breached, "2 小时前的 high 告警应已超 SLA(1h)");
        assert!(a.sla_remaining_secs(now).unwrap_or(0) < 0);
        a.state = AlertState::Closed;
        a.refresh_sla(now);
        assert!(!a.sla_breached, "已关闭告警不再计 SLA 超时");
    }

    #[test]
    fn merge_occurrence_accumulates() {
        let now = Timestamp::now();
        let mut a = alert();
        let e1 = Id::new();
        let e2 = Id::new();
        a.merge_occurrence(now.offset_secs(30), &[e1, e2]);
        a.merge_occurrence(now.offset_secs(60), &[e2]);
        assert_eq!(a.dedup_count, 3);
        assert_eq!(a.event_ids.len(), 2, "事件 id 去重");
        assert!(a.last_seen_at.unix_secs() >= now.unix_secs() + 59);
    }

    #[test]
    fn active_state_matrix() {
        let mut a = alert();
        assert!(a.is_active());
        a.state = AlertState::Suppressed;
        assert!(!a.is_active());
        a.state = AlertState::Escalated;
        assert!(a.is_active());
    }

    #[test]
    fn maintenance_window_coverage() {
        let now = Timestamp::now();
        let asset = Id::new();
        let w = MaintenanceWindow {
            reason: "变更".into(),
            from: now.offset_secs(-600),
            to: now.offset_secs(600),
            asset_ids: vec![asset],
        };
        assert!(w.covers(now, Some(&asset)));
        assert!(!w.covers(now, Some(&Id::new())));
        assert!(!w.covers(now.offset_secs(1_000), Some(&asset)));
        let global = MaintenanceWindow { asset_ids: vec![], ..w };
        assert!(global.covers(now, None));
    }

    #[test]
    fn escalation_rule_triggers_after_delay() {
        let now = Timestamp::now();
        let mut a = alert();
        a.last_seen_at = now.offset_secs(-4_000);
        let rule = EscalationRule {
            id: Id::new(),
            tenant_id: TenantId::default_tenant(),
            name: "high-1h".into(),
            min_severity: Severity::High,
            after_secs: 3_600,
            notify_user_ids: vec![],
            channel_ids: vec![],
            level: 1,
            enabled: true,
            created_at: now,
        };
        assert!(rule.should_escalate(&a, now));
        a.escalation_level = 1;
        assert!(!rule.should_escalate(&a, now), "已升级到该层级不再重复");
        a.escalation_level = 0;
        a.severity = Severity::Medium;
        assert!(!rule.should_escalate(&a, now), "等级不足");
        a.severity = Severity::High;
        a.last_seen_at = now;
        assert!(!rule.should_escalate(&a, now), "未到延迟时间");
    }
}
