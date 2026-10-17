//! 授权（RBAC + ABAC + 租户隔离），§4.7。
//!
//! ## 判定顺序（短路，安全优先）
//!
//! 1. **租户隔离**：请求租户 ≠ 资源租户且非超管 → [`DomainError::TenantViolation`]（不可被任何角色绕过）；
//! 2. **超管短路**：`is_superadmin` → 放行（但仍记录审计）；
//! 3. **RBAC**：角色 → 权限点集合，支持 `assets:*` 与 `*` 通配；
//! 4. **ABAC**：绑定上的条件（部门、数据分级、来源网段）必须全部满足；
//! 5. **只读判定**：供前端裁剪 UI（不参与放行与否）。
//!
//! 设计原则：**默认拒绝**。任何步骤缺少信息都视为不满足条件。

use std::collections::{BTreeMap, BTreeSet};

use agf_core::enums::DataClass;
use agf_core::error::{DomainError, DomainResult};
use agf_core::ids::{Id, TenantId};
use agf_core::rbac::{AbacCondition, AccessRequest, EffectivePermissions, Permission, Role, RoleBinding, builtin};
use ipnet::IpNet;

/// 授权器：持有角色与绑定快照（由 `agf-storage` 加载，允许缓存）。
#[derive(Debug, Clone, Default)]
pub struct Authorizer {
    roles: BTreeMap<String, Role>,
    bindings: Vec<RoleBinding>,
}

impl Authorizer {
    /// 空授权器（无任何权限，默认拒绝）。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 由角色与绑定构造。
    #[must_use]
    pub fn from_parts(roles: Vec<Role>, bindings: Vec<RoleBinding>) -> Self {
        let roles = roles.into_iter().map(|r| (r.name.clone(), r)).collect();
        Self { roles, bindings }
    }

    /// 注册/覆盖角色。
    pub fn upsert_role(&mut self, role: Role) {
        self.roles.insert(role.name.clone(), role);
    }

    /// 覆盖绑定集合。
    pub fn set_bindings(&mut self, bindings: Vec<RoleBinding>) {
        self.bindings = bindings;
    }

    /// 角色是否已加载。
    #[must_use]
    pub fn has_role(&self, name: &str) -> bool {
        self.roles.contains_key(name)
    }

    /// 计算某主体的有效权限集合。
    ///
    /// `role_names`：主体直接携带的角色名（来自 JWT）；
    /// `bindings` 中匹配 `subject_id` 的绑定会额外贡献角色与 ABAC 条件。
    #[must_use]
    pub fn effective_permissions(
        &self,
        subject_id: Option<Id>,
        role_names: &[String],
        is_superadmin: bool,
        request: Option<&AccessRequest>,
    ) -> EffectivePermissions {
        let mut perms: BTreeSet<Permission> = BTreeSet::new();
        let mut any_write = is_superadmin;
        if is_superadmin {
            perms.insert(Permission::from_raw("*"));
        }

        // 1) JWT 携带的角色（无 ABAC 条件，视为全局角色）
        for name in role_names {
            if let Some(role) = self.roles.get(name) {
                for p in &role.permissions {
                    perms.insert(p.clone());
                    if !is_read_only_permission(p) {
                        any_write = true;
                    }
                }
            }
        }

        // 2) 数据库绑定（带 ABAC 条件与有效期）
        if let Some(sid) = subject_id {
            for b in self.bindings.iter().filter(|b| b.subject_id == sid && b.is_effective()) {
                if !self.abac_satisfied(&b.condition, request) {
                    continue;
                }
                if let Some(role) = self.roles.values().find(|r| r.id == b.role_id) {
                    for p in &role.permissions {
                        perms.insert(p.clone());
                        if !is_read_only_permission(p) {
                            any_write = true;
                        }
                    }
                }
            }
        }

        EffectivePermissions { permissions: perms, superadmin: is_superadmin, read_only: !any_write }
    }

    /// 执行一次访问判定。
    ///
    /// # Errors
    /// - 跨租户访问 → [`DomainError::TenantViolation`]；
    /// - 权限不足 → [`DomainError::Forbidden`]。
    pub fn authorize(
        &self,
        subject_id: Option<Id>,
        role_names: &[String],
        is_superadmin: bool,
        request: &AccessRequest,
        actor_tenant: TenantId,
    ) -> DomainResult<()> {
        // 步骤 1：租户隔离（超管可跨租户，但仍受权限点约束）
        if actor_tenant != request.resource_tenant && !is_superadmin {
            return Err(DomainError::TenantViolation {
                tenant: actor_tenant.to_string(),
                resource: format!("tenant:{} permission:{}", request.resource_tenant, request.permission),
            });
        }
        // 步骤 2-4：RBAC + ABAC
        let effective = self.effective_permissions(subject_id, role_names, is_superadmin, Some(request));
        if effective.allows(&request.permission) {
            return Ok(());
        }
        Err(DomainError::Forbidden(format!(
            "缺少权限 {}（角色: {}）",
            request.permission,
            if role_names.is_empty() { "无".to_string() } else { role_names.join(",") }
        )))
    }

    /// 判定 ABAC 条件是否满足。
    ///
    /// 语义：条件中**非空**的维度必须与请求匹配；空维度表示不限制。
    /// 条件本身为空（`is_unconstrained`）时放行。
    #[must_use]
    pub fn abac_satisfied(&self, condition: &AbacCondition, request: Option<&AccessRequest>) -> bool {
        if condition.is_unconstrained() {
            return true;
        }
        let Some(req) = request else {
            // 有条件但请求未提供上下文 → 保守拒绝
            return false;
        };
        if !condition.departments.is_empty() {
            match &req.department {
                Some(d) if condition.departments.iter().any(|x| x == d) => {}
                _ => return false,
            }
        }
        if !condition.data_classes.is_empty() {
            match req.data_class {
                Some(dc) if condition.data_classes.contains(&dc) => {}
                _ => return false,
            }
        }
        if !condition.source_cidrs.is_empty() {
            match &req.source_ip {
                Some(ip) if cidr_matches_any(&condition.source_cidrs, ip) => {}
                _ => return false,
            }
        }
        true
    }

    /// 内置角色是否满足"最小权限"体检（用于自检页提示过度授权）。
    #[must_use]
    pub fn overprivileged_roles(&self) -> Vec<String> {
        self.roles
            .values()
            .filter(|r| {
                r.permissions.iter().any(|p| p.as_str() == "*")
                    || r.permissions.iter().any(|p| p.as_str().ends_with(":admin"))
            })
            .map(|r| r.name.clone())
            .collect()
    }

    /// 内置角色定义表（用于首次播种对照检查）。
    #[must_use]
    pub fn builtin_role_names() -> Vec<&'static str> {
        vec![
            builtin::SUPERADMIN,
            builtin::TENANT_ADMIN,
            builtin::SOC_ANALYST,
            builtin::REDTEAM_ENGINEER,
            builtin::AUDITOR,
            builtin::VIEWER,
            builtin::ASSET_OWNER,
        ]
    }
}

/// 判断权限点是否"只读"（用于 UI 裁剪）。
fn is_read_only_permission(p: &Permission) -> bool {
    let s = p.as_str();
    s.ends_with(":read") || s.ends_with(":export")
}

/// 判断 IP 是否落在任一 CIDR 内。
#[must_use]
pub fn cidr_matches_any(cidrs: &[String], ip: &str) -> bool {
    let Ok(addr) = ip.parse::<std::net::IpAddr>() else { return false };
    cidrs.iter().any(|c| c.parse::<IpNet>().is_ok_and(|net| net.contains(&addr)))
}

/// 判断数据分级是否在允许范围内（数据不出域约束）。
#[must_use]
pub fn data_class_allowed(ceiling: DataClass, requested: DataClass) -> bool {
    requested <= ceiling
}

#[cfg(test)]
mod tests {
    use super::*;
    use agf_core::rbac::{Permission, SubjectKind};
    use agf_core::time::Timestamp;

    fn role(name: &str, perms: &[&str]) -> Role {
        Role {
            id: Id::new(),
            tenant_id: TenantId::default_tenant(),
            name: name.to_string(),
            display_name: name.to_string(),
            description: String::new(),
            permissions: perms.iter().map(|p| Permission::from_raw(*p)).collect(),
            builtin: false,
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
        }
    }

    fn binding(subject: Id, role_id: Id, condition: AbacCondition) -> RoleBinding {
        RoleBinding {
            id: Id::new(),
            tenant_id: TenantId::default_tenant(),
            subject_id: subject,
            subject_kind: SubjectKind::User,
            role_id,
            condition,
            granted_at: Timestamp::now(),
            expires_at: None,
            granted_by: None,
        }
    }

    fn req(permission: &str, tenant: TenantId) -> AccessRequest {
        AccessRequest {
            permission: Permission::from_raw(permission),
            resource_tenant: tenant,
            data_class: None,
            department: None,
            source_ip: None,
        }
    }

    #[test]
    fn default_deny_when_no_roles_loaded() {
        let a = Authorizer::new();
        let t = TenantId::default_tenant();
        let res = a.authorize(None, &[], false, &req("assets:read", t), t);
        assert!(res.is_err());
        assert!(matches!(res.err(), Some(DomainError::Forbidden(_))));
    }

    #[test]
    fn wildcard_and_superadmin_permissions_are_not_read_only() {
        let authorizer = Authorizer::from_parts(
            vec![role("all", &["*"]), role("group", &["assets:*"]), role("read", &["assets:read", "reports:export"])],
            vec![],
        );
        for name in ["all", "group"] {
            assert!(!authorizer.effective_permissions(None, &[name.into()], false, None).read_only);
        }
        assert!(authorizer.effective_permissions(None, &["read".into()], false, None).read_only);
        let superadmin = Authorizer::new().effective_permissions(None, &[], true, None);
        assert!(!superadmin.read_only);
        assert!(superadmin.permissions.contains(&Permission::from_raw("*")));
    }

    #[test]
    fn role_permission_grants_access() {
        let a = Authorizer::from_parts(vec![role("soc", &["alerts:read", "cases:write"])], vec![]);
        let t = TenantId::default_tenant();
        assert!(a.authorize(None, &["soc".to_string()], false, &req("alerts:read", t), t).is_ok());
        assert!(a.authorize(None, &["soc".to_string()], false, &req("assets:read", t), t).is_err());
    }

    #[test]
    fn wildcard_permission_grants_group() {
        let a = Authorizer::from_parts(vec![role("admin", &["assets:*"])], vec![]);
        let t = TenantId::default_tenant();
        assert!(a.authorize(None, &["admin".to_string()], false, &req("assets:delete", t), t).is_ok());
        assert!(a.authorize(None, &["admin".to_string()], false, &req("cases:read", t), t).is_err());
    }

    #[test]
    fn tenant_isolation_cannot_be_bypassed_by_roles() {
        let a = Authorizer::from_parts(vec![role("all", &["*"])], vec![]);
        let other = TenantId::new();
        let mine = TenantId::default_tenant();
        let res = a.authorize(None, &["all".to_string()], false, &req("assets:read", other), mine);
        assert!(matches!(res.err(), Some(DomainError::TenantViolation { .. })));
    }

    #[test]
    fn superadmin_can_cross_tenant() {
        let a = Authorizer::from_parts(vec![role("all", &["*"])], vec![]);
        let other = TenantId::new();
        let mine = TenantId::default_tenant();
        assert!(a.authorize(None, &["all".to_string()], true, &req("assets:read", other), mine).is_ok());
    }

    #[test]
    fn binding_abac_department_restriction() {
        let r = role("owner", &["assets:write"]);
        let subject = Id::new();
        let b =
            binding(subject, r.id, AbacCondition { departments: vec!["研发".to_string()], ..AbacCondition::default() });
        let a = Authorizer::from_parts(vec![r], vec![b]);
        let t = TenantId::default_tenant();

        let mut ok_req = req("assets:write", t);
        ok_req.department = Some("研发".to_string());
        assert!(a.authorize(Some(subject), &[], false, &ok_req, t).is_ok());

        let mut bad_req = req("assets:write", t);
        bad_req.department = Some("市场".to_string());
        assert!(a.authorize(Some(subject), &[], false, &bad_req, t).is_err());

        let mut missing_req = req("assets:write", t);
        missing_req.department = None;
        assert!(a.authorize(Some(subject), &[], false, &missing_req, t).is_err(), "缺少部门信息应保守拒绝");
    }

    #[test]
    fn binding_abac_data_class_restriction() {
        let r = role("restricted-reader", &["findings:read"]);
        let subject = Id::new();
        let b = binding(
            subject,
            r.id,
            AbacCondition { data_classes: vec![DataClass::Internal, DataClass::Public], ..AbacCondition::default() },
        );
        let a = Authorizer::from_parts(vec![r], vec![b]);
        let t = TenantId::default_tenant();
        let mut r1 = req("findings:read", t);
        r1.data_class = Some(DataClass::Internal);
        assert!(a.authorize(Some(subject), &[], false, &r1, t).is_ok());
        let mut r2 = req("findings:read", t);
        r2.data_class = Some(DataClass::Restricted);
        assert!(a.authorize(Some(subject), &[], false, &r2, t).is_err());
    }

    #[test]
    fn binding_abac_cidr_restriction() {
        let r = role("soc", &["alerts:read"]);
        let subject = Id::new();
        let b = binding(
            subject,
            r.id,
            AbacCondition { source_cidrs: vec!["10.0.0.0/8".to_string()], ..AbacCondition::default() },
        );
        let a = Authorizer::from_parts(vec![r], vec![b]);
        let t = TenantId::default_tenant();
        let mut inside = req("alerts:read", t);
        inside.source_ip = Some("10.1.2.3".to_string());
        assert!(a.authorize(Some(subject), &[], false, &inside, t).is_ok());
        let mut outside = req("alerts:read", t);
        outside.source_ip = Some("192.168.1.1".to_string());
        assert!(a.authorize(Some(subject), &[], false, &outside, t).is_err());
    }

    #[test]
    fn expired_binding_is_ignored() {
        let r = role("temp", &["assets:read"]);
        let subject = Id::new();
        let mut b = binding(subject, r.id, AbacCondition::default());
        b.expires_at = Some(Timestamp::now().offset_secs(-60));
        let a = Authorizer::from_parts(vec![r], vec![b]);
        let t = TenantId::default_tenant();
        assert!(a.authorize(Some(subject), &[], false, &req("assets:read", t), t).is_err());
    }

    #[test]
    fn read_only_flag_computed() {
        let a = Authorizer::from_parts(vec![role("viewer", &["assets:read", "findings:read"])], vec![]);
        let ep = a.effective_permissions(None, &["viewer".to_string()], false, None);
        assert!(ep.read_only);
        assert!(ep.permissions.contains(&Permission::from_raw("assets:read")));

        let a2 = Authorizer::from_parts(vec![role("op", &["assets:read", "assets:write"])], vec![]);
        let ep2 = a2.effective_permissions(None, &["op".to_string()], false, None);
        assert!(!ep2.read_only);
    }

    #[test]
    fn unconstrained_abac_always_satisfied() {
        let a = Authorizer::new();
        assert!(a.abac_satisfied(&AbacCondition::default(), None));
        let constrained = AbacCondition { departments: vec!["x".into()], ..AbacCondition::default() };
        assert!(!a.abac_satisfied(&constrained, None), "有条件但无上下文应拒绝");
    }

    #[test]
    fn cidr_matching_helper() {
        let nets = vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()];
        assert!(cidr_matches_any(&nets, "10.255.255.255"));
        assert!(cidr_matches_any(&nets, "192.168.1.1"));
        assert!(!cidr_matches_any(&nets, "172.16.0.1"));
        assert!(!cidr_matches_any(&nets, "not-an-ip"));
        assert!(!cidr_matches_any(&[], "10.0.0.1"));
    }

    #[test]
    fn data_class_ceiling() {
        assert!(data_class_allowed(DataClass::Restricted, DataClass::Internal));
        assert!(!data_class_allowed(DataClass::Internal, DataClass::Restricted));
    }

    #[test]
    fn overprivileged_detection() {
        let a = Authorizer::from_parts(
            vec![role("super", &["*"]), role("ops", &["platform:admin"]), role("viewer", &["assets:read"])],
            vec![],
        );
        let mut names = a.overprivileged_roles();
        names.sort();
        assert_eq!(names, vec!["ops".to_string(), "super".to_string()]);
    }

    #[test]
    fn builtin_roles_are_registered_when_provided() {
        let defs = Role::builtin_definitions();
        let roles: Vec<Role> = defs
            .iter()
            .map(|(name, display, desc, perms)| Role {
                id: Id::new(),
                tenant_id: TenantId::default_tenant(),
                name: (*name).to_string(),
                display_name: (*display).to_string(),
                description: (*desc).to_string(),
                permissions: perms.iter().map(|p| Permission::from_raw(*p)).collect(),
                builtin: true,
                created_at: Timestamp::now(),
                updated_at: Timestamp::now(),
            })
            .collect();
        let a = Authorizer::from_parts(roles, vec![]);
        for name in Authorizer::builtin_role_names() {
            assert!(a.has_role(name), "内置角色 {name} 未注册");
        }
        let t = TenantId::default_tenant();
        assert!(a.authorize(None, &[builtin::SUPERADMIN.to_string()], false, &req("platform:admin", t), t).is_ok());
        assert!(a.authorize(None, &[builtin::VIEWER.to_string()], false, &req("assets:write", t), t).is_err());
    }
}
