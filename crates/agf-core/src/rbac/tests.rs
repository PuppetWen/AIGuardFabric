//! 由 `rbac.rs` 拆分：`wildcard_permission_matches_group` 等 9 个函数（纯搬移，逻辑不变）。

use crate::ids::{Id, TenantId};
use crate::time::Timestamp;

use super::*;

#[test]
pub(crate) fn wildcard_permission_matches_group() {
    let p = Permission::from_raw("assets:*");
    assert!(p.matches(&Permission::new("assets", "read")));
    assert!(p.matches(&Permission::new("assets", "delete")));
    assert!(!p.matches(&Permission::new("cases", "read")));
}

#[test]
pub(crate) fn global_wildcard_matches_everything() {
    let p = Permission::from_raw("*");
    assert!(p.matches(&Permission::new("anything", "read")));
}

#[test]
pub(crate) fn exact_permission_matches_only_itself() {
    let p = Permission::new("findings", "read");
    assert!(p.matches(&Permission::new("findings", "read")));
    assert!(!p.matches(&Permission::new("findings", "write")));
}

#[test]
pub(crate) fn builtin_roles_have_expected_shape() {
    let defs = Role::builtin_definitions();
    assert_eq!(defs.len(), 7);
    let superadmin = defs.iter().find(|d| d.0 == builtin::SUPERADMIN);
    assert_eq!(superadmin.map(|d| d.3), Some(&["*"][..]));
    for (name, display, desc, perms) in defs {
        assert!(!name.is_empty());
        assert!(!display.is_empty());
        assert!(!desc.is_empty());
        assert!(!perms.is_empty());
    }
}

#[test]
pub(crate) fn role_allows_uses_wildcards() {
    let role = Role {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "soc".into(),
        display_name: "SOC".into(),
        description: String::new(),
        permissions: vec![Permission::from_raw("alerts:*"), Permission::new("cases", "read")],
        builtin: false,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    };
    assert!(role.allows(&Permission::new("alerts", "write")));
    assert!(role.allows(&Permission::new("cases", "read")));
    assert!(!role.allows(&Permission::new("cases", "write")));
}

#[test]
pub(crate) fn abac_unconstrained_detection() {
    assert!(AbacCondition::default().is_unconstrained());
    let c = AbacCondition { departments: vec!["研发".into()], ..AbacCondition::default() };
    assert!(!c.is_unconstrained());
}

#[test]
pub(crate) fn role_binding_expiry() {
    let mut b = RoleBinding {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        subject_id: Id::new(),
        subject_kind: SubjectKind::User,
        role_id: Id::new(),
        condition: AbacCondition::default(),
        granted_at: Timestamp::now(),
        expires_at: None,
        granted_by: None,
    };
    assert!(b.is_effective());
    b.expires_at = Some(Timestamp::now().offset_secs(-1));
    assert!(!b.is_effective());
}

#[test]
pub(crate) fn effective_permissions_superadmin_short_circuit() {
    let mut ep = EffectivePermissions { superadmin: true, ..EffectivePermissions::default() };
    assert!(ep.allows(&Permission::new("platform", "admin")));
    ep.superadmin = false;
    assert!(!ep.allows(&Permission::new("platform", "admin")));
}

#[test]
pub(crate) fn resource_group_and_action_lists_are_complete() {
    assert_eq!(ResourceGroup::all().len(), 21);
    assert_eq!(Action::all().len(), 7);
    for g in ResourceGroup::all() {
        assert!(!g.as_str().is_empty());
    }
}
