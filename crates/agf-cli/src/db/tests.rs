//! 由 `db.rs` 拆分：`fallback` 等 13 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn fallback() -> PgTarget {
    PgTarget {
        host: "127.0.0.1".to_string(),
        port: 5432,
        database: "aiguardfabric".to_string(),
        user: "agf".to_string(),
        password: "fallback-secret".to_string(),
    }
}

#[test]
pub(crate) fn parse_full_dsn_overrides_every_field() {
    let t = PgTarget::parse("postgres://svc:pw@db.internal:6543/agf_prod", &fallback()).expect("解析");
    assert_eq!(t.host, "db.internal");
    assert_eq!(t.port, 6543);
    assert_eq!(t.database, "agf_prod");
    assert_eq!(t.user, "svc");
    assert_eq!(t.password, "pw");
    assert_eq!(t.dsn(), "postgres://svc:pw@db.internal:6543/agf_prod");
}

#[test]
pub(crate) fn parse_falls_back_for_missing_parts() {
    let t = PgTarget::parse("postgresql://10.0.0.5/otherdb", &fallback()).expect("解析");
    assert_eq!(t.host, "10.0.0.5");
    assert_eq!(t.port, 5432, "缺端口应回退");
    assert_eq!(t.user, "agf", "缺用户名应回退");
    assert_eq!(t.password, "fallback-secret", "缺口令应回退");
    assert_eq!(t.database, "otherdb");
}

#[test]
pub(crate) fn parse_rejects_bad_scheme_port_and_empty_database() {
    assert!(PgTarget::parse("mysql://u:p@h:3306/db", &fallback()).is_err());
    assert!(PgTarget::parse("postgres://u:p@h:notaport/db", &fallback()).is_err());
    let err = PgTarget::parse("postgres://u:p@h:5432/", &fallback());
    assert!(err.is_err(), "空库名必须被拒绝");
}

#[test]
pub(crate) fn parse_ignores_query_parameters() {
    let t = PgTarget::parse("postgres://u:p@h:5432/db?sslmode=require", &fallback()).expect("解析");
    assert_eq!(t.database, "db");
}

#[test]
pub(crate) fn debug_and_masked_never_leak_password() {
    let t = PgTarget::parse("postgres://u:SuperSecretPw@h:5432/db", &fallback()).expect("解析");
    let dbg = format!("{t:?}");
    assert!(!dbg.contains("SuperSecretPw"), "Debug 泄露口令: {dbg}");
    assert!(!t.masked().contains("SuperSecretPw"), "掩码泄露口令: {}", t.masked());
    assert!(t.dsn().contains("SuperSecretPw"), "真实 DSN 必须含口令（连接用）");
    assert!(t.masked().contains('*'));
}

#[test]
pub(crate) fn libpq_env_passes_connection_via_environment_not_argv() {
    let t = PgTarget::parse("postgres://u:p@h:5433/db", &fallback()).expect("解析");
    let env = t.libpq_env();
    let get = |k: &str| env.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
    assert_eq!(get("PGHOST").as_deref(), Some("h"));
    assert_eq!(get("PGPORT").as_deref(), Some("5433"));
    assert_eq!(get("PGDATABASE").as_deref(), Some("db"));
    assert_eq!(get("PGUSER").as_deref(), Some("u"));
    assert_eq!(get("PGPASSWORD").as_deref(), Some("p"));
    assert_eq!(get("PGCONNECT_TIMEOUT").as_deref(), Some("6"));
    // 空口令不应注入 PGPASSWORD（避免 pg_dump 用空串认证）
    let empty = PgTarget { password: String::new(), ..t };
    assert!(empty.libpq_env().iter().all(|(k, _)| k != "PGPASSWORD"));
}

#[test]
pub(crate) fn missing_tables_reports_only_absent_ones() {
    let expected = ["tenants", "users", "assets"];
    let present = vec!["tenants".to_string(), "assets".to_string(), "other".to_string()];
    assert_eq!(missing_tables(&expected, &present), vec!["users".to_string()]);
    assert_eq!(missing_tables(&expected, &[]).len(), 3);
    let all: Vec<String> = expected.iter().map(|s| (*s).to_string()).collect();
    assert!(missing_tables(&expected, &all).is_empty());
}

#[test]
pub(crate) fn required_table_list_is_used_and_nonempty() {
    assert!(REQUIRED_TABLES.len() >= 40, "§7 关键表清单应有 40+ 张，实际 {}", REQUIRED_TABLES.len());
    assert!(REQUIRED_TABLES.contains(&"tenants"));
    let missing = missing_tables(REQUIRED_TABLES, &["tenants".to_string()]);
    assert_eq!(missing.len(), REQUIRED_TABLES.len() - 1);
}

#[test]
pub(crate) fn schema_report_summary_and_completeness() {
    let ok = SchemaReport {
        target: "postgres://agf:****@127.0.0.1:5432/aiguardfabric".to_string(),
        server_version: "PostgreSQL 16".to_string(),
        rls_enabled_tables: 12,
        tenant_tables: 12,
        rls_unprotected: vec![],
        runtime_role_safe: true,
        present: 46,
        expected: 46,
        missing: vec![],
    };
    assert!(ok.is_complete());
    assert!(ok.summary_line().contains("通过"));
    let bad = SchemaReport { missing: vec!["users".to_string()], present: 45, ..ok.clone() };
    assert!(!bad.is_complete());
    assert!(bad.summary_line().contains("users"));
    let missing_rls = SchemaReport { rls_unprotected: vec!["assets".into()], ..ok.clone() };
    assert!(!missing_rls.is_complete());
    assert!(missing_rls.summary_line().contains("assets"));
    assert!(!SchemaReport { rls_enabled_tables: 11, ..ok.clone() }.is_complete());
    assert!(!SchemaReport { runtime_role_safe: false, ..ok }.is_complete());
}

#[test]
pub(crate) fn dependency_error_uses_exit_code_two_and_todo_anchor() {
    let err = dependency_error("PostgreSQL", "postgres://agf:***@h:5432/db", "connection refused");
    assert_eq!(err.exit_code(), 2, "外部依赖不可用必须是退出码 2");
    let msg = err.to_string();
    assert!(msg.contains("TODO(agfctl-pg-live)"), "必须带 TODO 锚点: {msg}");
    assert!(msg.contains("connection refused"));
}

#[test]
pub(crate) fn migrations_dir_defaults_to_documented_relative_path() {
    assert_eq!(resolve_migrations_dir(None), PathBuf::from(DEFAULT_MIGRATIONS_DIR));
    assert_eq!(resolve_migrations_dir(Some(Path::new("x/y"))), PathBuf::from("x/y"));
    assert!(!Path::new(DEFAULT_MIGRATIONS_DIR).is_absolute(), "默认迁移目录必须是相对路径（铁律 4）");
}

#[tokio::test]
pub(crate) async fn unresolved_pg_target_maps_to_exit_code_two() {
    // 指向一个必然拒绝连接的地址：本机 1 端口
    let target = PgTarget {
        host: "127.0.0.1".to_string(),
        port: 1,
        database: "nope".to_string(),
        user: "nope".to_string(),
        password: "nope".to_string(),
    };
    let err = connect(&target).await.expect_err("连接 127.0.0.1:1 必须失败");
    assert_eq!(err.exit_code(), 2, "PG 不可达必须映射为退出码 2: {err}");
    assert!(err.to_string().contains("不可达"));
}
