//! 对**真实 Oracle**（`AGF_E2E_ORACLE_DSN`）的端到端验证：连接（OCI）→ 真表取数 → 列类型解码
//! （NUMBER / TIMESTAMP / VARCHAR2 / NULL 三态）→ 游标增量（5 → +2 → 7，只推进到本批最后一行）。
//!
//! 为什么必须真机：方言 SQL（`:1` 占位符 / `CAST(col AS NUMBER)` / `"col"` 标识符 /
//! `OFFSET … FETCH NEXT`）、行 → JSON 的列解码、以及 `oracle` crate 与 **项目内 instantclient**
//! 的库加载**只有真的连上 Oracle 才可能被证伪**；离线单测只覆盖 SQL 文本、DSN 与解码决策表。
//!
//! 运行方式（Oracle 容器已在跑，instantclient 已解压在仓库内）：
//!
//! ```text
//! docker compose -f docker-compose.ingest-test.yml --profile oracle up -d --wait oracle
//! set AGF_E2E_ORACLE_DSN=oracle://agf:AgfTest2024@127.0.0.1:11521/FREEPDB1
//! set AGF_ORACLE_CLIENT_LIB_DIR=%CD%\tools\oracle\instantclient_23_5
//! cargo test -p agf-ingest --test oracle_live -- --ignored --nocapture
//! ```
//!
//! 未设置 `AGF_E2E_ORACLE_DSN` 时用例直接跳过（`#[ignore]` 保证常规 `cargo test` 不依赖任何外部服务）。
//!
//! 说明：本用例自己建表/插数（用 `oracle` crate 直连做 DDL/DML，与运行时驱动同一套 DSN 解析），
//! 因此"5 → +2 → 游标 7"是自洽可复现的。带 **PG Sink 行数**证据的整体验证走
//! `tools/simulators/run_oracle_e2e.ps1`（起真 agf-ingest 进程 + PostgreSQL 落库）。

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::sync::Arc;
use std::time::Duration;

use agf_core::enums::{HealthState, IngestProtocol};
use agf_core::ids::{Id, TenantId};
use agf_core::source::{CollectionMode, LogSource, SourceConnection};
use agf_core::time::Timestamp;
use agf_ingest::bus::NoopEventBus;
use agf_ingest::jdbc::{
    CursorType, JdbcReceiver, OracleConnectParams, SqlDialect, SqlPullConfig, connect_from_dsn, oracle_client_lib_dir,
    oracle_connect_params_from_dsn,
};
use agf_ingest::pipeline::{InMemorySink, IngestConfig, IngestPipeline, Sink};
use agf_ingest::registry::ParserRegistry;

/// 被测 Oracle 的 DSN（如 `oracle://agf:AgfTest2024@127.0.0.1:11521/FREEPDB1`）。
const ENV_DSN: &str = "AGF_E2E_ORACLE_DSN";

/// OCI 运行库目录（默认仓库内 `tools/oracle/instantclient_23_5`，与驱动同一口径）。
const ENV_LIB_DIR: &str = "AGF_ORACLE_CLIENT_LIB_DIR";

/// 本用例专用的表名（每次先 DROP 再建，可重复跑）。
const TABLE: &str = "agf_oracle_e2e";

fn dsn() -> Option<String> {
    let value = std::env::var(ENV_DSN).ok()?.trim().to_string();
    (!value.is_empty()).then_some(value)
}

/// 直连（Admin 用途：建表/插数）。库目录口径与 [`agf_ingest::jdbc::OracleSource`] 完全一致。
fn admin_connect(dsn: &str) -> oracle::Connection {
    let params = oracle_connect_params_from_dsn(dsn).expect("DSN 应能解析（oracle://user:pass@host:port/service）");
    println!("DSN（脱敏）: {:?}", redacted(&params));
    if let Some(dir) = oracle_client_lib_dir(std::env::var(ENV_LIB_DIR).ok().as_deref()) {
        println!("OCI 运行库目录: {}", dir.display());
        let mut init = oracle::InitParams::new();
        init.oracle_client_lib_dir(&dir).unwrap().init().unwrap();
    }
    oracle::Connection::connect(params.user(), params.password(), params.connect_string())
        .expect("应能连上 Oracle（检查 AGF_ORACLE_CLIENT_LIB_DIR 与容器健康）")
}

/// 脱敏展示（**口令绝不打印**）。
fn redacted(params: &OracleConnectParams) -> String {
    format!("user={} password=*** connect_string={}", params.user(), params.connect_string())
}

fn log_source() -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "oracle-live".to_string(),
        protocol: IngestProtocol::Jdbc,
        vendor: "generic".to_string(),
        product: "json".to_string(),
        enabled: true,
        parser_id: None,
        connection: SourceConnection::default(),
        mode: CollectionMode::Pull,
        poll_interval_secs: Some(1),
        require_mtls: false,
        allowed_cidrs: vec![],
        max_message_bytes: 1_048_576,
        max_eps: 0,
        tags: vec![],
        health: HealthState::Healthy,
        last_event_at: None,
        total_events: 0,
        last_error: None,
        created_at: now,
        updated_at: now,
    }
}

fn pipeline_and_sink() -> (Arc<IngestPipeline>, Arc<InMemorySink>) {
    let sink = Arc::new(InMemorySink::new());
    let pipeline = IngestPipeline::new(
        ParserRegistry::with_builtins(),
        Arc::clone(&sink) as Arc<dyn Sink>,
        Arc::new(NoopEventBus),
        IngestConfig { emit_to_bus: false, ..IngestConfig::default() },
    );
    (Arc::new(pipeline), sink)
}

/// 建表 + 插 5 行（id=1..4 带全部列值，id=5 的 message/detail/ts 为 NULL —— 用同一张表验三态）。
fn seed(conn: &oracle::Connection) {
    // 表名/列名都按 Oracle 默认（未加引号 ⇒ 大写）；查询侧用 `AS "id"` 之类的**带引号别名**
    // 把列名固定成小写（这是 Oracle 的常规做法，见 crates/agf-ingest/src/jdbc.rs 的文档）
    for ddl in [
        format!("BEGIN EXECUTE IMMEDIATE 'DROP TABLE {TABLE}'; EXCEPTION WHEN OTHERS THEN NULL; END;"),
        format!(
            "CREATE TABLE {TABLE} (id NUMBER(10) PRIMARY KEY, ts TIMESTAMP, amount NUMBER(10, 2), \
             message VARCHAR2(400), detail CLOB)"
        ),
    ] {
        conn.execute(&ddl, &[]).unwrap_or_else(|e| panic!("DDL 失败: {e}\n{ddl}"));
    }
    let insert = format!(
        "INSERT INTO {TABLE} (id, ts, amount, message, detail) VALUES \
         (:1, TIMESTAMP '2026-02-21 10:23:45.123', :2, :3, :4)"
    );
    for id in 1..=4_i32 {
        let amount = 10.5_f64 + f64::from(id);
        conn.execute(
            &insert,
            &[&id, &amount, &format!("audit event {id} from 203.0.113.{id}"), &format!("detail {id}")],
        )
        .unwrap_or_else(|e| panic!("INSERT 失败: {e}"));
    }
    // 第 5 行：时间/文本/大对象全 NULL（NULL 三态的真机证据）
    let nulls = format!("INSERT INTO {TABLE} (id, ts, amount, message, detail) VALUES (:1, NULL, NULL, NULL, NULL)");
    conn.execute(&nulls, &[&5_i32]).unwrap_or_else(|e| panic!("INSERT NULL 失败: {e}"));
    // OCI 默认**不自动提交**：拉取侧是另一条连接，必须显式 commit 才看得见
    conn.commit().unwrap_or_else(|e| panic!("COMMIT 失败: {e}"));
    let count: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {TABLE}"), &[]).unwrap().get(0).unwrap();
    println!("表 {TABLE} 现有行数 = {count}");
}

#[tokio::test]
#[ignore = "真机用例：需要真实 Oracle（AGF_E2E_ORACLE_DSN）与仓库内 instantclient"]
async fn oracle_live_pull_is_incremental_and_decodes_column_types() {
    let Some(dsn) = dsn() else {
        println!("跳过：未设置 {ENV_DSN}");
        return;
    };
    let admin = admin_connect(&dsn);
    seed(&admin);

    // ---- 1. 按 DSN 自动选驱动（不再是 NotImplemented/Config 报错）----
    let source = connect_from_dsn(&dsn, 4).await.expect("oracle:// 应能连上并选定驱动");
    assert_eq!(source.dialect(), SqlDialect::Oracle);
    println!("驱动描述: {}", source.describe());

    // ---- 2. 列类型解码（真机）----
    let probe = format!(
        r#"SELECT id AS "id", ts AS "ts", amount AS "amount", message AS "message", detail AS "detail" FROM {TABLE} WHERE id = 1"#
    );
    let rows = source.fetch_rows(&probe, None).await.expect("探测查询应成功");
    assert_eq!(rows.len(), 1, "{rows:?}");
    println!("行 JSON（第 1 行）: {}", rows[0]);
    let json: serde_json::Value = serde_json::from_str(&rows[0]).expect("行必须是合法 JSON");
    assert_eq!(json.get("id"), Some(&serde_json::Value::from(1)), "NUMBER(10) ⇒ 数字：{json}");
    assert_eq!(json.get("amount"), Some(&serde_json::Value::from(11.5_f64)), "NUMBER(10,2) ⇒ f64：{json}");
    assert_eq!(
        json.get("ts"),
        Some(&serde_json::Value::from("2026-02-21T10:23:45.123Z")),
        "TIMESTAMP ⇒ ISO-8601 毫秒 + Z（与 SQL 侧 TO_CHAR 格式同形）：{json}"
    );
    assert_eq!(
        json.get("message"),
        Some(&serde_json::Value::from("audit event 1 from 203.0.113.1")),
        "VARCHAR2 ⇒ 字符串：{json}"
    );
    assert_eq!(json.get("detail"), Some(&serde_json::Value::from("detail 1")), "CLOB ⇒ 字符串：{json}");

    // NULL 三态：SQL NULL ⇒ JSON null（不是 `<undecodable:...>`，也不是丢列）
    let null_rows = source
        .fetch_rows(
            &format!(r#"SELECT ts AS "ts", amount AS "amount", message AS "message" FROM {TABLE} WHERE id = 5"#),
            None,
        )
        .await
        .expect("NULL 探测查询应成功");
    println!("行 JSON（NULL 行）: {}", null_rows[0]);
    let null_json: serde_json::Value = serde_json::from_str(&null_rows[0]).expect("行必须是合法 JSON");
    for key in ["ts", "amount", "message"] {
        assert_eq!(null_json.get(key), Some(&serde_json::Value::Null), "{key} 必须是 JSON null：{null_json}");
    }

    // ---- 3. 游标增量：5 → +2 → 7（与 PostgreSQL/MySQL/MSSQL 同一份游标实现）----
    let config = SqlPullConfig {
        sql: format!(r#"SELECT id AS "id", ts AS "ts", message AS "message" FROM {TABLE}"#),
        cursor_field: Some("id".to_string()),
        cursor_type: CursorType::Int,
        batch_limit: 500,
        interval_secs: 1,
        cursor_path: None,
    };
    let receiver = JdbcReceiver::new(Arc::clone(&source), config);
    let (pipeline, sink) = pipeline_and_sink();
    let log_source = log_source();
    println!("预览 SQL（首轮，无游标）: {}", receiver.preview_sql().unwrap());

    let first = receiver.pull_once(&pipeline, &log_source, 500).await.expect("首轮拉取应成功");
    println!("首轮: rows={} persisted={}", first.rows, first.persisted);
    assert_eq!((first.rows, first.persisted), (5, 5), "首轮 5 行 ⇒ 5 条事件");
    assert_eq!(receiver.cursor().as_deref(), Some("5"), "游标推进到本批最后一行");
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.unwrap(), 5);

    // 再插 2 行（id 6/7）⇒ 只应拉到新增的 2 行
    let insert = format!(
        "INSERT INTO {TABLE} (id, ts, amount, message) VALUES (:1, TIMESTAMP '2026-02-21 10:24:00.456', :2, :3)"
    );
    for id in 6..=7_i32 {
        admin
            .execute(&insert, &[&id, &(20.0_f64 + f64::from(id)), &format!("audit event {id}")])
            .unwrap_or_else(|e| panic!("追加 INSERT 失败: {e}"));
    }
    admin.commit().unwrap_or_else(|e| panic!("COMMIT 失败: {e}"));
    println!("追加 2 行（id=6,7）后重跑一轮 …");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let second = receiver.pull_once(&pipeline, &log_source, 500).await.expect("第二轮拉取应成功");
    println!("第二轮: rows={} persisted={}", second.rows, second.persisted);
    assert_eq!((second.rows, second.persisted), (2, 2), "只应拉到新增的 2 行（**不重不漏**）");
    assert_eq!(receiver.cursor().as_deref(), Some("7"), "游标必须前进到 7");
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.unwrap(), 7, "5 + 2 恰好 7 条事件");

    // 第三轮无新行
    let third = receiver.pull_once(&pipeline, &log_source, 500).await.expect("第三轮拉取应成功");
    assert_eq!(third.rows, 0, "无新行时不再拉取");
    assert_eq!(receiver.cursor().as_deref(), Some("7"), "无新行时游标不动");
    println!("断言通过：Oracle 真机 5 → +2 → 7 条事件、游标 \"5\" → \"7\"（增量只认新行）");
}
