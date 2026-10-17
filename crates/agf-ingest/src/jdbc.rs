//! SQL 拉取接收器（"JDBC" 语义）：从数据库表**按游标列增量拉取**日志行。
//!
//! ## 为什么不叫"JDBC 驱动"
//!
//! Rust 侧没有统一的 JDBC 实现（JDBC 是 Java API），平台落地方式是**按数据库接原生驱动**。
//! 本接收器用 `sqlx`（workspace 已声明）实现 **PostgreSQL 与 MySQL** 拉取、
//! 用 `tiberius`（纯 Rust，TDS）实现 **MSSQL** 拉取、
//! 用 `oracle`（rust-oracle / ODPI-C，OCI）实现 **Oracle** 拉取，
//! 驱动由 `AGF_INGEST_SQL_DSN` 的 scheme 自动选择（`postgres://` ⇒ PostgreSQL，
//! `mysql://` ⇒ MySQL，`mssql://`/`sqlserver://` ⇒ MSSQL，
//! `oracle://`/`oracle+tcps://` ⇒ Oracle）。
//!
//! ## 一份增量逻辑、四套方言（这是本模块的关键结构）
//!
//! **游标/分页/落盘/幂等**全部只有一份实现（[`JdbcReceiver`]），数据库差异被压缩成
//! 两条边界：
//!
//! 1. [`SqlDialect`]：占位符（`$1` / `?` / `@P1` / `:1`）、游标转型（`::bigint` /
//!    `CAST(x AS signed)` / `CAST(x AS bigint)` / `CAST(x AS NUMBER)`）、
//!    标识符引号（`"col"` / `` `col` `` / `[col]`）、"行 → JSON"的落地方式；
//! 2. [`SqlSource`]：唯一的数据库交互点（`fetch_rows`），`PgSqlSource` / `MySqlSource` /
//!    `MsSqlSource` / `OracleSource` 各实现一次，**其余代码一行不用改**。
//!
//! 主键列（`id`）的游标与 `int` 游标类型完全一致，因此**接新库不改游标语义**。
//!
//! ## 增量语义（这是接收器真正负责的部分）
//!
//! 操作方只写"基础查询"（如 `SELECT id, ts, message FROM audit_log`），
//! 接收器负责拼出**带游标谓词、排序、上限**的拉取语句：
//!
//! ```sql
//! -- PostgreSQL
//! SELECT row_to_json(t)::text FROM ( SELECT id, ts, message FROM audit_log ) t
//!   WHERE ("id")::bigint > $1::bigint
//!   ORDER BY ("id")::bigint ASC
//!   LIMIT 500
//!
//! -- MySQL（无 row_to_json，拉原始列后由 MySqlSource 按列元数据解码为 JSON 行；无 :: 转型运算符）
//! SELECT * FROM ( SELECT id, ts, message FROM audit_log ) t
//!   WHERE CAST(`id` AS signed) > CAST(? AS signed)
//!   ORDER BY CAST(`id` AS signed) ASC
//!   LIMIT 500
//!
//! -- MSSQL（无 row_to_json / 无 LIMIT：用 OFFSET…FETCH；无游标谓词时改用 TOP (n)）
//! SELECT * FROM ( SELECT id, ts, message FROM audit_log ) t
//!   WHERE CAST([id] AS bigint) > CAST(@P1 AS bigint)
//!   ORDER BY CAST([id] AS bigint) ASC
//!   OFFSET 0 ROWS FETCH NEXT 500 ROWS ONLY
//!
//! -- Oracle（12c+ 行限制子句；无游标谓词时用 FETCH FIRST，因为 OFFSET 强制要求 ORDER BY）
//! SELECT * FROM ( SELECT id, ts, message FROM audit_log ) t
//!   WHERE CAST("id" AS NUMBER) > CAST(:1 AS NUMBER)
//!   ORDER BY CAST("id" AS NUMBER) ASC
//!   OFFSET 0 ROWS FETCH NEXT 500 ROWS ONLY
//! ```
//!
//! * **游标列**（`cursor_field`）与**游标类型**（`cursor_type` = `int` / `timestamptz` / `text`）
//!   都由配置给出，接收器**只做标识符校验后加引号**（拒绝 `;`、引号、空白等），避免配置面注入；
//! * **游标持久化**：拉到哪一行的游标值就落盘（`cursor_path`，原子写）；
//!   进程重启从磁盘恢复，**不重复拉取**；
//! * **batch 上限**：`LIMIT` 由接收器附加，单轮最多 `batch_limit` 行；游标只推进到**本批最后一行**，
//!   因此不会跳过中间数据；
//! * 行 → 事件的映射：整行渲染为 JSON（PostgreSQL 用 `row_to_json`；MySQL 按列类型解码），
//!   JSON 的每个字段都保真进入解析流水线。
//!
//! ## 配置（环境变量见 `apps/ingest` 模块文档）
//!
//! | 字段 | 环境变量 | 默认 |
//! |---|---|---|
//! | DSN | `AGF_INGEST_SQL_DSN` | 空（未配置 ⇒ 接收器不启停）；scheme 决定驱动 |
//! | 基础 SQL | `AGF_INGEST_SQL_QUERY` | 空（必填） |
//! | 游标列 | `AGF_INGEST_SQL_CURSOR_FIELD` | 空（空 = 全量拉取，不做增量） |
//! | 游标类型 | `AGF_INGEST_SQL_CURSOR_TYPE` | `int`（MySQL 的 `timestamptz` 映射到 `CAST(... AS datetime)`，MSSQL 映射到 `CAST(... AS datetime2)`，Oracle 映射到 `TO_CHAR(..., 'YYYY-MM-DD"T"HH24:MI:SS.FF3"Z"')` 归一） |
//! | 单轮上限 | `AGF_INGEST_SQL_BATCH_LIMIT` | 500 |
//! | 间隔 | `AGF_INGEST_SQL_INTERVAL_SECS` | 60 |
//! | 游标文件 | `AGF_INGEST_SQL_CURSOR_PATH` | `data/ingest/sql-pull-cursor.json` |
//! | Oracle 客户端库目录 | `AGF_ORACLE_CLIENT_LIB_DIR` | 仓库内 `tools/oracle/instantclient_23_5`（仅 `oracle://` 用；**不写全局 PATH**） |
//!
//! ## 未实现 / 取舍（如实标注）
//!
//! * **Oracle 的构建期代价**：OCI 是 **C 运行库**，`oracle` crate 在构建期用 `cc` 编译随包分发的
//!   ODPI-C（**需要 C 编译器**，与仓库其余"纯 Rust"依赖不同；**不需要** Oracle SDK 头文件，
//!   OCI 在运行期动态加载）。运行期需要 Instant Client，本项目把它放在仓库内
//!   `tools/oracle/instantclient_23_5/`，由 [`ORACLE_CLIENT_LIB_DIR_ENV`] 指给驱动 ——
//!   **不污染 `D:\Environment`、不改全局 `PATH`**。OCI 缺失/连接失败**只 warn**，
//!   进程照常启动，`/readyz` notes 如实写明（该接收器不启用）。
//! * **Oracle 标识符大小写**：未加引号的 Oracle 标识符折叠为**大写**，而本方言按配置原样加双引号
//!   ⇒ 基础 SQL 请用 `SELECT id AS "id", ts AS "ts", message FROM audit_log` 这种**带引号的别名**
//!   固定列名，并配 `cursor_field=id`；否则谓词里的 `"id"` 会直接 ORA-00904（显式报错，不静默）。
//! * **Oracle 的连接数**：OCI 句柄是单连接（不是连接池），`AGF_INGEST_SQL_MAX_CONNECTIONS`
//!   对它不适用（PostgreSQL/MySQL 生效）；阻塞调用一律走 `spawn_blocking`（见 [`OracleSource`]）。
//! * **MSSQL 的连接数**：`tiberius::Client` 是单连接句柄（不是连接池），
//!   `AGF_INGEST_SQL_MAX_CONNECTIONS` 对它不生效（PostgreSQL/MySQL 生效）；见 [`MsSqlSource`]。
//! * **连接失败**：`/readyz` 照常 ready，接收器只 warn 并下一轮重试（进程绝不起不来）。
//! * **Oracle 未覆盖的形态（本轮未做，明确列出）**：`REFCURSOR`/对象/集合列按字符串兜底；
//!   钱包（`?descriptor=` 可透传完整 TNS 描述符，但没有专用的 `config_dir` 环境变量）；
//!   数组批量取（`fetch_array_size`）用驱动默认值。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use agf_core::enums::IngestProtocol;
use agf_core::error::{DomainError, DomainResult};
use agf_core::source::LogSource;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, info, warn};

use crate::metrics::ReceiverCounters;
use crate::pipeline::IngestPipeline;
use crate::receiver::{Receiver, ReceiverDescriptor, ReceiverStatus};

mod config;
mod dialect;
mod metrics;
mod oracle;
mod oracle_cells;
mod receiver;
mod source;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_oracle;
#[cfg(test)]
mod tests_support;

pub use config::*;
pub use dialect::*;
pub use metrics::*;
pub use oracle::*;
pub use oracle_cells::*;
pub use receiver::*;
pub use source::*;
