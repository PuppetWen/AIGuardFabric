#![forbid(unsafe_code)]
//! # agf-correlate — AIGuardFabric 关联分析（§4.6 / §4.7）
//!
//! 本 crate 负责把"单条事件/告警"升级为"可运营的结论"：跨源实体对齐 → 时序与基线关联
//! → 攻击链路还原 → 告警聚合抑制 → 案件闭环 → SLA 计时 → 通知派发 → SOAR-lite 处置。
//!
//! ## 模块状态（**如实登记，未实现项禁止假装可用**）
//!
//! | 模块 | 职责 | 状态 |
//! |---|---|---|
//! | [`entity`] | 跨源实体对齐（IP / 主机 / 用户 / Agent / 域名归一与别名） | ✅ 已实现 |
//! | [`temporal`] | 时序与序列关联（时间窗、序列模式、同源链路） | ✅ 已实现 |
//! | [`baseline`] | 基线偏离（按实体建立行为基线并计算偏离度） | ✅ 已实现 |
//! | [`aggregate`] | 告警聚合 / 去重 / 抑制 / 降噪率 | ✅ 已实现 |
//! | [`case`] | 案件闭环（升级、状态机、时间线、finding、合并/拆分） | ✅ 已实现 |
//! | [`sla`] | SLA 计时（三类目标、暂停计时、违约判定、升级阶梯） | ✅ 已实现 |
//! | [`notify`] | 通知渠道抽象 + Mock 渠道 + 派发器（去重/抑制/限流/重试/审计） | ✅ 已实现 |
//! | [`playbook`] | SOAR-lite 剧本（YAML 声明式 + 确定性执行器 + 轨迹） | ✅ 已实现 |
//!
//! ## 数据流
//!
//! ```text
//! Event ──entity──▶ 实体对齐键 ──temporal──▶ 关联命中
//!                          │
//!                          ├──baseline──▶ 基线偏离
//!                          ▼
//!                    aggregate ──▶ EventCluster（去重/抑制后的运营单元）
//!                          ▼
//!                      case ──▶ Case ──sla──▶ 违约/升级判定 ──▶ notify 派发
//!                                       └──▶ playbook 处置（动作全部经 trait 注入）
//! ```
//!
//! ## 降级行为
//!
//! 关联分析是**离线可跑**的分析与编排层：全部能力都是纯函数 + 内存结构，
//! 不需要数据库、缓存或网络。需要外部系统的地方（通知渠道、处置动作、人工审批）
//! **一律经 trait 注入**，本 crate 只提供 Mock 实现：
//!
//! | 能力 | 未注入/不可用时 |
//! |---|---|
//! | 通知渠道 | [`notify::NotificationChannel`] 未注入 ⇒ 该渠道判 `unroutable` 并留审计，**不静默丢弃** |
//! | 处置动作 | [`playbook::ActionExecutor`] 未注入 ⇒ 该步记为失败（或中止），**绝不假装已隔离** |
//! | 人工审批 | [`playbook::ApprovalGate`] 未注入 ⇒ 需要审批的剧本**直接拒绝执行**，绝不自动放行不可逆动作 |
//! | 持久化（簇/案件/SLA 钟/去重状态） | 全部为内存态，各模块文档列出了 `TODO(correlate-*)` 锚点供 `agf-api` 在能力页展示 |
//!
//! 未实现的能力**不会**被静默降级为"没有告警"或"已处置"，而是明确留 `TODO` 锚点。

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]

pub mod aggregate;
pub mod baseline;
pub mod case;
pub mod entity;
pub mod graph;
pub mod notify;
pub mod playbook;
pub mod sla;
pub mod temporal;

/// 平台版本。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
