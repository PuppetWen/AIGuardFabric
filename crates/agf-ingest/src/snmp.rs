//! SNMP Trap 接收器：**SNMP v1/v2c Trap 的 BER/ASN.1 手写解析 + UDP 监听**。
//!
//! ## 为什么手写 BER 而不是引 SNMP 协议栈
//!
//! 平台只需要"**收 Trap 并把它变成一条事件**"：不需要 GET/WALK/SET，也不需要 MIB 编译。
//! 引 `rasn`/`snmp` 会带来一整套 ASN.1 代码生成与 MIB 依赖，而本接收器真正需要的
//! 只是 BER 的 `SEQUENCE / INTEGER / OCTET STRING / OID / [APPLICATION n]` 六种类型
//! （见 [`ber`]）。手写实现：零新增依赖、可在单测里逐字段构造报文验证、
//! 未知类型按 `Opaque` 渲染为 hex 而不是丢弃整条 Trap。
//!
//! ## 支持范围（如实标注）
//!
//! | 版本 | 状态 | 说明 |
//! |---|---|---|
//! | SNMP v2c Trap（`0xA7`） | **已实现** | `request-id` + `variable-bindings`；`snmpTrapOID.0` 提取为 trap OID |
//! | SNMP v2c Inform（`0xA6`） | 已实现 | 与 Trap 同构（当前只解析不回应答，`TODO ingest-snmp-inform-ack`） |
//! | SNMP v1 Trap（`0xA4`） | 已实现 | `enterprise` / `agent-addr` / `generic-trap` / `specific-trap` / `time-stamp` |
//! | SNMP v3 `noAuthNoPriv` | **已实现** | USM 报文结构（`msgGlobalData` / `msgSecurityParameters` / ScopedPDU）解析，`msgFlags=0x00` |
//! | SNMP v3 `authNoPriv` | **已实现** | HMAC-MD5-96 与 HMAC-SHA-96 摘要校验（RFC3414 §6.3.1/§7.3）+ 时限窗口（150s）+ `usmStats` 计数 |
//! | SNMP v3 `authPriv` + **DES** | **已实现** | RFC3414 §8 CBC-DES：`privKey=Kul[0..16]`（前 8 = DES key、后 8 = pre-IV）、`IV = pre-IV XOR salt`、补齐按 BER 长度剥离 |
//! | SNMP v3 `authPriv` + **AES-128** | **已实现（默认）** | RFC3826 §3 CFB128-AES-128：`key = Kul[0..16]`、`IV = engineBoots‖engineTime‖salt`、流模式无补齐 |
//! | GET/WALK/SET（轮询） | 未实现 | 本接收器只收 Trap；设备侧轮询请用 HTTP Pull/JDBC |
//!
//! `authPriv` 的解密失败/认证失败**分类计数**（`usmStatsDecryptionErrors` / `usmStatsWrongDigests`
//! + `agf_ingest_snmp_usm_priv_*`），绝不静默丢弃。
//!
//! ## v3 的口令 / 密钥模型（重要）
//!
//! Trap 的发送方就是**权威引擎**，因此接收侧无法预先知道 `msgAuthoritativeEngineID`：
//! 接收器**从报文里取 engineID**，再按 RFC3414 §2.6 本地化口令得到密钥
//! （`Ku = H(口令重复至 1 MiB)`，`Kul = H(Ku ‖ engineID ‖ Ku)`）。
//! 本地化结果按 engineID 缓存，避免每条 Trap 重算 1 MiB 哈希。
//! 校验时把 `msgAuthenticationParameters` 段**置 12 字节 0**后对整报文做 HMAC 并截断 96 bit（常量时间比对）。
//!
//! ## 配置
//!
//! | 字段 | 环境变量 | 默认 |
//! |---|---|---|
//! | 监听地址 | `AGF_INGEST_SNMP_LISTEN` | `0.0.0.0:1162`（容器外暴露见 compose；162 需要 root/特权） |
//! | community（v1/v2c） | `AGF_INGEST_SNMP_COMMUNITY` | `public` |
//! | 版本 | `AGF_INGEST_SNMP_VERSION` | `v2c`（`v1` / `v2c` / `v3`） |
//! | v3 用户名 | `AGF_INGEST_SNMP_V3_USER` | 空（`noAuthNoPriv` 可不填；`authNoPriv`/`authPriv` 必填） |
//! | v3 安全级别 | `AGF_INGEST_SNMP_V3_SECURITY_LEVEL` | `noAuthNoPriv`（`noAuthNoPriv`/`authNoPriv`/`authPriv`） |
//! | v3 认证协议 | `AGF_INGEST_SNMP_V3_AUTH_PROTOCOL` | `md5`（`md5` / `sha1`） |
//! | v3 认证口令 | `AGF_INGEST_SNMP_V3_AUTH_PASSWORD` | 空（`authNoPriv`/`authPriv` 必填，≥8 字符） |
//! | v3 隐私协议 | `AGF_INGEST_SNMP_V3_PRIV_PROTOCOL` | `aes`（`aes` / `des`） |
//! | v3 隐私口令 | `AGF_INGEST_SNMP_V3_PRIV_PASSWORD` | 空（`authPriv` 必填，≥8 字符） |
//!
//! community 不匹配 ⇒ 拒绝并计入 `dropped`（常量时间比较，避免逐字节试探）。
//! v3 认证/解密失败 ⇒ 拒绝并计入 `dropped` + 对应的 `usmStats` 计数器（如实分类，不合并成"未知错误"）。
//! **口令绝不进日志/Debug/错误文本**：对外只有 [`UsmConfig::describe`]（不含口令）。
//! 绑定失败只 warn，进程照常启动（其余接收器不受影响）。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use agf_core::enums::IngestProtocol;
use agf_core::error::{DomainError, DomainResult};
use agf_core::source::LogSource;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tracing::{debug, warn};

use crate::metrics::ReceiverCounters;
use crate::pipeline::IngestPipeline;
use crate::receiver::{Receiver, ReceiverDescriptor, ReceiverStatus, constant_time_eq};

pub mod ber;
pub mod encode;

mod message;
mod privacy;
mod receiver;
mod usm;
mod usm_state;
mod v3_body;

#[cfg(test)]
mod tests;

pub use message::*;
pub use privacy::*;
pub use receiver::*;
pub use usm::*;
pub use usm_state::*;
use v3_body::*;
