//! APIG 内容安全与模型公开配置的可信观察、一次性发布、回滚和本地恢复。
//!
//! 只有显式工作流会调用固定源驱动。无云CAS，配置可能共享；
//! 云ACK、独立配置回读、本地审计和消费者生效分别记录。

mod archive;
mod audit;
mod authority;
mod claim;
mod completion;
mod content;
mod context;
mod contract;
mod dependencies;
mod dispatch;
mod input;
mod observation;
mod operations;
mod preview;
mod projection;
mod provider;
mod records;
mod recover;
mod registry;
mod risk;
mod routes;
mod scope;
mod sql;
mod store;
mod util;
mod views;

pub use registry::Registry;
pub(crate) use routes::router;

const NAME: &str = "alicloud-apig";
const MAX_GUARDS: usize = 32;
const MAX_CONTENT_BYTES: usize = 640 * 1024;
const MAX_RELATED: usize = 100;

mod mock;
