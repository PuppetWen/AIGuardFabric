//! 创建选定服务的接口终端节点，并单独接受连接；ACK 不代表业务可达。
//!
//! 调用层必须先持久领取原 UUID，持有同一云来源锁，并在每次发送前核查
//! 原身份、权限、配置版本和原期限。此驱动只发一次，不重试、不隐式接受。
//! Mock 状态应由调用层在业务/审计事务中持久维护，不伪造真实云网络。

mod dispatch;
mod observation;
#[cfg(test)]
mod tests;
mod types;
mod validate;

pub use dispatch::{CurrentGuard, dispatch_once};
pub use observation::{EndpointObservation, verify_observation};
pub use types::{AcceptConnection, CreateEndpoint, PreparedChange, WriteEvidence, WriteStatus, Zone};

use agf_core::error::DomainError;

fn invalid() -> DomainError {
    DomainError::Validation("PrivateLink 参数或完整观察无效，请核对选定资源".into())
}

fn expired() -> DomainError {
    DomainError::Timeout("PrivateLink 原操作期限已到，请读取原回执；不会重新派发".into())
}

mod current_observation;
pub use current_observation::{observe_current, validate_reference};
