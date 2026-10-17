use agf_core::error::{DomainError, DomainResult};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(super) fn invalid() -> DomainError {
    DomainError::Validation("人工处理输入无效；只允许已采集失败证据和明确操作人决策".into())
}
pub(super) fn stale() -> DomainError {
    DomainError::Conflict("来源或处理版本已改变，请重新读取后明确提交".into())
}
pub(super) fn corrupt() -> DomainError {
    DomainError::Crypto("人工处理证据、身份或持久记录不匹配".into())
}
pub(super) fn hash<T: Serialize>(value: &T) -> DomainResult<String> {
    let mut value = serde_json::to_value(value)?;
    canonical(&mut value);
    let bytes = serde_json::to_vec(&value)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
fn canonical(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let previous = std::mem::take(map);
            let mut entries = previous.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            for (key, mut item) in entries {
                canonical(&mut item);
                map.insert(key, item);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(canonical),
        _ => {}
    }
}
pub(super) fn bounded<T: Serialize>(value: &T, cap: usize) -> DomainResult<()> {
    if serde_json::to_vec(value)?.len() > cap {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn identifier(value: &str, cap: usize) -> bool {
    !value.is_empty()
        && value.len() <= cap
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
}
pub(super) fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
