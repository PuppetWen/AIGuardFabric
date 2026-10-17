//! 稳定资源分区，同一资源在一批广播任务中恰好属于一个分片。
use agf_core::error::{DomainError, DomainResult};
use axum::http::HeaderMap;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Partition {
    pub index: u32,
    pub total: u32,
}
impl Default for Partition {
    fn default() -> Self {
        Self { index: 0, total: 1 }
    }
}
impl Partition {
    pub(crate) fn parse(headers: &HeaderMap) -> DomainResult<Self> {
        let field = |name| headers.get(name).map(|value| value.to_str().ok().and_then(|raw| raw.parse::<u32>().ok()));
        let result = match (field("schedulerx-shardingindex"), field("schedulerx-shardingtotal")) {
            (None, None) => Self::default(),
            (Some(Some(index)), Some(Some(total))) => Self { index, total },
            _ => return Err(DomainError::Validation("分片序号与总数须成对提供有效整数".into())),
        };
        if result.total == 0 || result.total > 256 || result.index >= result.total {
            return Err(DomainError::Validation("分片总数须为 1–256，序号从 0 开始且小于总数".into()));
        }
        Ok(result)
    }
    pub(crate) fn owns(self, key: &str) -> bool {
        let value = Sha256::digest(key.as_bytes()).iter().take(8).fold(0u64, |n, b| (n << 8) | u64::from(*b));
        value % u64::from(self.total) == u64::from(self.index)
    }
    pub(crate) fn first(self) -> bool {
        self.index == 0
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn each_resource_has_exactly_one_stable_owner() {
        for total in [1, 2, 4, 8, 32, 256] {
            let mut counts = vec![0u32; total as usize];
            for resource in 0..1000 {
                let key = format!("resource-{resource}");
                let owners: Vec<_> = (0..total).filter(|index| Partition { index: *index, total }.owns(&key)).collect();
                assert_eq!(owners.len(), 1);
                counts[owners[0] as usize] += 1;
            }
            assert_eq!(counts.iter().sum::<u32>(), 1000);
            if total > 1 {
                assert!(counts.iter().filter(|count| **count > 0).count() > 1);
            }
        }
    }
}
