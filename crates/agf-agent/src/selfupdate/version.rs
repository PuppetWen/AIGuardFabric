//! 按 SemVer 比较可信发布版本；预发布数字段按长度和数位比较，避免整数溢出。
use agf_core::error::{DomainError, DomainResult};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// 语义化版本；不保存不影响排序的构建元数据。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Version {
    /// 主版本。
    pub major: u64,
    /// 次版本。
    pub minor: u64,
    /// 修订版本。
    pub patch: u64,
    /// 已验证的预发布标识符，以点分隔。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre: Option<String>,
}

impl std::fmt::Display for Version {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(pre) = &self.pre {
            write!(formatter, "-{pre}")?;
        }
        Ok(())
    }
}

fn identifier_cmp(left: &str, right: &str) -> Ordering {
    let numeric = |value: &str| value.bytes().all(|byte| byte.is_ascii_digit());
    match (numeric(left), numeric(right)) {
        (true, true) => left.len().cmp(&right.len()).then_with(|| left.cmp(right)),
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => left.cmp(right),
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let core = (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch));
        if core != Ordering::Equal {
            return core;
        }
        match (&self.pre, &other.pre) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(left), Some(right)) => {
                let mut left = left.split('.');
                let mut right = right.split('.');
                loop {
                    match (left.next(), right.next()) {
                        (Some(a), Some(b)) => {
                            let order = identifier_cmp(a, b);
                            if order != Ordering::Equal {
                                return order;
                            }
                        }
                        (Some(_), None) => return Ordering::Greater,
                        (None, Some(_)) => return Ordering::Less,
                        (None, None) => return Ordering::Equal,
                    }
                }
            }
        }
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn invalid() -> DomainError {
    DomainError::Validation("Release version is not a bounded semantic version".into())
}

fn valid_identifiers(value: &str, prerelease: bool) -> bool {
    value.split('.').all(|part| {
        !part.is_empty()
            && part.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && !(prerelease
                && part.len() > 1
                && part.starts_with('0')
                && part.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

/// 解析 `major.minor.patch[-prerelease][+build]`，允许 v/V 前缀。
///
/// # Errors
/// 拒绝空标识符、非法前导零、非法字符和溢出的主版本数字段。
pub fn parse_version(raw: &str) -> DomainResult<Version> {
    if raw.len() > 256 {
        return Err(invalid());
    }
    let trimmed = raw.trim();
    let value = trimmed.strip_prefix(['v', 'V']).unwrap_or(trimmed);
    let without_build = match value.split_once('+') {
        Some((version, build)) if valid_identifiers(build, false) => version,
        Some(_) => return Err(invalid()),
        None => value,
    };
    let (core, pre) = match without_build.split_once('-') {
        Some((core, pre)) if valid_identifiers(pre, true) => (core, Some(pre.to_owned())),
        Some(_) => return Err(invalid()),
        None => (without_build, None),
    };
    let parts = core.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(invalid());
    }
    let numeric = |part: &str| -> DomainResult<u64> {
        if part.is_empty()
            || !part.bytes().all(|byte| byte.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
        {
            return Err(invalid());
        }
        part.parse().map_err(|_| invalid())
    };
    Ok(Version { major: numeric(parts[0])?, minor: numeric(parts[1])?, patch: numeric(parts[2])?, pre })
}

/// 判断可信候选版本是否具有更高的语义化版本优先级。
///
/// # Errors
/// 任一版本格式不合法时返回验证错误。
pub fn is_newer(current: &str, candidate: &str) -> DomainResult<bool> {
    Ok(parse_version(candidate)? > parse_version(current)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn semantic_precedence_keeps_numeric_identifiers_and_release_downgrades_correct() {
        let ordered = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ];
        for pair in ordered.windows(2) {
            assert!(is_newer(pair[0], pair[1]).unwrap());
            assert!(!is_newer(pair[1], pair[0]).unwrap());
        }
        assert!(is_newer("1.0.0-rc.9", "1.0.0-rc.10").unwrap());
        assert!(is_newer("1.0.0-999999999999999999999999", "1.0.0-1000000000000000000000000").unwrap());
        assert!(!is_newer("1.0.0+old", "1.0.0+new").unwrap());
    }

    #[test]
    fn malformed_version_identifiers_cannot_select_an_installation() {
        for invalid in ["01.0.0", "+1.0.0", "1.0.0-", "1.0.0-rc..1", "1.0.0-01", "1.0.0+", "1.0.0+x+y", "1.0.0-å"] {
            assert!(parse_version(invalid).is_err(), "{invalid}");
        }
        assert_eq!(parse_version("V1.0.0-rc.10+001.build").unwrap().to_string(), "1.0.0-rc.10");
    }
}
