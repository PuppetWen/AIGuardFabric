//! 由 `entity.rs` 拆分：`impl_CrossSourceAlignment`/`clean_opt` 等 10 项（纯搬移，逻辑不变）。
use super::*;

impl CrossSourceAlignment {
    /// 由多个事件对齐（同一实体的不同指称被合并）。
    #[must_use]
    pub fn from_events(tenant: TenantId, aligner: &EntityAligner, events: &[Event]) -> Self {
        let mut out = Self::default();
        for event in events {
            let entities = aligner.extract(event);
            for r in &entities.refs {
                let key = entity_alignment_key(tenant, r.kind, &r.canonical);
                out.keys.entry(key.clone()).or_default().insert(r.source.clone());
                let slot = out.strength.entry(key).or_insert(EntityRefStrength::Weak);
                if r.strength > *slot {
                    *slot = r.strength;
                }
            }
        }
        out
    }

    /// 被**两个及以上**独立来源观察到的实体（跨源一致的强信号）。
    #[must_use]
    pub fn multi_source(&self) -> Vec<(&str, usize)> {
        let mut v: Vec<(&str, usize)> =
            self.keys.iter().filter(|(_, s)| s.len() >= 2).map(|(k, s)| (k.as_str(), s.len())).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        v
    }

    /// 两个事件是否共享**强**实体（被强证据观察到的同一实体）。
    #[must_use]
    pub fn shares_strong_entity(&self, other: &Self) -> bool {
        self.strength
            .iter()
            .filter(|(_, s)| **s == EntityRefStrength::Strong)
            .any(|(k, _)| other.strength.get(k).is_some_and(|s| *s >= EntityRefStrength::Medium))
    }

    /// 对齐键数量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

// ===========================================================================
// 归一化原语（纯函数，全部无 panic）
// ===========================================================================

/// 去掉空白并小写；空串返回 `None`。
#[must_use]
pub fn clean_opt(value: Option<&str>) -> Option<String> {
    let v = value?.trim().to_lowercase();
    if v.is_empty() { None } else { Some(v) }
}

/// 主机名归一：小写；剥离 FQDN 尾点；剥离常见 `.local`/`.corp` 之后的域后缀？
///
/// 设计取舍：**只剥尾点与统一小写**，不剥域名后缀——`a.corp.com` 与 `a.cloud.com`
/// 是不同主机，剥后缀会把它们错并成同一实体（假阳）。跨后缀的同一主机依靠
/// `host.id` / 云实例 id 这类强标识对齐。
#[must_use]
pub fn normalize_hostname(value: &str) -> String {
    let v = value.trim().trim_end_matches('.').to_lowercase();
    v.strip_prefix("http://").or_else(|| v.strip_prefix("https://")).unwrap_or(&v).to_string()
}

/// IP 归一：IPv4 去前导零；IPv6 完整展开（压缩形式与展开形式落到同一串）。
///
/// 无法解析时返回 `None`（调用方决定是否降级为字符串比较）。
#[must_use]
pub fn normalize_ip(value: &str) -> Option<String> {
    let raw = value.trim().trim_matches(|c: char| matches!(c, '[' | ']'));
    if raw.is_empty() {
        return None;
    }
    if let Some(v4) = parse_ipv4(raw) {
        return Some(v4);
    }
    parse_ipv6_expand(raw)
}

/// IPv4 解析为"去前导零"的规范形式。
pub(crate) fn parse_ipv4(value: &str) -> Option<String> {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        octets[i] = p.parse::<u8>().ok()?;
    }
    Some(format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]))
}

/// IPv6 展开为 8 组 4 位十六进制（含 `::` 压缩与内嵌 IPv4）。
pub(crate) fn parse_ipv6_expand(value: &str) -> Option<String> {
    if !value.contains(':') {
        return None;
    }
    let (head_raw, tail_raw) = match value.split_once("::") {
        Some((h, t)) => (h, Some(t)),
        None => (value, None),
    };
    if tail_raw.is_some() && value.matches("::").count() > 1 {
        return None;
    }
    let head = split_groups(head_raw)?;
    let tail = match tail_raw {
        Some(t) => split_groups(t)?,
        None => Vec::new(),
    };
    let mut groups: Vec<u16> = head;
    if tail_raw.is_some() {
        let missing = 8usize.checked_sub(groups.len() + tail.len())?;
        if missing == 0 {
            return None; // `::` 至少压缩一组
        }
        groups.extend(std::iter::repeat_n(0u16, missing));
    }
    groups.extend(tail);
    if groups.len() != 8 {
        return None;
    }
    Some(groups.iter().map(|g| format!("{g:04x}")).collect::<Vec<_>>().join(":"))
}

/// 按 `:` 切分组，支持最后一组是内嵌 IPv4（`::ffff:10.0.0.1`）。
pub(crate) fn split_groups(part: &str) -> Option<Vec<u16>> {
    if part.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    let items: Vec<&str> = part.split(':').collect();
    for (i, item) in items.iter().enumerate() {
        if item.is_empty() {
            return None;
        }
        if item.contains('.') {
            if i != items.len() - 1 {
                return None;
            }
            let v4 = parse_ipv4(item)?;
            let octets: Vec<u8> = v4.split('.').filter_map(|o| o.parse::<u8>().ok()).collect();
            if octets.len() != 4 {
                return None;
            }
            out.push(u16::from(octets[0]) << 8 | u16::from(octets[1]));
            out.push(u16::from(octets[2]) << 8 | u16::from(octets[3]));
            continue;
        }
        if item.len() > 4 || !item.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        out.push(u16::from_str_radix(item, 16).ok()?);
    }
    Some(out)
}

/// 域名归一：小写、去尾点、去 `www.`、去 scheme/端口/路径；非域名（含空格、无点）返回 `None`。
#[must_use]
pub fn normalize_domain(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return None;
    }
    let lowered = trimmed.to_lowercase();
    let stripped = lowered
        .strip_prefix("http://")
        .or_else(|| lowered.strip_prefix("https://"))
        .or_else(|| lowered.strip_prefix("ftp://"))
        .unwrap_or(&lowered);
    let host = stripped.split(['/', '?', '#']).next().unwrap_or_default();
    let host = host.split('@').next_back().unwrap_or_default();
    let host = host.split(':').next().unwrap_or_default();
    let host = host.strip_prefix("www.").unwrap_or(host);
    if host.is_empty() || host.contains(' ') {
        return None;
    }
    // 必须形如 a.b：至少一个点，且 TLD 为字母（避免把 "1.2" 当域名）
    let (_, tld) = host.rsplit_once('.')?;
    if tld.len() < 2 || !tld.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    if host.bytes().any(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))) {
        return None;
    }
    Some(host.to_string())
}

/// 邮箱归一：小写、校验基本形状。
#[must_use]
pub fn normalize_email(value: &str) -> Option<String> {
    let v = value.trim().trim_matches(|c: char| matches!(c, '<' | '>' | ',' | ';')).to_lowercase();
    let (local, domain) = v.split_once('@')?;
    if local.is_empty() || domain.is_empty() || local.contains('@') || domain.contains('@') {
        return None;
    }
    normalize_domain(domain)?;
    Some(format!("{local}@{domain}"))
}

/// 归一化资源标识引用（云 ARN / 路径 / 对象 key 的小写稳定形式）。
///
/// 用途：把 `arn:aws:s3:::Bucket/Key` 与 `s3://bucket/key` 归一到同一键。
#[must_use]
pub fn normalize_resource_identifier(value: &str) -> String {
    let v = value.trim().to_lowercase();
    let v = v.strip_prefix("arn:").map_or(v.clone(), |rest| {
        let mut parts = rest.splitn(6, ':');
        let _partition = parts.next();
        let _service = parts.next();
        let _region = parts.next();
        let _account = parts.next();
        parts.next().unwrap_or_default().to_string()
    });
    v.trim_start_matches('/').replace('\\', "/")
}
