//! 由 `privatelink.rs` 拆分：`evaluate_security_groups` 等 5 个函数（纯搬移，逻辑不变）。
use super::*;

/// 依据"最小化"要求评估安全组白名单。
///
/// 判定规则（公开可解释）：
/// - 未绑定任何安全组 → [`WhitelistVerdict::Unbound`]（需要核对默认规则）；
/// - 含 `0.0.0.0/0` 或 `::/0` → [`WhitelistVerdict::PubliclyOpen`]；
/// - 含超大网段（前缀 ≤ 16，如 `172.16.0.0/12`、`10.0.0.0/8`）→ [`WhitelistVerdict::TooBroad`]；
/// - 其余（如 `10.20.30.0/24`）→ [`WhitelistVerdict::Minimal`]。
#[must_use]
pub fn evaluate_security_groups(
    endpoints: &[PrivatelinkEndpoint],
    groups: &BTreeMap<String, Vec<String>>,
) -> Vec<SecurityGroupCheck> {
    let mut out = Vec::new();
    for endpoint in endpoints {
        if endpoint.security_groups.is_empty() {
            out.push(SecurityGroupCheck {
                endpoint_id: endpoint.endpoint_id.clone(),
                security_group: String::new(),
                allowed_cidrs: Vec::new(),
                verdict: WhitelistVerdict::Unbound,
                note: "终端节点未绑定安全组；请核对实际访问控制并绑定所需安全组".to_string(),
            });
            continue;
        }
        for group_id in &endpoint.security_groups {
            let allowed = groups.get(group_id).cloned().unwrap_or_default();
            let verdict =
                if groups.contains_key(group_id) { classify_cidrs(&allowed) } else { WhitelistVerdict::Unknown };
            out.push(SecurityGroupCheck {
                endpoint_id: endpoint.endpoint_id.clone(),
                security_group: group_id.clone(),
                allowed_cidrs: allowed.clone(),
                verdict,
                note: match verdict {
                    WhitelistVerdict::Unknown => "规则缺失、非法或引用其他安全组/前缀列表；不能判定最小化".into(),
                    WhitelistVerdict::NoIngress => {
                        "已读取入方向规则，未发现允许入站的 CIDR；仍须核对规则优先级和业务可达性".into()
                    }
                    WhitelistVerdict::Minimal => "允许来源为受限私网 CIDR；未验证端口和规则优先级".to_string(),
                    WhitelistVerdict::TooBroad => format!("白名单含超大网段，建议收敛到 /24 以内：{allowed:?}"),
                    WhitelistVerdict::PubliclyOpen => "白名单含公网来源，需核对是否符合私网接入要求".to_string(),
                    WhitelistVerdict::Unbound => "安全组无入方向规则记录".to_string(),
                },
            });
        }
    }
    out
}

/// 对单个安全组的来源 CIDR 集合分类。
#[must_use]
pub fn classify_cidrs(cidrs: &[String]) -> WhitelistVerdict {
    if cidrs.is_empty() {
        return WhitelistVerdict::NoIngress;
    }
    if cidrs.iter().any(|c| c == "0.0.0.0/0" || c == "::/0") {
        return WhitelistVerdict::PubliclyOpen;
    }
    if cidrs.iter().any(|cidr| prefix_len(cidr).is_none()) {
        return WhitelistVerdict::Unknown;
    }
    for cidr in cidrs {
        let Some((address, _)) = cidr.split_once('/') else {
            return WhitelistVerdict::Unknown;
        };
        let private = match address.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(ip)) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
            Ok(std::net::IpAddr::V6(ip)) => ip.is_unique_local() || ip.is_loopback() || ip.is_unicast_link_local(),
            Err(_) => return WhitelistVerdict::Unknown,
        };
        if !private {
            return WhitelistVerdict::PubliclyOpen;
        }
    }
    if cidrs.iter().any(|c| prefix_len(c).is_some_and(|p| p <= if c.contains(':') { 64 } else { 16 })) {
        return WhitelistVerdict::TooBroad;
    }
    WhitelistVerdict::Minimal
}

/// 取 CIDR 前缀长度（非法输入返回 `None`）。
#[must_use]
pub fn prefix_len(cidr: &str) -> Option<u8> {
    let (address, prefix) = cidr.split_once('/')?;
    let address = address.parse::<std::net::IpAddr>().ok()?;
    let prefix = prefix.parse::<u8>().ok()?;
    (prefix <= if address.is_ipv4() { 32 } else { 128 }).then_some(prefix)
}

/// 解析终端节点列表响应。
#[must_use]
pub fn parse_endpoints(body: &serde_json::Value) -> Vec<PrivatelinkEndpoint> {
    json_array(body, &["Endpoint", "Endpoints", "VpcEndpoint"])
        .into_iter()
        .map(|item| PrivatelinkEndpoint {
            endpoint_id: json_str(item, "EndpointId").or_else(|| json_str(item, "VpcEndpointId")).unwrap_or_default(),
            name: json_str(item, "Name").or_else(|| json_str(item, "EndpointName")).unwrap_or_default(),
            service_name: json_str(item, "ServiceName").unwrap_or_default(),
            vpc_id: json_str(item, "VpcId").unwrap_or_default(),
            zone_ids: item
                .get("ZoneIds")
                .or_else(|| item.get("Zones"))
                .and_then(serde_json::Value::as_array)
                .map(|zones| zones.iter().filter_map(|z| z.as_str().map(ToString::to_string)).collect())
                .unwrap_or_default(),
            status: json_str(item, "EndpointStatus")
                .or_else(|| json_str(item, "Status"))
                .unwrap_or_else(|| "Unknown".to_string()),
            bandwidth_mbps: json_i64(item, "Bandwidth").unwrap_or(0).max(0).unsigned_abs() as u32,
            security_groups: item
                .get("SecurityGroups")
                .and_then(serde_json::Value::as_array)
                .map(|groups| groups.iter().filter_map(|g| g.as_str().map(ToString::to_string)).collect())
                .unwrap_or_default(),
            connection_status: json_str(item, "ConnectionStatus").unwrap_or_else(|| "Unknown".to_string()),
        })
        .collect()
}

/// 解析安全组规则响应为 `安全组 → 来源 CIDR` 映射。
#[must_use]
pub fn parse_security_group_rules(body: &serde_json::Value) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for item in json_array(body, &["SecurityGroupRule", "Rules"]) {
        let Some(group) = json_str(item, "SecurityGroupId") else { continue };
        let cidr = json_str(item, "SourceCidrIp")
            .or_else(|| json_str(item, "IpProtocol"))
            .unwrap_or_else(|| "0.0.0.0/0".to_string());
        out.entry(group).or_default().push(cidr);
    }
    out
}
