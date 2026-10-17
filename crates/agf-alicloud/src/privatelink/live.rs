//! PrivateLink inventory and real TCP probes. Rule inspection uses ECS, not a fabricated PrivateLink API.
use super::*;
use crate::openapi::contract;
use serde_json::{Value, json};

impl PrivatelinkAdapter {
    async fn pages(&self, action: &str, mut input: Value, key: &str) -> DomainResult<Vec<Value>> {
        let mut result = Vec::new();
        let mut tokens = std::collections::BTreeSet::new();
        input["RegionId"] = json!(self.core.region);
        input["MaxResults"] = json!(50);
        for _ in 0..20 {
            let response = contract(AliCloudService::Privatelink, action)?.call(self.live_client()?, &input).await?;
            let items =
                response.body[key].as_array().ok_or_else(|| DomainError::Parse(format!("{action} 缺少 {key}")))?;
            result.extend(items.iter().cloned());
            let token = response.body["NextToken"].as_str().unwrap_or_default();
            if token.is_empty() {
                return Ok(result);
            }
            if !tokens.insert(token.to_string()) {
                return Err(DomainError::Parse("PrivateLink 分页令牌循环".into()));
            }
            input["NextToken"] = json!(token);
        }
        Err(DomainError::Validation("PrivateLink 超过 20 页，请缩小地域/节点范围".into()))
    }
}

#[async_trait]
impl PrivatelinkApi for PrivatelinkAdapter {
    async fn pull_endpoints(&self) -> DomainResult<Vec<PrivatelinkEndpoint>> {
        if self.core.is_mock() {
            return Ok(mock::privatelink_endpoints());
        }
        let items = self.pages("ListVpcEndpoints", json!({}), "Endpoints").await?;
        if items.len() > 200 {
            return Err(DomainError::Validation("单次最多读取 200 个终端节点详情".into()));
        }
        let mut endpoints = parse_endpoints(&json!({"Endpoints":items}));
        for endpoint in &mut endpoints {
            if endpoint.endpoint_id.is_empty() {
                return Err(DomainError::Parse("PrivateLink 节点缺少 EndpointId".into()));
            }
            let input = json!({"EndpointId":endpoint.endpoint_id});
            let groups = self.pages("ListVpcEndpointSecurityGroups", input.clone(), "SecurityGroups").await?;
            endpoint.security_groups = groups
                .iter()
                .map(|item| {
                    item["SecurityGroupId"]
                        .as_str()
                        .filter(|id| !id.is_empty())
                        .map(str::to_owned)
                        .ok_or_else(|| DomainError::Parse("PrivateLink 安全组缺少标识".into()))
                })
                .collect::<DomainResult<_>>()?;
            let zones = self.pages("ListVpcEndpointZones", input, "Zones").await?;
            endpoint.zone_ids = zones.iter().filter_map(|item| item["ZoneId"].as_str().map(str::to_owned)).collect();
        }
        Ok(endpoints)
    }

    async fn probe(&self, target: &str) -> DomainResult<PrivatelinkProbe> {
        if self.core.is_mock() {
            return Ok(mock::privatelink_probe(target));
        }
        if !self.core.is_live() {
            return Ok(Self::unknown_probe(target));
        }
        let port = self
            .probe_port
            .ok_or_else(|| DomainError::Config("请配置实际业务 probe_port，再从部署网络探测终端节点 ID".into()))?;
        let response = contract(AliCloudService::Privatelink, "GetVpcEndpointAttribute")?
            .call(self.live_client()?, &json!({"RegionId":self.core.region,"EndpointId":target}))
            .await?;
        if response.body["EndpointId"] != target {
            return Err(DomainError::Parse("终端节点返回的 EndpointId 不匹配".into()));
        }
        let domain = response.body["EndpointDomain"]
            .as_str()
            .filter(|domain| !domain.is_empty())
            .ok_or_else(|| DomainError::Parse("终端节点缺少 EndpointDomain".into()))?;
        let start = std::time::Instant::now();
        let connection =
            tokio::time::timeout(std::time::Duration::from_secs(5), tokio::net::TcpStream::connect((domain, port)))
                .await;
        let (reachable, resolved_ip, detail) = match connection {
            Ok(Ok(stream)) => (
                true,
                stream.peer_addr().map(|addr| addr.ip().to_string()).unwrap_or_default(),
                "TCP 连接成功；未验证 TLS、业务认证或应用响应",
            ),
            Ok(Err(_)) => (false, String::new(), "从部署网络建立 TCP 连接失败；请检查 DNS、端口、安全组和节点状态"),
            Err(_) => (false, String::new(), "从部署网络建立 TCP 连接超时（5 秒）"),
        };
        Ok(PrivatelinkProbe {
            target: target.into(),
            reachable,
            latency_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
            endpoint_id: target.into(),
            resolved_ip,
            detail: detail.into(),
            at: Timestamp::now(),
        })
    }

    async fn check_security_groups(&self) -> DomainResult<Vec<SecurityGroupCheck>> {
        let endpoints = self.pull_endpoints().await?;
        if self.core.is_mock() {
            return Ok(evaluate_security_groups(&endpoints, &mock::privatelink_security_groups()));
        }
        let client = self.live_client()?.ecs_security_group_client(self.ecs_endpoint.as_deref())?;
        let ids: std::collections::BTreeSet<_> =
            endpoints.iter().flat_map(|ep| ep.security_groups.iter().cloned()).collect();
        if ids.len() > 200 {
            return Err(DomainError::Validation("一次最多检查 200 个安全组".into()));
        }
        let mut rules = BTreeMap::new();
        for id in ids {
            let mut sources = Vec::new();
            let mut token = String::new();
            let mut seen = std::collections::BTreeSet::new();
            for page in 0..20 {
                let mut input = vec![
                    ("RegionId".into(), self.core.region.clone()),
                    ("SecurityGroupId".into(), id.clone()),
                    ("Direction".into(), "ingress".into()),
                    ("MaxResults".into(), "100".into()),
                ];
                if !token.is_empty() {
                    input.push(("NextToken".into(), token.clone()));
                }
                let response = client.call_async("DescribeSecurityGroupAttribute", "2014-05-26", "GET", &input).await?;
                let permissions = response
                    .body
                    .pointer("/Permissions/Permission")
                    .and_then(Value::as_array)
                    .ok_or_else(|| DomainError::Parse("ECS 安全组响应缺少 Permissions.Permission".into()))?;
                for rule in permissions {
                    if rule["Policy"].as_str().is_some_and(|policy| policy.eq_ignore_ascii_case("drop")) {
                        continue;
                    }
                    let mut has_source = false;
                    for key in ["SourceCidrIp", "Ipv6SourceCidrIp"] {
                        if let Some(cidr) = rule[key].as_str().filter(|s| !s.is_empty()) {
                            sources.push(cidr.into());
                            has_source = true;
                        }
                    }
                    if !has_source {
                        sources.push("unknown-source-reference".into());
                    }
                }
                token = response.body["NextToken"].as_str().unwrap_or_default().into();
                if token.is_empty() {
                    break;
                }
                if page == 19 || !seen.insert(token.clone()) {
                    return Err(DomainError::Parse("ECS 安全组分页未完成".into()));
                }
            }
            rules.insert(id, sources);
        }
        Ok(evaluate_security_groups(&endpoints, &rules))
    }
}
