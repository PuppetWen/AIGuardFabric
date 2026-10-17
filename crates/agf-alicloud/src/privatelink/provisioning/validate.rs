use super::{AcceptConnection, CreateEndpoint, PreparedChange, invalid};
use agf_core::{error::DomainResult, ids::Id};
use serde_json::json;
use std::collections::BTreeSet;

pub(super) fn token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

pub(super) fn resource(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|tail| token(tail, 64))
}

fn identity(id: Id) -> DomainResult<()> {
    if id.as_uuid().is_nil() { Err(invalid()) } else { Ok(()) }
}

impl CreateEndpoint {
    /// 构造一次 CreateVpcEndpoint；ClientToken 始终取已持久领取的原 UUID。
    ///
    /// # Errors
    /// 缺少明确资源、重复列表、非法地域或跨地域带宽不一致。
    pub fn prepare(&self, request_id: Id) -> DomainResult<PreparedChange> {
        identity(request_id)?;
        let valid_name = (2..=128).contains(&self.name.chars().count())
            && self.name.chars().next().is_some_and(char::is_alphabetic)
            && self.name.chars().all(|c| c.is_alphanumeric() || matches!(c, '-' | '_'));
        if !token(&self.region_id, 64)
            || !token(&self.service_region_id, 64)
            || !resource(&self.service_id, "epsrv-")
            || !resource(&self.vpc_id, "vpc-")
            || !valid_name
            || !(1..=10).contains(&self.zones.len())
            || !(1..=10).contains(&self.security_group_ids.len())
        {
            return Err(invalid());
        }
        let mut zones = BTreeSet::new();
        let mut switches = BTreeSet::new();
        for zone in &self.zones {
            if !token(&zone.zone_id, 64)
                || !zone.zone_id.starts_with(&(self.region_id.clone() + "-"))
                || !resource(&zone.vswitch_id, "vsw-")
                || !zones.insert(&zone.zone_id)
                || !switches.insert(&zone.vswitch_id)
            {
                return Err(invalid());
            }
        }
        let mut groups = BTreeSet::new();
        if self.security_group_ids.iter().any(|group| !resource(group, "sg-") || !groups.insert(group)) {
            return Err(invalid());
        }
        let cross_region = self.region_id != self.service_region_id;
        if cross_region != self.cross_region_bandwidth.is_some()
            || self.cross_region_bandwidth.is_some_and(|value| !(100..=50_000).contains(&value))
        {
            return Err(invalid());
        }
        let mut input = json!({
            "RegionId":self.region_id,"ClientToken":request_id.to_string(),"DryRun":false,
            "EndpointName":self.name,"EndpointType":"Interface","VpcId":self.vpc_id,
            "ServiceId":self.service_id,"ServiceRegionId":self.service_region_id,
            "Zone":self.zones.iter().map(|zone| json!({"ZoneId":zone.zone_id,"VSwitchId":zone.vswitch_id})).collect::<Vec<_>>(),
            "SecurityGroupId":self.security_group_ids,"ProtectedEnabled":true,"AddressIpVersion":"IPv4",
            "ZonePrivateIpAddressCount":1
        });
        if let Some(bandwidth) = self.cross_region_bandwidth {
            input["CrossRegionBandwidth"] = json!(bandwidth);
        }
        Ok(PreparedChange { action: "CreateVpcEndpoint", input, endpoint_id: None })
    }
}

impl AcceptConnection {
    /// 单独接受已观察到的连接；不创建服务、白名单、安全组或路由。
    ///
    /// # Errors
    /// 原 UUID 或目标资源无效。
    pub fn prepare(&self, request_id: Id) -> DomainResult<PreparedChange> {
        identity(request_id)?;
        if !token(&self.region_id, 64) || !resource(&self.service_id, "epsrv-") || !resource(&self.endpoint_id, "ep-") {
            return Err(invalid());
        }
        Ok(PreparedChange {
            action: "EnableVpcEndpointConnection",
            input: json!({"RegionId":self.region_id,"ClientToken":request_id.to_string(),"DryRun":false,
                          "ServiceId":self.service_id,"EndpointId":self.endpoint_id}),
            endpoint_id: Some(self.endpoint_id.clone()),
        })
    }
}
