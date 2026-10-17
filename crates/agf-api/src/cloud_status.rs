//! Console projections report saved tenant configuration and recorded checks, never invented cloud results.
use crate::{
    cloud_store as config,
    integration_store::{decrypt, id},
    state::AppState,
};
use agf_core::{enums::AliCloudService, error::DomainResult, ids::TenantId, time::Timestamp};
use serde_json::{Value, json};

pub async fn services(state: &AppState, tenant: TenantId) -> DomainResult<Vec<Value>> {
    let mut rows = Vec::new();
    for service in AliCloudService::all() {
        let name = service.as_str();
        let stored = config::load(state, tenant, name).await?;
        let private = stored.as_ref().map(|row| decrypt(state, tenant, row)).transpose()?.unwrap_or_default();
        let enabled = stored.as_ref().is_some_and(|row| row.enabled);
        let mocked = state.config.mock_mode || stored.as_ref().is_none_or(|row| row.mock);
        let version = stored.as_ref().map_or(0, |row| row.version);
        let probe = state.configurations.get::<Value>(tenant, "cloud-probe", id(tenant, name)).await?.filter(|probe| {
            enabled && probe["version"].as_u64() == Some(version) && probe["mocked"].as_bool() == Some(mocked)
        });
        let checked = probe
            .as_ref()
            .and_then(|probe| probe["checked_at"].as_str())
            .and_then(|raw| Timestamp::parse_rfc3339(raw).ok());
        let recent = checked.is_some_and(|at| Timestamp::now().since_secs(&at) < 300);
        let passed = enabled && !mocked && recent && probe.as_ref().is_some_and(|probe| probe["status"] == "succeeded");
        let health = if !enabled {
            "unconfigured"
        } else if mocked || !recent {
            "degraded"
        } else if passed {
            "healthy"
        } else {
            "unhealthy"
        };
        let note = if !enabled {
            "云集成未启用"
        } else if mocked {
            "模拟数据不证明真实云端网络、权限或配额"
        } else if !recent {
            "尚无当前配置的近期只读自检；请在连接配置中运行检查"
        } else if passed {
            "最近一次只读检查成功，仅覆盖记录中的接口权限"
        } else {
            "最近一次只读检查失败，请查看操作回执"
        };
        let descriptor = agf_alicloud::mock::descriptor_of(service);
        rows.push(json!({"name":name,"service":name,"display_name":descriptor.display_name,"category":"cloud",
            "configured":stored.is_some(),"enabled":enabled,"mode":if mocked {"mocked"}else{"live"},"serving":passed,
            "real_implementation":true,"version":version,"health":health,"note":note,"region":config::setting(&private,"region_id","cn-hangzhou"),
            "resource_id":private.settings.get("instance_id").or_else(||private.settings.get("cluster_id")),
            "mock_location":"tests/fixtures/alicloud/openapi-*.json","degradation":descriptor.degradation,
            "doc_anchor":"docs/alicloud-operations-guide.md","probe":probe,"checked_at":checked}));
    }
    Ok(rows)
}
pub async fn checks(state: &AppState, tenant: TenantId) -> DomainResult<Vec<Value>> {
    let mut out = Vec::new();
    for row in services(state, tenant).await? {
        for (category, label, requirement) in [
            ("connectivity", "只读调用", "实际云 API 请求成功"),
            ("least-privilege", "最小权限", "核对 RAM 授权动作和资源范围；单次 API 成功不能证明最小权限"),
            ("quota", "云配额", "在云控制台核对当前账号资源与额度"),
        ] {
            let unverified = category != "connectivity";
            let result = if unverified
                || row["mode"] == "mocked"
                || row["health"] == "unconfigured"
                || row["health"] == "degraded"
            {
                "warn"
            } else if row["serving"] == true {
                "pass"
            } else {
                "fail"
            };
            out.push(
                json!({"id":format!("{}-{category}",row["name"].as_str().unwrap_or_default()),"category":category,
                "name":format!("{} · {label}",row["display_name"].as_str().unwrap_or_default()),"result":result,
                "detail":if category == "quota" {"尚未查询实际云配额，不能推算可用额度"}
                    else if unverified {"只读接口回执不能证明账号已遵循最小权限，请在 RAM 策略和资源范围中核对"}
                    else {row["note"].as_str().unwrap_or_default()},
                "value":if unverified {"unknown"}else{row["probe"]["action"].as_str().unwrap_or("not-checked")},
                "requirement":requirement,"checkedAt":if unverified {Value::Null}else{row["checked_at"].clone()}}),
            );
        }
    }
    Ok(out)
}
pub async fn report(state: &AppState, tenant: TenantId) -> DomainResult<Value> {
    let reports = services(state, tenant).await?;
    let items = checks(state, tenant).await?;
    let blocking = items.iter().filter(|item| item["result"] == "fail").count();
    let quota_items: Vec<_> = items.iter().filter(|item| item["category"] == "quota").collect();
    let quota_warnings = quota_items.iter().filter(|item| item["result"] == "warn").count();
    let quota_warn_ratio = if quota_items.is_empty() { 0.0 } else { quota_warnings as f64 / quota_items.len() as f64 };
    let mut markdown = String::from("# 云环境检查记录\n\n检查只覆盖实际执行的接口；Mock 不代表真实环境通过。\n\n");
    for row in &reports {
        markdown.push_str(&format!(
            "- {}：{}\n",
            row["display_name"].as_str().unwrap_or_default(),
            row["note"].as_str().unwrap_or_default()
        ));
    }
    // AgentTeams does not publish a RAM action matrix in this API version; do not invent one.
    let actions = [
        "cms:DescribeAlertHistoryList",
        "apig:ListGateways",
        "mse:ListClusters",
        "privatelink:ListVpcEndpoints",
        "schedulerx3:ListJobs",
    ];
    let ram_policy = serde_json::to_string_pretty(
        &json!({"Version":"1","Statement":[{"Effect":"Allow","Action":actions,"Resource":"*"}]}),
    )?;
    Ok(json!({"overall":if blocking>0 {"unhealthy"}else{"degraded"},"reports":reports,"items":items,
        "blocking_failures":blocking,"quota_warnings":quota_warnings,"ram_policy":ram_policy,
        "ram_policy_note":"仅供只读自检；按账号/地域/资源收窄支持资源级控制的 ARN。AgentTeams 权限以当前厂商授权方式为准。",
        "markdown":markdown,"quota_warn_ratio":quota_warn_ratio}))
}
