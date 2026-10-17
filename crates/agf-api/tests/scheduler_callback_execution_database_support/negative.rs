//! A genuine additional provider observation creates the negative sealed qualification; SQL never invents a proof.
use super::*;
use native::{
    provider::Pending,
    wire::{Reply, Server},
};
use std::sync::atomic::{AtomicBool, Ordering};
mod signing;
mod provider {
    pub(super) const ACCESS_KEY: &str = "agf-owned-scheduler-key-no-cloud";
    pub(super) const SECRET: &str = "agf-owned-scheduler-signing-secret-no-cloud";
}
use provider::{ACCESS_KEY, SECRET};

pub(super) async fn qualification_wait() -> DomainResult<()> {
    let mut f = Fixture::new("cb-negative-guard").await?;
    let disabled = Arc::new(AtomicBool::new(false));
    let state = disabled.clone();
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../agf-alicloud/src/schedulerx3/native_observation/owned_fixture.json"
    ))?;
    let provider = Server::start(move |request| {
        let host =
            request.headers.get("host").ok_or_else(|| native::wire::fixture_error("negative provider host absent"))?;
        signing::verify_signature(request, &format!("http://{host}"))?;
        let fields = signing::query(request)?;
        if fields.get("AppName").map(String::as_str) != Some("app-agf-demo")
            || fields.get("ClusterId").map(String::as_str) != Some("cluster-agf-demo")
        {
            return Err(native::wire::fixture_error("negative fixture identity mismatch"));
        }
        match request.headers.get("x-acs-action").map(String::as_str) {
            Some("GetApp") if fields.len() == 2 => Ok(Reply::json(&fixture["GetApp"])),
            Some("ListJobs")
                if fields.len() == 4
                    && fields.get("PageNum").map(String::as_str) == Some("1")
                    && fields.get("PageSize").map(String::as_str) == Some("100") =>
            {
                let records: Vec<Value> = KINDS
                    .iter()
                    .map(|kind| {
                        let mut row = fixture["ListJobs"]["Data"]["Records"][0].clone();
                        row["JobId"] = json!(job(kind));
                        row["Status"] = json!(i32::from(!(*kind == "asset-inventory" && state.load(Ordering::SeqCst))));
                        row["Name"] = json!(format!("owned-negative-{kind}"));
                        row
                    })
                    .collect();
                Ok(Reply::json(&json!({"Code":200,"Success":true,"RequestId":"owned-negative-list",
                    "Data":{"PageNumber":1,"PageSize":100,"Total":6,"Records":records}})))
            }
            _ => Err(native::wire::fixture_error("negative fixture rejects unexpected read")),
        }
    })
    .await?;
    let address = provider
        .origin
        .trim_start_matches("http://")
        .parse()
        .map_err(|_| native::wire::fixture_error("negative fixture socket invalid"))?;
    f.h.state.scheduler_native_observation =
        Arc::new(agf_api::scheduler_native_observation::Registry::literal_loopback_for_test(f.h.tenant, address)?);
    f.h = native::for_tenant(f.h, f.case.h.tenant)?;
    let mut settings = native::settings();
    settings["endpoint"] = json!(provider.origin);
    assert_eq!(
        f.h.request(
            "PUT",
            native::CONFIG,
            Some(&f.h.admin),
            Some(json!({"expected_version":1,"enabled":true,"mock":false,
        "settings":settings,"secrets":{"access_key_id":ACCESS_KEY,"access_key_secret":SECRET}}))
        )
        .await
        .status,
        StatusCode::OK
    );
    let positive = Id::new();
    let mut observe = native::observe(positive, false);
    observe["configuration_version"] = json!(2);
    let observed = native::post(&f.h, &format!("{}/observe", native::BASE), observe).await?;
    f.target = observed["originalTarget"].clone();
    let saved =
        f.h.request(
            "PUT",
            &format!("{}/bindings", native::BASE),
            Some(&f.h.admin),
            Some(replace(Id::new(), 1, positive, 2)),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK);
    f.binding = saved.json();
    let good_binding = native::row(&f.h, native::BINDING, native::main_id(&f.h))
        .await?
        .ok_or_else(|| native::wire::fixture_error("positive sealed binding absent"))?;
    disabled.store(true, Ordering::SeqCst);
    let negative = Id::new();
    let mut observe = native::observe(negative, false);
    observe["configuration_version"] = json!(2);
    native::post(&f.h, &format!("{}/observe", native::BASE), observe).await?;
    let actual = native::read(&f.h, native::BASE).await?;
    assert!(actual["bindings"]["items"].as_array().is_some_and(|items| {
        items.iter().any(|item| {
            item["kind"] == "asset-inventory" && item["eligibility"] == "revoked" && item["reason"] == "job_disabled"
        })
    }));
    let revoked = native::row(&f.h, native::BINDING, native::main_id(&f.h))
        .await?
        .ok_or_else(|| native::wire::fixture_error("negative sealed binding absent"))?;
    f.case.owner.check().await?;
    f.h.state.configurations.put(f.h.tenant, native::BINDING, native::main_id(&f.h), &good_binding).await?;
    let fact = f.admit(f.input("asset-inventory", "owned-qualification-change", 0, 1)).await?;
    let before = native::rows(&f.h, EXECUTION).await?;
    let mut tx = f.case.owner.pool.begin().await.map_err(native::sql)?;
    let lock = format!("{}:{}:{}", f.h.tenant, native::BINDING, native::main_id(&f.h));
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(&lock)
        .execute(&mut *tx)
        .await
        .map_err(native::sql)?;
    let mut pending =
        Pending::start(&f.h, "POST", format!("{}/validate", fact_path(&fact)?), f.token.clone(), Some(claim(&fact)));
    gate::wait_advisory(&f.case.owner, &lock).await?;
    f.case.owner.check().await?;
    assert_eq!(sqlx::query("UPDATE console_configurations SET payload=$4,updated_at=now() WHERE tenant_id=$1 AND kind=$2 AND id=$3 AND deleted_at IS NULL")
        .bind(f.h.tenant.as_uuid()).bind(native::BINDING).bind(native::main_id(&f.h).as_uuid()).bind(revoked)
        .execute(&mut *tx).await.map_err(native::sql)?.rows_affected(), 1);
    tx.commit().await.map_err(native::sql)?;
    assert_eq!(pending.finish().await?.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(native::rows(&f.h, EXECUTION).await?, before);
    assert_eq!(audit_count(&f.h, &fact, "scheduler-native-callback-start").await?, 0);
    provider.settled(4).await?;
    f.engine.count(2).await?;
    f.clean().await
}
