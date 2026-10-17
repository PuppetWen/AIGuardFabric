use super::*;

pub(crate) async fn concurrent() -> DomainResult<()> {
    let f = Fixture::new("cb-twin").await?;
    let second = f.second().await?;
    let input = f.input("asset-inventory", "owned-twin", 0, 1);
    let (a, b) = tokio::join!(
        call(&f.h, &f.token, "POST", ROOT, Some(input.clone())),
        call(&second, &f.token, "POST", ROOT, Some(input.clone()))
    );
    let a = a?;
    let b = b?;
    assert_eq!(a["factId"], b["factId"]);
    assert_eq!(a["claimId"], b["claimId"]);
    assert_eq!([&a, &b].iter().filter(|row| row["mayConfirmStart"] == true).count(), 1);
    assert_eq!(a["mayExecute"], false);
    assert_eq!(b["mayExecute"], false);
    assert_eq!(native::rows(&f.h, EXECUTION).await?.len(), 1);
    assert_eq!(audit_count(&f.h, &a, "scheduler-native-callback-claim").await?, 1);
    let before = snapshot(&f.h).await?;
    passive(&f.get(&a).await?);
    passive(&f.admit(input.clone()).await?);
    assert_eq!(snapshot(&f.h).await?, before);
    let start = format!("{}/validate", fact_path(&a)?);
    let (first, other) = tokio::join!(
        call(&f.h, &f.token, "POST", &start, Some(claim(&a))),
        call(&second, &f.token, "POST", &start, Some(claim(&a)))
    );
    let first = first?;
    let other = other?;
    assert_eq!([&first, &other].iter().filter(|row| row["mayExecute"] == true).count(), 1);
    assert_eq!(first["startedAt"], other["startedAt"]);
    assert_eq!(first["executionLeaseExpiresAt"], other["executionLeaseExpiresAt"]);
    assert_eq!(audit_count(&f.h, &a, "scheduler-native-callback-start").await?, 1);
    let mut alias = input;
    alias["request_id"] = json!(Id::new());
    let duplicate = call(&second, &f.token, "POST", ROOT, Some(alias.clone())).await?;
    passive(&duplicate);
    assert_eq!(duplicate["requestId"], a["requestId"]);
    assert_eq!(duplicate["factId"], a["factId"]);
    assert_eq!(audit_count(&f.h, &a, "scheduler-native-callback-request").await?, 1);
    let after_alias = snapshot(&f.h).await?;
    passive(&call(&second, &f.token, "POST", ROOT, Some(alias)).await?);
    passive(&f.start(&a).await?);
    assert_eq!(snapshot(&f.h).await?, after_alias);
    let done = f.complete(&a, good()).await?;
    assert_eq!(done["state"], "succeeded");
    let before = snapshot(&f.h).await?;
    assert_eq!(f.complete(&a, good()).await?, done);
    assert_eq!(call(&second, &f.token, "GET", &fact_path(&a)?, None).await?, done);
    assert_eq!(snapshot(&f.h).await?, before);
    assert_eq!(audit_count(&f.h, &a, EXECUTION).await?, 1);
    f.engine.count(2).await?;
    f.clean().await
}

pub(crate) async fn conflicts() -> DomainResult<()> {
    let f = Fixture::new("cb-collisions").await?;
    let original = f.input("asset-inventory", "owned-collision", 0, 2);
    let fact = f.admit(original.clone()).await?;
    let baseline = snapshot(&f.h).await?;
    let modifications = [
        ("kind", json!("rule-hot-reload")),
        ("source_fingerprint", json!("0".repeat(64))),
        ("binding_version", json!(2)),
        ("configuration_version", json!(2)),
        ("partition_total", json!(3)),
        ("job_execution_id", json!("owned-other-body")),
    ];
    for (field, value) in modifications {
        let mut changed = original.clone();
        changed[field] = value.clone();
        assert_eq!(f.h.request("POST", ROOT, Some(&f.token), Some(changed)).await.status, StatusCode::CONFLICT);
        if field != "job_execution_id" {
            let mut global = original.clone();
            global["request_id"] = json!(Id::new());
            global[field] = value;
            assert_eq!(f.h.request("POST", ROOT, Some(&f.token), Some(global)).await.status, StatusCode::CONFLICT);
        }
        assert_eq!(snapshot(&f.h).await?, baseline);
    }
    let path = format!("{}/validate", fact_path(&fact)?);
    assert_eq!(
        f.h.request("POST", &path, Some(&f.token), Some(json!({"claim_id":Id::new()}))).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(snapshot(&f.h).await?, baseline);
    let second = f.second().await?;
    assert_eq!(call(&second, &f.token, "GET", &fact_path(&fact)?, None).await?["claimId"], fact["claimId"]);
    passive(&f.admit(original).await?);
    assert_eq!(snapshot(&f.h).await?, baseline);
    f.engine.count(2).await?;
    f.clean().await
}

pub(crate) async fn purpose() -> DomainResult<()> {
    let f = Fixture::new("cb-uuid-purpose").await?;
    let input = f.input("asset-inventory", "owned-purpose", 0, 1);
    let request = native::identifier(&input, "request_id")?;
    f.admit(input).await?;
    let before = snapshot(&f.h).await?;
    let observed = f.h.post(&format!("{}/observe", native::BASE), native::observe(request, false)).await;
    assert_eq!(observed.status, StatusCode::CONFLICT);
    let binding =
        f.h.request(
            "PUT",
            &format!("{}/bindings", native::BASE),
            Some(&f.h.admin),
            Some(replace(request, 1, f.observation, 1)),
        )
        .await;
    assert_eq!(binding.status, StatusCode::CONFLICT);
    assert_eq!(snapshot(&f.h).await?, before);
    let native_binding = Id::new();
    assert_eq!(
        f.h.request(
            "PUT",
            &format!("{}/bindings", native::BASE),
            Some(&f.h.admin),
            Some(json!({"action":"disable","request_id":native_binding,"expected_version":1}))
        )
        .await
        .status,
        StatusCode::OK
    );
    let before = snapshot(&f.h).await?;
    for occupied in [f.observation, native_binding] {
        let mut input = f.input("asset-inventory", "owned-native-reverse", 0, 1);
        input["request_id"] = json!(occupied);
        assert_eq!(f.h.request("POST", ROOT, Some(&f.token), Some(input)).await.status, StatusCode::CONFLICT);
        assert_eq!(snapshot(&f.h).await?, before);
    }
    f.engine.count(2).await?;
    f.clean().await
}

pub(crate) async fn archive() -> DomainResult<()> {
    let f = Fixture::new("cb-proof-archive").await?;
    let before = f.binding["items"].clone();
    native::archive(&f.h, &[f.observation]).await?;
    assert_eq!(native::read(&f.h, &native::receipt(f.observation)).await?["status"], "archived");
    let current = native::read(&f.h, native::BASE).await?;
    assert_eq!(current["bindings"]["items"], before);
    assert_eq!(current["bindings"]["current"], true);
    let fact = f.admit(f.input("asset-inventory", "owned-after-body-archive", 0, 1)).await?;
    assert_eq!(fact["mayConfirmStart"], true);
    assert_eq!(f.start(&fact).await?["mayExecute"], true);
    assert_eq!(f.complete(&fact, good()).await?["state"], "succeeded");
    f.engine.count(2).await?;
    f.clean().await
}

pub(crate) async fn lookup() -> DomainResult<()> {
    let f = Fixture::new("cb-request-lookup").await?;
    let input = f.input("asset-inventory", "owned-lost-response", 0, 1);
    let request = native::identifier(&input, "request_id")?;
    let fact = f.admit(input.clone()).await?;
    let lookup = format!("{ROOT}/requests/{request}");
    let before = snapshot(&f.h).await?;
    let second = f.second().await?;
    // Deliberately discard start permission from the original response; a lookup never recreates it.
    let original = call(&second, &f.token, "GET", &lookup, None).await?;
    passive(&original);
    assert_eq!(original["factId"], fact["factId"]);
    assert_eq!(original["claimId"], fact["claimId"]);
    assert_eq!(original["requestId"], fact["requestId"]);
    assert_eq!(snapshot(&f.h).await?, before);
    assert_eq!(
        f.h.request("GET", &format!("{ROOT}/requests/{}", Id::new()), Some(&f.token), None).await.status,
        StatusCode::NOT_FOUND
    );
    let other =
        f.h.post(
            "/api/v1/settings/api-keys",
            json!({"name":format!("owned-other-key-{}",Id::new()),
        "scopes":["alicloud:read","assets:read"]}),
        )
        .await;
    assert_eq!(other.status, StatusCode::CREATED);
    let other = other.json();
    let other_token = other["plaintext"].as_str().ok_or_else(|| native::wire::fixture_error("other key absent"))?;
    let denied_before = snapshot(&f.h).await?;
    assert_eq!(f.h.request("GET", &lookup, Some(other_token), None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(snapshot(&f.h).await?, denied_before);
    let foreign = f.case.foreign().await?;
    let issued = foreign
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":format!("owned-foreign-key-{}",Id::new()),
        "scopes":["alicloud:read","assets:read"]}),
        )
        .await;
    assert_eq!(issued.status, StatusCode::CREATED);
    let issued = issued.json();
    let foreign_token =
        issued["plaintext"].as_str().ok_or_else(|| native::wire::fixture_error("foreign key absent"))?;
    let before_foreign = snapshot(&f.h).await?;
    assert_eq!(foreign.request("GET", &lookup, Some(foreign_token), None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(snapshot(&f.h).await?, before_foreign);
    let mut alias = input.clone();
    let alias_id = Id::new();
    alias["request_id"] = json!(alias_id);
    passive(&f.admit(alias.clone()).await?);
    let before = snapshot(&f.h).await?;
    let resolved = call(&second, &f.token, "GET", &format!("{ROOT}/requests/{alias_id}"), None).await?;
    passive(&resolved);
    assert_eq!(resolved["factId"], fact["factId"]);
    assert_eq!(resolved["requestId"], json!(request));
    assert_eq!(snapshot(&f.h).await?, before);
    // A persisted alias may not point at an unrelated fact/body while keeping its original hash.
    let index_id = deterministic_id("agf.scheduler.callback.request.v1", &format!("{}:{alias_id}", f.h.tenant));
    let index = native::row(&f.h, REQUEST, index_id)
        .await?
        .ok_or_else(|| native::wire::fixture_error("request alias absent"))?;
    let unrelated = f.admit(f.input("asset-inventory", "owned-other-fact", 0, 1)).await?;
    let mut corrupt = index.clone();
    corrupt["fact_id"] = unrelated["factId"].clone();
    super::crypto::with_record(&f, REQUEST, index_id, &index, &corrupt, || {
        Box::pin(async {
            let baseline = snapshot(&f.h).await?;
            assert_eq!(
                f.h.request("GET", &format!("{ROOT}/requests/{alias_id}"), Some(&f.token), None).await.status,
                StatusCode::INTERNAL_SERVER_ERROR
            );
            assert_eq!(snapshot(&f.h).await?, baseline);
            Ok(())
        })
    })
    .await?;
    f.case.owner.check().await?;
    assert_eq!(sqlx::query("UPDATE api_keys SET scopes=scopes-'assets:read',updated_at=now() WHERE tenant_id=$1 AND id=$2 AND NOT revoked AND deleted_at IS NULL")
        .bind(f.h.tenant.as_uuid()).bind(f.key.as_uuid()).execute(&f.case.owner.pool).await.map_err(native::sql)?.rows_affected(), 1);
    let baseline = snapshot(&f.h).await?;
    assert_eq!(f.h.request("GET", &lookup, Some(&f.token), None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(snapshot(&f.h).await?, baseline);
    f.engine.count(2).await?;
    f.clean().await
}
