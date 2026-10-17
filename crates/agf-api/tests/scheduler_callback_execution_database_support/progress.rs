use super::*;

pub(crate) async fn superseded() -> DomainResult<()> {
    let f = Fixture::new("cb-partition-latest").await?;
    let old_input = f.input("asset-inventory", "owned-old-batch", 0, 2);
    let old = f.admit(old_input.clone()).await?;
    f.start(&old).await?;
    let latest = f.finish("asset-inventory", "owned-new-batch", 0, 1, good()).await?;
    let original_progress = native::rows(&f.h, PROGRESS).await?;
    let before = snapshot(&f.h).await?;
    let denied =
        f.h.request("POST", ROOT, Some(&f.token), Some(f.input("asset-inventory", "owned-old-batch", 1, 2))).await;
    assert_eq!(denied.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(snapshot(&f.h).await?, before);
    passive(&f.admit(old_input).await?);
    assert_eq!(f.complete(&old, good()).await?["state"], "succeeded");
    assert_eq!(native::rows(&f.h, PROGRESS).await?, original_progress);
    let log = f.finish("log-pull", "owned-uses-latest", 0, 1, good()).await?;
    assert_eq!(log["state"], "succeeded");
    assert_ne!(latest["factId"], old["factId"]);
    f.engine.count(2).await?;
    f.clean().await
}

pub(crate) async fn dag() -> DomainResult<()> {
    let f = Fixture::new("cb-six-dag").await?;
    let mut done = Vec::new();
    let before = snapshot(&f.h).await?;
    assert_eq!(
        f.h.request("POST", ROOT, Some(&f.token), Some(f.input("log-pull", "owned-too-early", 0, 1))).await.status,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(snapshot(&f.h).await?, before);
    // Traverse the actual platform_defaults DAG; two distinct terminal partitions per kind.
    for kind in KINDS {
        for index in 0..2 {
            done.push(f.finish(kind, &format!("owned-dag-{kind}"), index, 2, good()).await?);
            if kind == "asset-inventory" && index == 0 {
                let before = snapshot(&f.h).await?;
                assert_eq!(
                    f.h.request("POST", ROOT, Some(&f.token), Some(f.input("log-pull", "owned-partial", 0, 1)))
                        .await
                        .status,
                    StatusCode::PRECONDITION_FAILED
                );
                assert_eq!(snapshot(&f.h).await?, before);
            }
        }
        if kind == "asset-inventory" {
            // No log-pull evidence yet: report requires both inventory and log-pull.
            assert_eq!(
                f.h.request("POST", ROOT, Some(&f.token), Some(f.input("report", "owned-missing-log", 0, 1)))
                    .await
                    .status,
                StatusCode::PRECONDITION_FAILED
            );
        }
    }
    assert_eq!(done.len(), 12);
    assert_eq!(native::rows(&f.h, EXECUTION).await?.len(), 12);
    assert_eq!(native::rows(&f.h, BATCH).await?.len(), 6);
    assert_eq!(native::rows(&f.h, PROGRESS).await?.len(), 6);
    for fact in done {
        assert_eq!(audit_count(&f.h, &fact, "scheduler-native-callback-claim").await?, 1);
        assert_eq!(audit_count(&f.h, &fact, "scheduler-native-callback-start").await?, 1);
        assert_eq!(audit_count(&f.h, &fact, EXECUTION).await?, 1);
        passive(&f.get(&fact).await?);
    }
    f.engine.count(2).await?;
    f.clean().await
}

pub(crate) async fn unqualified() -> DomainResult<()> {
    for flavor in ["partial", "skipped", "failed"] {
        let f = Fixture::new("cb-upstream-gate").await?;
        f.finish("asset-inventory", "owned-previous-success", 0, 1, good()).await?;
        let mut outcome = good();
        let total = if flavor == "partial" { 2 } else { 1 };
        if flavor == "skipped" {
            outcome = json!({"ok":true,"skipped":true,"degraded":false,"artifacts":[]});
        }
        if flavor == "failed" {
            outcome["ok"] = json!(false);
        }
        let result = f.finish("asset-inventory", "owned-latest-not-usable", 0, total, outcome).await?;
        assert_eq!(result["state"], if flavor == "failed" { "failed" } else { "succeeded" });
        let before = snapshot(&f.h).await?;
        for downstream in ["log-pull", "redteam-cruise", "report"] {
            let rejected =
                f.h.request("POST", ROOT, Some(&f.token), Some(f.input(downstream, "owned-not-filled", 0, 1))).await;
            assert_eq!(rejected.status, StatusCode::PRECONDITION_FAILED);
            assert_eq!(snapshot(&f.h).await?, before);
        }
        f.engine.count(2).await?;
        f.clean().await?;
    }
    Ok(())
}

pub(crate) async fn old_context() -> DomainResult<()> {
    for change_source in [false, true] {
        let mut f = Fixture::new("cb-old-progress").await?;
        let original = f.finish("asset-inventory", "owned-before-retarget", 0, 1, good()).await?;
        let version = if change_source {
            native::provider::configure(&f.h, &f.engine, 1, true).await?;
            2
        } else {
            1
        };
        let observation = Id::new();
        let mut input = native::observe(observation, false);
        input["configuration_version"] = json!(version);
        let observed = native::post(&f.h, &format!("{}/observe", native::BASE), input).await?;
        let saved =
            f.h.request(
                "PUT",
                &format!("{}/bindings", native::BASE),
                Some(&f.h.admin),
                Some(replace(Id::new(), 1, observation, version)),
            )
            .await;
        assert_eq!(saved.status, StatusCode::OK);
        f.binding = saved.json();
        f.target = observed["originalTarget"].clone();
        assert_eq!(f.binding["adoptionVersion"], 2);
        let before = snapshot(&f.h).await?;
        assert_eq!(
            f.h.request("POST", ROOT, Some(&f.token), Some(f.input("log-pull", "owned-current-needs-fresh", 0, 1)))
                .await
                .status,
            StatusCode::PRECONDITION_FAILED
        );
        assert_eq!(snapshot(&f.h).await?, before);
        let current = f.finish("asset-inventory", "owned-current-adoption", 0, 1, good()).await?;
        assert_ne!(current["adoptionVersion"], original["adoptionVersion"]);
        if change_source {
            assert_ne!(current["originalTarget"], original["originalTarget"]);
        }
        f.finish("log-pull", "owned-current-allowed", 0, 1, good()).await?;
        f.engine.count(4).await?;
        f.clean().await?;
    }
    Ok(())
}
