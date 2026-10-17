//! Actual delivered HTTP requests with unknown results remain permanent across API instances.
use crate::{common::*, publication_db as db, transport::*};
use agf_core::{
    audit::{AuditAction, AuditOutcome},
    error::DomainResult,
    ids::{Id, deterministic_id},
};

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_MSE_CONFIG_PUBLICATION_DATABASE_OWNER"]
async fn lost_error_and_false_provider_responses_persist_unknown_risk_without_resending_after_restart()
-> DomainResult<()> {
    for (label, reply, content_changed) in [
        ("mse-pub-unknown-lost", Reply::Lost, true),
        ("mse-pub-unknown-error", Reply::Error, false),
        ("mse-pub-unknown-false", Reply::False, false),
    ] {
        let case = db::open(label).await?;
        let f = Fixture::attach(case.h.clone()).await?;
        let preview = f.ready().await?;
        let request = Id::new();
        f.engine.reply(reply).await;
        let result = f.apply(&preview, request).await?;
        assert_eq!(result["status"], "uncertain", "{label}");
        assert_eq!(result["cloudWrite"]["status"], "unknown", "{label}");
        assert_eq!(result["readback"]["status"], "not_attempted");
        assert_eq!(result["localPublication"]["status"], "published");
        assert_eq!(result["completionState"], "complete");
        assert_eq!(result["consumerApplied"], Value::Null);
        assert_eq!(result["target"]["mocked"], false);
        assert_eq!(result["target"]["transportMode"], "loopback-test");
        assert_eq!(f.engine.content().await != INITIAL, content_changed);
        assert_eq!(f.engine.counts().await, (2, 1));
        let seen = f.engine.seen().await;
        assert!(seen.iter().all(|row| row.authenticated));
        assert_eq!(seen.iter().filter(|row| row.method == "POST").count(), 1);

        let scope = id(&result["target"], "targetScopeId")?;
        let risk_id = deterministic_id("agf.mse.config-publication.risk", &format!("{}:{scope}", f.h.tenant));
        let risk = db::row(&f.h, MAIN, risk_id).await?;
        assert_eq!(risk["tenant"], json!(f.h.tenant));
        assert_eq!(risk["scope_id"], json!(scope));
        assert_eq!(risk["latest_unknown"], json!(request));
        assert_eq!(risk["unknown_count"], 1);
        assert_eq!(risk["lease_expires_at"], result["leaseExpiresAt"]);
        let fact = db::row(&f.h, FACT, db::fact_id(f.h.tenant, request)).await?;
        assert_eq!(fact["scope"]["target"], result["target"]);
        assert_eq!(fact["outcome"]["type"], "operation");
        assert_eq!(fact["outcome"]["receipt"]["cloud_write"], "unknown");
        assert_eq!(
            fact["outcome"]["receipt"]["source_policy_versions"],
            json!([{"policy_id":id(&f.policy,"id")?,"version":1}])
        );

        let committed = snapshot(&f.h).await?;
        let second = route(case.second_instance().await, f.engine.address)?;
        let original = read(&second, &receipt(request)).await?;
        assert_eq!(original, result);
        assert_eq!(original["sourceCurrent"], true);
        assert_eq!(original["currentPolicyVersions"], json!([{"policyId":id(&f.policy,"id")?,"version":1}]));
        let state = read(&second, BASE).await?;
        assert_eq!(state["unresolvedOperationId"], json!(request));
        assert_eq!(db::row(&second, MAIN, risk_id).await?, risk);
        assert_eq!(db::row(&second, FACT, db::fact_id(second.tenant, request)).await?, fact);
        assert_eq!(snapshot(&second).await?, committed);
        assert_eq!(post(&second, &format!("{BASE}/operations"), apply_input(&preview, request)?).await?, original);
        assert_eq!(post(&second, &format!("{}/recover", receipt(request)), json!({})).await?, original);
        assert_eq!(read(&second, &receipt(request)).await?, original);
        assert_eq!(snapshot(&second).await?, committed, "duplicate reads/recovery must not mutate {label}");
        assert_eq!(f.engine.counts().await, (2, 1));
        assert!(second.state.configurations.list::<Value>(second.tenant, PENDING).await?.is_empty());
        assert_eq!(audits(&second, request, "mse-config-publication-claim").await?.len(), 1);
        let terminal = audits(&second, request, "mse-config-publication").await?;
        assert_eq!(terminal.len(), 1);
        assert_eq!(terminal[0].action, AuditAction::Execute);
        assert_eq!(terminal[0].outcome, AuditOutcome::Failure);
        db::chain(&second).await?;
        case.pool.close().await;
    }
    Ok(())
}
