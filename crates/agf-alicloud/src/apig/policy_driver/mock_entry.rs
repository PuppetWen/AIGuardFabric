use super::{
    CurrentGuard, MockBridge, MockScope, MockSourceGuard, Observation, PreparedUpdate, WriteOutcome,
    client::{acknowledged, check_deadline, driver_deadline},
    observe, profile,
};
use agf_core::error::{DomainError, DomainResult};
use serde_json::json;
use tokio::time::{Instant, timeout_at};

impl MockBridge<'_> {
    /// Observe the three exact resources of an explicitly initialized encrypted Mock target.
    ///
    /// This never seeds a target and uses the same response/evidence validation as the live driver.
    /// The original submission deadline is capped at 30 seconds, without extending its budget.
    ///
    /// # Errors
    /// The target is uninitialized, its source/authority changes, evidence is invalid, or time expires.
    pub async fn observe_current(
        &self,
        scope: &MockScope,
        source: MockSourceGuard<'_>,
        guard: &dyn CurrentGuard,
        submitted_deadline: Instant,
    ) -> DomainResult<Observation> {
        let deadline = driver_deadline(submitted_deadline);
        timeout_at(deadline, self.observe_inner(scope, source, guard, deadline))
            .await
            .map_err(|_| unavailable("APIG Mock observation deadline expired"))?
    }

    /// Reobserve the authenticated baseline, then invoke the Mock provider update at most once.
    ///
    /// Once UpdatePolicy execution is entered, any error or timeout is Unknown: a committed
    /// provider change can outlive its post-commit guard. No implicit seeding or retry occurs.
    ///
    /// # Errors
    /// A changed baseline, invalid prepared target/input, guard, or deadline prevents update entry.
    pub async fn publish_once(
        &self,
        scope: &MockScope,
        source: MockSourceGuard<'_>,
        update: &PreparedUpdate,
        guard: &dyn CurrentGuard,
        submitted_deadline: Instant,
    ) -> DomainResult<WriteOutcome> {
        let deadline = driver_deadline(submitted_deadline);
        let input = timeout_at(deadline, async {
            if &scope.binding != update.baseline.binding() {
                return Err(observe::evidence("Prepared APIG Mock target differs"));
            }
            let current = self.observe_inner(scope, source, guard, deadline).await?;
            if current.fingerprint() != update.baseline_fingerprint() {
                return Err(DomainError::Conflict("APIG configuration changed; read and preview a new intent".into()));
            }
            let input = profile::update_input(update)?;
            guard.validate().await?;
            check_deadline(deadline)?;
            Ok(input)
        })
        .await
        .map_err(|_| unavailable("APIG Mock preflight deadline expired"))??;

        check_deadline(deadline)?;
        let result = timeout_at(deadline, self.execute(scope, source, "UpdatePolicy", &input, guard, deadline)).await;
        Ok(match result {
            Ok(Ok(response)) => acknowledged(&response),
            Ok(Err(_)) | Err(_) => WriteOutcome::Unknown,
        })
    }

    async fn observe_inner(
        &self,
        scope: &MockScope,
        source: MockSourceGuard<'_>,
        guard: &dyn CurrentGuard,
        deadline: Instant,
    ) -> DomainResult<Observation> {
        let binding = &scope.binding;
        binding.validate()?;
        let api = self
            .execute(
                scope,
                source,
                "GetHttpApi",
                &json!({"httpApiId":binding.http_api_id,"expandPolicyConfigs":false}),
                guard,
                deadline,
            )
            .await?;
        let policy =
            self.execute(scope, source, "GetPolicy", &json!({"policyId":binding.policy_id}), guard, deadline).await?;
        let attachment = self
            .execute(
                scope,
                source,
                "GetPolicyAttachment",
                &json!({"policyAttachmentId":binding.attachment_id}),
                guard,
                deadline,
            )
            .await?;
        guard.validate().await?;
        check_deadline(deadline)?;
        observe::parse_current(binding, &api, &policy, &attachment)
    }
}

fn unavailable(cause: &str) -> DomainError {
    DomainError::DependencyUnavailable { dependency: "alicloud-apig-mock".into(), cause: cause.into() }
}
