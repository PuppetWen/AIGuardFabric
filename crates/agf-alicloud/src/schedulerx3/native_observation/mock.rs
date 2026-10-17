use super::{Observation, Scope, parse_current};
use crate::http::RpcResponse;
use agf_core::error::{DomainError, DomainResult};
use serde_json::Value;
use std::fmt;

/// Explicit, process-local owned example provider; it never creates real cloud jobs.
///
/// Ordinary observations cannot seed it. This small driver mock is not an API workflow,
/// a durable database provider or proof that six platform callbacks were registered.
#[derive(Default)]
pub struct MockState {
    seeded: Option<(Scope, RpcResponse, Vec<RpcResponse>)>,
}

impl fmt::Debug for MockState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("MockState").field("seeded", &self.seeded.is_some()).finish_non_exhaustive()
    }
}

impl MockState {
    /// Explicitly seed only cluster-agf-demo / app-agf-demo from the owned fixture.
    ///
    /// An existing seed is retained. Unknown targets are rejected rather than synthesized.
    /// The enclosing API must separately authorize any explicit Mock initialization.
    ///
    /// # Errors
    /// Wrong scope, malformed owned fixture or an inconsistent existing seed.
    pub fn seed_owned_fixture(&mut self, scope: &Scope) -> DomainResult<()> {
        scope.validate()?;
        if scope.cluster_id != "cluster-agf-demo" || scope.app_name != "app-agf-demo" {
            return Err(unseeded());
        }
        if let Some((prior, _, _)) = &self.seeded {
            return if prior == scope { Ok(()) } else { Err(unseeded()) };
        }
        let fixture: Value = serde_json::from_str(include_str!("owned_fixture.json"))?;
        let app = response(fixture.get("GetApp").ok_or_else(super::fields::invalid)?);
        let page = response(fixture.get("ListJobs").ok_or_else(super::fields::invalid)?);
        let pages = vec![page];
        parse_current(scope, &app, &pages)?;
        self.seeded = Some((scope.clone(), app, pages));
        Ok(())
    }

    /// Read an already seeded exact example scope through the real strict parser.
    ///
    /// # Errors
    /// No seed, a different scope, or invalid provider evidence.
    pub fn observe(&self, scope: &Scope) -> DomainResult<Observation> {
        scope.validate()?;
        let (prior, app, pages) = self.seeded.as_ref().ok_or_else(unseeded)?;
        if prior != scope {
            return Err(unseeded());
        }
        parse_current(scope, app, pages)
    }
}

fn response(value: &Value) -> RpcResponse {
    RpcResponse { status: 200, body: value.clone(), raw: String::new() }
}

fn unseeded() -> DomainError {
    DomainError::PreconditionFailed("Scheduler Mock target has not been explicitly seeded as an owned example".into())
}
