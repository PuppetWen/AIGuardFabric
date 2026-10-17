//! Parse comma-separated selections without losing any values from console multi-select controls.
use crate::{
    error::{ApiError, ApiResult},
    query::ListQuery,
};
use agf_core::{
    enums::{RiskDomain, Severity},
    error::DomainError,
};
use agf_storage::repository::FindingFilter;

pub(super) fn parse(query: &ListQuery) -> ApiResult<FindingFilter> {
    let values =
        |key| query.filter(key).unwrap_or("").split(',').map(str::trim).filter(|s| !s.is_empty()).collect::<Vec<_>>();
    let invalid = |error| ApiError::new(DomainError::Validation(error));
    Ok(FindingFilter {
        domains: values("domain")
            .into_iter()
            .map(|s| RiskDomain::parse(s).map_err(invalid))
            .collect::<Result<_, _>>()?,
        severities: values("severity")
            .into_iter()
            .map(|s| Severity::parse(s).map_err(invalid))
            .collect::<Result<_, _>>()?,
        minimum: query.filter("min_severity").map(|s| Severity::parse(s).map_err(invalid)).transpose()?,
        states: values(if query.filter("state").is_some() { "state" } else { "status" })
            .into_iter()
            .map(super::assets::parse_finding_state)
            .collect::<Result<_, _>>()?,
    })
}
