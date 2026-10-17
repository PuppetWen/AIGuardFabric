use crate::openapi::Contract;
use agf_core::{
    enums::AliCloudService,
    error::{DomainError, DomainResult},
};

// These private typed contracts deliberately do not extend generic cloud invoke.
// Generic APIG carriers must gain a safe projection/barrier before sensitive actions become public.
pub(super) fn definition(action: &str) -> DomainResult<Contract> {
    if matches!(action, "GetHttpApi" | "UpdatePluginAttachment") {
        return crate::openapi::contract(AliCloudService::Apig, action);
    }
    let contracts: Vec<Contract> = serde_json::from_str(include_str!("contracts.json"))
        .map_err(|_| DomainError::Internal("APIG private typed contract is invalid".into()))?;
    contracts
        .into_iter()
        .find(|item| item.action == action)
        .ok_or_else(|| DomainError::PreconditionFailed("This APIG typed action is unsupported".into()))
}
