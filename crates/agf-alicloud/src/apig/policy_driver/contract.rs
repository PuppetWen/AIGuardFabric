use crate::openapi::Contract;
use agf_core::{enums::AliCloudService, error::DomainResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Action {
    HttpApi,
    Policy,
    Attachment,
    Update,
}

impl Action {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::HttpApi => "GetHttpApi",
            Self::Policy => "GetPolicy",
            Self::Attachment => "GetPolicyAttachment",
            Self::Update => "UpdatePolicy",
        }
    }

    pub(super) fn definition(self) -> DomainResult<Contract> {
        crate::openapi::contract(AliCloudService::Apig, self.name())
    }
}
