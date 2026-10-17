//! Permanent callback admission and local completion never dispatch a business handler.
mod admission;
mod completion;
mod current;
mod dependencies;
mod evidence;
mod identity;
mod input;
mod model;
mod routes;
mod staging;
mod start;
mod views;

pub(super) use model::{BATCH, EXECUTION, PENDING, PROGRESS, REQUEST};
pub(crate) use routes::router;

pub(super) fn request_key(tenant: agf_core::ids::TenantId, id: agf_core::ids::Id) -> (String, agf_core::ids::Id) {
    identity::request_key(tenant, id)
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_crypto;
#[cfg(test)]
mod tests_support;
