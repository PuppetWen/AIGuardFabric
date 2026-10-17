//! Original authenticated call authority for the separately registered semantic repository.
//!
//! No route enables semantic reuse here. Service code must first resolve a complete trusted
//! embedding/chat profile, current policy/source records and an atomic fee reservation.

mod authority;

pub use authority::{AgentAuthorityView, CurrentCallAuthority};
