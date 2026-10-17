//! Credentials arrive only through bounded stdin, never a file, readiness DTO, argv or environment override.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read, path::Path};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Login {
    pub(super) run_id: String,
    pub(super) owner: String,
    pub(super) username: String,
    pub(super) password: String,
}
impl Login {
    pub(super) fn read() -> DomainResult<Self> {
        let mut bytes = Vec::new();
        std::io::stdin().lock().take(16_385).read_to_end(&mut bytes).map_err(|_| fail("stdin"))?;
        if bytes.len() > 16_384 {
            return Err(fail("stdin_size"));
        }
        let login: Self = serde_json::from_slice(&bytes).map_err(|_| fail("stdin_shape"))?;
        if login.run_id.len() != 32
            || !login.run_id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || login.owner != format!("{}{}", owned::OWNER_PREFIX, login.run_id)
            || login.username != format!("ui-{}", &login.run_id[..12])
            || !(24..=128).contains(&login.password.len())
            || login.password.chars().any(char::is_control)
        {
            return Err(fail("stdin_identity"));
        }
        Ok(login)
    }
    pub(super) fn tenant_slug(&self) -> String {
        format!("scheduler-ui-{}", &self.run_id[..12])
    }
    pub(super) fn config(project: &Path, data: &Path) -> DomainResult<agf_core::config::AppConfig> {
        // AppState also reads these process switches directly; never inherit a production/demo path or seed.
        if std::env::var_os("AGF_RISK_HISTORY_PATH").is_some()
            || std::env::var("AGF_SEED_FIXTURES").is_ok_and(|v| v != "0")
            || std::env::var("AGF_SHARED_RATELIMIT_REQUIRED").is_ok_and(|v| v != "0")
        {
            return Err(fail("inherited_override"));
        }
        let random = || agf_core::secret::generate_token();
        let values: BTreeMap<String, String> = [
            ("AGF_ENV", "test".into()),
            ("AGF_MOCK_MODE", "0".into()),
            ("AGF_NATS_ENABLED", "0".into()),
            ("AGF_LOG_LEVEL", "warn".into()),
            ("AGF_JWT_SECRET", random()),
            ("AGF_JWT_ISSUER", "aiguardfabric".into()),
            ("AGF_MASTER_KEY_BASE64", STANDARD.encode(Sha256::digest(random().as_bytes()))),
            ("AGF_FINGERPRINT_SALT", random()),
            ("AGF_PASSWORD_MIN_LENGTH", "12".into()),
            ("AGF_FORCE_PASSWORD_CHANGE", "0".into()),
            ("AGF_PROJECT_ROOT", project.to_string_lossy().into_owned()),
            ("AGF_DATA_DIR", data.to_string_lossy().into_owned()),
            ("AGF_CORS_ALLOW_ORIGINS", "http://127.0.0.1:28081".into()),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect();
        agf_core::config::from_env_map(&values).map_err(|_| fail("config"))
    }
}
