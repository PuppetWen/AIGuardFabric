//! 使用 HTTPS 下载发布资产，禁用重定向、Cookie、自动代理和不安全 TLS。
use super::{
    paths::{deny, io, plain},
    trust::VerifiedUpdate,
};
use agf_core::error::DomainResult;
use sha2::{Digest, Sha256};
use std::{fs::OpenOptions, io::Write, path::Path, time::Duration};
pub(crate) async fn artifact(update: &VerifiedUpdate, path: &Path) -> DomainResult<()> {
    plain(path)?;
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_mins(1))
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd();
    if let Some(ca) = &update.policy.enterprise_ca {
        plain(ca)?;
        let metadata = std::fs::metadata(ca).map_err(io)?;
        if !metadata.is_file() || metadata.len() > 1024 * 1024 {
            return Err(deny("Enterprise CA file exceeds budget"));
        }
        let pem = std::fs::read(ca).map_err(io)?;
        builder = builder.add_root_certificate(
            reqwest::Certificate::from_pem(&pem).map_err(|_| deny("Enterprise CA PEM is invalid"))?,
        );
    }
    let client = builder.build().map_err(|_| deny("Update HTTPS client could not be configured"))?;
    // 精确使用已验签地址，不转发令牌，也不跟随重定向。
    let mut response = client
        .get(&update.plan.url)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await
        .map_err(|_| deny("Update HTTPS request failed"))?;
    if response.status() != reqwest::StatusCode::OK
        || response.content_length().is_some_and(|size| size != update.plan.size)
        || response.headers().contains_key(reqwest::header::CONTENT_ENCODING)
    {
        return Err(deny("Update artifact response does not match the authenticated size/encoding"));
    }
    let mut output = OpenOptions::new().write(true).create_new(true).open(path).map_err(io)?;
    let mut count = 0_u64;
    let mut hash = Sha256::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| deny("Update artifact transfer was interrupted"))? {
        count = count.checked_add(chunk.len() as u64).ok_or_else(|| deny("Artifact byte count overflow"))?;
        if count > update.plan.size || count > update.policy.max_bytes {
            return Err(deny("Update artifact exceeds its byte budget"));
        }
        hash.update(&chunk);
        output.write_all(&chunk).map_err(io)?;
    }
    if count != update.plan.size || hex::encode(hash.finalize()) != update.plan.sha256.to_ascii_lowercase() {
        return Err(deny("Update artifact size or SHA-256 mismatch"));
    }
    output.sync_all().map_err(io)?;
    Ok(())
}
