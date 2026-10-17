use super::{
    provider::{self, Engine},
    *,
};
use agf_core::credential::SecretMaterial;
use agf_storage::crypto::FieldCipher;
use secrecy::ExposeSecret;
use sha2::{Digest as _, Sha256};

pub(crate) async fn bounded_archive() -> DomainResult<()> {
    let case = SqlCase::open("sch-128-archive-100").await?;
    mock(&case.h, 0, true).await?;
    let mut ids = Vec::new();
    // Actual public requests, actual encrypted observations and one claim/read audit pair per UUID.
    // This is not 128 copies of one ciphertext or a fabricated capacity counter.
    for index in 0..128 {
        let id = Id::new();
        let observed = post(&case.h, &format!("{BASE}/observe"), observe(id, index == 0)).await?;
        assert_eq!(observed["status"], "observed");
        assert_eq!(observed["total"], 6);
        ids.push(id);
    }
    let second = case.second().await?;
    let full = read(&second, BASE).await?;
    assert_eq!(full["detailedObservationCount"], 128);
    assert_eq!(rows(&second, FACT).await?.len(), 128);
    let before = snapshot(&second).await?;
    assert_eq!(
        second.post(&format!("{BASE}/observe"), observe(Id::new(), false)).await.status,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(snapshot(&second).await?, before);
    let facts = rows(&second, FACT).await?;
    let generation = number(&full, "generation")?;
    let result = archive(&second, &ids[..100]).await?;
    assert_eq!(result["archivedCount"], 100);
    assert_eq!(rows(&second, FACT).await?, facts);
    let bodies = rows(&second, BODY).await?;
    assert_eq!(bodies.len(), 128);
    assert_eq!(bodies.iter().filter(|body| body["class"] == "archived").count(), 100);
    assert!(bodies.iter().filter(|body| body["class"] == "archived").all(|body| body.get("secret").is_none()));
    let remaining = bodies
        .iter()
        .filter(|body| body["class"] == "content")
        .try_fold(0_usize, |sum, body| Ok::<_, DomainError>(sum + serde_json::to_vec(body)?.len()))?;
    assert_eq!(number(&result, "storedContentBytes")?, remaining as u64);
    let after = snapshot(&second).await?;
    for id in &ids[..100] {
        let archived = read(&second, &receipt(*id)).await?;
        assert_eq!(archived["status"], "archived");
        assert_eq!(archived["originalStatus"], "observed");
        assert_eq!(post(&second, &format!("{BASE}/observe"), observe(*id, *id == ids[0])).await?, archived);
    }
    assert_eq!(snapshot(&second).await?, after);
    let rejected = second
        .post(
            &format!("{BASE}/observations/archive"),
            json!({"expected_generation":generation,"request_ids":&ids[..100]}),
        )
        .await;
    assert_eq!(rejected.status, StatusCode::CONFLICT);
    assert_eq!(snapshot(&second).await?, after);
    archive(&second, &ids[..100]).await?;
    assert_eq!(snapshot(&second).await?, after);
    let fresh = Id::new();
    post(&second, &format!("{BASE}/observe"), observe(fresh, false)).await?;
    assert_eq!(read(&second, BASE).await?["detailedObservationCount"], 29);
    assert_eq!(rows(&second, FACT).await?.len(), 129);
    let archive_audit = audits(&second, main_id(&second), "scheduler-native-archive").await?;
    assert_eq!(archive_audit.len(), 1);
    assert_eq!(archive_audit[0].after.as_ref().map(|a| a["count"].clone()), Some(json!(100)));
    for id in ids {
        assert_eq!(audits(&second, id, "scheduler-native-read-claim").await?.len(), 1);
        terminal(&second, id, AuditOutcome::Success).await?;
    }
    terminal(&second, fresh, AuditOutcome::Success).await?;
    case.owner.pool.close().await;
    Ok(())
}
pub(crate) async fn large_and_authenticated() -> DomainResult<()> {
    let case = SqlCase::open("sch-large-aad").await?;
    let engine = Engine::new(2000, true).await?;
    let h = provider::attach(case.h.clone(), &engine)?;
    provider::configure(&h, &engine, 0, true).await?;
    let id = Id::new();
    let observed = post(&h, &format!("{BASE}/observe"), observe(id, false)).await?;
    assert_eq!(observed["total"], 2000);
    assert_eq!(observed["observation"]["jobs"].as_array().map(Vec::len), Some(100));
    engine.count(21).await?;
    let key = record_id(&h, BODY, id);
    let original = row(&h, BODY, key).await?.ok_or_else(|| wire::fixture_error("large body absent"))?;
    let secret: SecretMaterial = serde_json::from_value(original["secret"].clone())?;
    assert_eq!(secret.aad.as_deref(), Some(FieldCipher::make_aad(&h.tenant, &key).as_str()));
    let clear = agf_api::model_gateway::cipher(&h.state)?.decrypt(&secret)?;
    let clear = clear.expose_secret();
    assert!(clear.len() > 1024 * 1024 && clear.len() <= 2 * 1024 * 1024);
    assert_eq!(original["hash"], hex::encode(Sha256::digest(clear.as_bytes())));
    let safe: Value = serde_json::from_str(clear)?;
    assert_eq!(safe["jobs"].as_array().map(Vec::len), Some(2000));
    let size = serde_json::to_vec(&original)?.len();
    assert!(size > 1024 * 1024 && size <= 4 * 1024 * 1024);
    assert_eq!(read(&h, BASE).await?["storedContentBytes"], size);
    let second = provider::attach(case.second().await?, &engine)?;
    let committed = snapshot(&second).await?;
    assert_eq!(read(&second, &receipt(id)).await?, observed);
    for page in 1..=20 {
        let dto = read(&second, &format!("{}?page={page}", receipt(id))).await?;
        assert_eq!(dto["observation"]["jobs"].as_array().map(Vec::len), Some(100));
        assert_eq!(dto["observation"]["totalPages"], 20);
    }
    assert_eq!(snapshot(&second).await?, committed);
    engine.count(21).await?;
    case.owner.check().await?;
    let mut corrupt = original.clone();
    corrupt["secret"]["aad"] = json!(FieldCipher::make_aad(&second.tenant, &Id::new()));
    second.state.configurations.put(second.tenant, BODY, key, &corrupt).await?;
    let before = snapshot(&second).await?;
    assert_eq!(second.get(&receipt(id)).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(snapshot(&second).await?, before);
    engine.count(21).await?;
    case.owner.check().await?;
    second.state.configurations.put(second.tenant, BODY, key, &original).await?;
    assert_eq!(snapshot(&second).await?, committed);
    assert_eq!(read(&second, &receipt(id)).await?, observed);
    terminal(&second, id, AuditOutcome::Success).await?;
    case.owner.pool.close().await;
    Ok(())
}
