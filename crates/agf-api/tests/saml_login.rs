//! SP-initiated SAML with a local signing IdP, including browser and replay checks.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use saml_rs::{
    AuthnRequest, BrowserInput, CertificatePem, Credentials, EntityId, IdpConfig, IdpValidationPolicy,
    MetadataTrustPolicy, NameId, PrivateKeyPem, ReplayPolicy, RespondSso, Saml, SamlValidationContext, SpDescriptor,
    SsoEndpoint, Subject,
};
use std::time::SystemTime;

const SETTINGS: &str = "/api/v1/settings/identity/saml";
const START: &str = "/api/v1/auth/saml/start";
const ACS: &str = "/api/v1/auth/saml/default/acs";
const STATUS: &str = "/api/v1/auth/saml/status";
const COMPLETE: &str = "/api/v1/auth/saml/complete";
const SP_ENTITY: &str = "https://console.example.test/api/v1/auth/saml/default/metadata";
const SP_ACS: &str = "https://console.example.test/api/v1/auth/saml/default/acs";
const IDP_ENTITY: &str = "https://idp.example.test/metadata";

fn test_idp() -> Saml<saml_rs::Idp> {
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    let pem = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap().to_pkcs8_pem(LineEnding::LF).unwrap();
    let key = rcgen::KeyPair::from_pem(pem.as_str()).unwrap();
    let cert = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap().self_signed(&key).unwrap();
    Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY).unwrap())
            .sso_endpoint(SsoEndpoint::redirect("https://idp.example.test/sso").unwrap())
            .credentials(Credentials {
                signing_key: Some(PrivateKeyPem::new(key.serialize_pem())),
                signing_certificate: Some(CertificatePem::new(cert.pem())),
                ..Credentials::default()
            })
            .validation(IdpValidationPolicy::strict())
            .build()
            .unwrap(),
    )
    .unwrap()
}

fn config(idp: &Saml<saml_rs::Idp>) -> Value {
    json!({"expected_revision":null,"enabled":true,"name":"Test SAML",
        "idp_metadata_xml":idp.metadata_xml(), "sp_entity_id":SP_ENTITY,"acs_url":SP_ACS,
        "auto_provision":true,"default_role":"viewer","email_domains":["example.test"],
        "email_attribute":"email","name_attribute":"displayName"})
}

async fn post_form(h: &Harness, fields: &[saml_rs::FormField]) -> Resp {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields.iter().map(|field| (field.name(), field.value())))
        .finish();
    send(
        &h.app,
        Request::builder()
            .method("POST")
            .uri(ACS)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap(),
    )
    .await
}

async fn signed_response(h: &Harness, idp: &Saml<saml_rs::Idp>) -> (Value, Vec<saml_rs::FormField>) {
    let start = h.request("POST", START, None, Some(json!({"tenant_slug":"default"}))).await;
    assert_eq!(start.status, StatusCode::OK, "{}", start.text);
    let data = start.json();
    let url = url::Url::parse(data["authorization_url"].as_str().unwrap()).unwrap();
    let metadata = h.request("GET", "/api/v1/auth/saml/default/metadata", None, None).await;
    assert_eq!(metadata.status, StatusCode::OK, "{}", metadata.text);
    let sp = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY).unwrap(),
        &metadata.text,
        MetadataTrustPolicy::UnsignedForCompatibility,
    )
    .unwrap();
    let request = idp
        .receive_sso(
            &sp,
            BrowserInput::<AuthnRequest>::redirect(url.query().unwrap()),
            SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility),
        )
        .unwrap();
    let response = idp
        .respond_sso(
            &sp,
            &request,
            Subject::new(NameId::new("alice@example.test", None), Vec::new()),
            RespondSso::post().sign_response(),
        )
        .unwrap();
    (
        json!({"tenant_slug":"default","state":data["state"],"binding":data["binding"]}),
        response.post_form().unwrap().fields().to_vec(),
    )
}

#[tokio::test]
async fn saml_signed_flow_browser_binding_roles_and_replay() {
    let h = setup().await;
    let idp = test_idp();
    assert_eq!(h.request("PUT", SETTINGS, Some(&h.viewer), Some(config(&idp))).await.status, StatusCode::FORBIDDEN);
    let saved = h.request("PUT", SETTINGS, Some(&h.admin), Some(config(&idp))).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert!(!saved.text.contains("PRIVATE KEY"));
    let stored: Vec<Value> = h.state.configurations.list(h.tenant, "saml-provider").await.unwrap();
    assert!(!serde_json::to_string(&stored).unwrap().contains("PRIVATE KEY"));
    let (flow, fields) = signed_response(&h, &idp).await;
    let mut wrong = flow.clone();
    wrong["binding"] = json!("x".repeat(64));
    assert_eq!(h.request("POST", STATUS, None, Some(wrong.clone())).await.status, StatusCode::UNAUTHORIZED);
    let accepted = post_form(&h, &fields).await;
    assert_eq!(accepted.status, StatusCode::SEE_OTHER, "{}", accepted.text);
    assert!(accepted.header("location").contains("/login/saml/callback?state="));
    assert_eq!(post_form(&h, &fields).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(h.request("POST", STATUS, None, Some(wrong.clone())).await.status, StatusCode::UNAUTHORIZED);
    let status = h.request("POST", STATUS, None, Some(flow.clone())).await;
    assert_eq!(status.status, StatusCode::OK, "{}", status.text);
    assert_eq!(status.json()["mfa_required"], false);
    assert_eq!(h.request("POST", COMPLETE, None, Some(wrong)).await.status, StatusCode::UNAUTHORIZED);
    let login = h.request("POST", COMPLETE, None, Some(flow.clone())).await;
    assert_eq!(login.status, StatusCode::OK, "{}", login.text);
    assert_eq!(login.json()["roles"], json!(["viewer"]));
    assert_eq!(login.json()["user"]["idp"], "saml");
    assert_eq!(h.request("POST", COMPLETE, None, Some(flow)).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn saml_rejects_invalid_response_and_configuration() {
    let h = setup().await;
    let idp = test_idp();
    let mut bad = config(&idp);
    bad["acs_url"] = json!("https://attacker.example.test/acs");
    assert_eq!(h.request("PUT", SETTINGS, Some(&h.admin), Some(bad)).await.status, StatusCode::BAD_REQUEST);
    let mut bad = config(&idp);
    bad["default_role"] = json!("superadmin");
    assert_eq!(h.request("PUT", SETTINGS, Some(&h.admin), Some(bad)).await.status, StatusCode::BAD_REQUEST);
    let saved = h.request("PUT", SETTINGS, Some(&h.admin), Some(config(&idp))).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    let (_flow, mut fields) = signed_response(&h, &idp).await;
    let response = fields.iter_mut().find(|field| field.name() == "SAMLResponse").unwrap();
    *response = saml_rs::FormField::new("SAMLResponse", "tampered");
    assert_eq!(post_form(&h, &fields).await.status, StatusCode::UNAUTHORIZED);
    let (flow, fields) = signed_response(&h, &idp).await;
    assert_eq!(post_form(&h, &fields).await.status, StatusCode::SEE_OTHER);
    let mut stale = config(&idp);
    stale["expected_revision"] = saved.json()["revision"].clone();
    stale["enabled"] = json!(false);
    assert_eq!(h.request("PUT", SETTINGS, Some(&h.admin), Some(stale)).await.status, StatusCode::OK);
    assert_eq!(h.request("POST", COMPLETE, None, Some(flow)).await.status, StatusCode::PRECONDITION_FAILED);
}
