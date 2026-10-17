//! Local-only identity provider: real signed ID tokens, PKCE and one-use codes.
#![allow(dead_code)]
use super::*;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use std::sync::Mutex;
use wiremock::{
    Mock, MockServer, Request as MockRequest, ResponseTemplate,
    matchers::{method, path},
};

pub(crate) struct Provider {
    pub server: MockServer,
    pending: Arc<Mutex<BTreeMap<String, (Value, String)>>>,
}
impl Provider {
    pub(crate) async fn start() -> Self {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer":server.uri(), "authorization_endpoint":format!("{}/authorize",server.uri()),
                "token_endpoint":format!("{}/token",server.uri()), "jwks_uri":format!("{}/jwks",server.uri()),
                "code_challenge_methods_supported":["S256"] })))
            .mount(&server)
            .await;
        let jwks: Value = serde_json::from_str(include_str!("../fixtures/oidc-test-jwks.json")).unwrap();
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&server)
            .await;
        let pending: Arc<Mutex<BTreeMap<String, (Value, String)>>> = Arc::default();
        let codes = pending.clone();
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(move |req: &MockRequest| {
                let form: BTreeMap<_, _> = url::form_urlencoded::parse(&req.body).into_owned().collect();
                if form.get("grant_type").map(String::as_str) != Some("authorization_code")
                    || form.get("client_id").map(String::as_str) != Some("console")
                    || form.get("client_secret").map(String::as_str) != Some("local-test-secret")
                    || form.get("redirect_uri").map(String::as_str) != Some("http://127.0.0.1:8081/login/oidc/callback")
                {
                    return ResponseTemplate::new(400);
                }
                let Some((claims, challenge)) =
                    codes.lock().unwrap().remove(form.get("code").map_or("", String::as_str))
                else {
                    return ResponseTemplate::new(400);
                };
                if agf_auth::oidc::challenge(form.get("code_verifier").map_or("", String::as_str)) != challenge {
                    return ResponseTemplate::new(400);
                }
                let mut header = Header::new(Algorithm::ES256);
                header.kid = Some("local-test-key".into());
                if claims["fault"] == "unknown-key" {
                    header.kid = Some("unknown-key".into());
                }
                let key = EncodingKey::from_ec_pem(include_bytes!("../fixtures/oidc-test-only.pem")).unwrap();
                let mut token = encode(&header, &claims, &key).unwrap();
                if claims["fault"] == "signature" {
                    let i = token.rfind('.').unwrap() + 1;
                    let replacement = if &token[i..=i] == "A" { "B" } else { "A" };
                    token.replace_range(i..=i, replacement);
                }
                ResponseTemplate::new(200)
                    .set_body_json(json!({"id_token":token, "access_token":"local-only", "token_type":"Bearer"}))
            })
            .mount(&server)
            .await;
        Self { server, pending }
    }
    pub(crate) fn config(&self) -> Value {
        json!({"enabled":true,"name":"本地模拟身份中心", "issuer":self.server.uri(), "client_id":"console",
            "client_auth":"client_secret_post", "client_secret":"local-test-secret",
            "redirect_uri":"http://127.0.0.1:8081/login/oidc/callback", "auto_provision":true,
            "default_role":"viewer", "email_domains":["example.test"]})
    }
    pub(crate) fn authorize(&self, start: &Value, overrides: Value) -> Value {
        let url = url::Url::parse(start["authorization_url"].as_str().unwrap()).unwrap();
        let q: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["response_type"], "code");
        let now = Timestamp::now().unix_secs();
        let mut claims = json!({"iss":self.server.uri(),"aud":"console", "sub":"employee-one",
            "iat":now,"exp":now+300,"nonce":q["nonce"],"email":"person@example.test",
            "email_verified":true, "name":"企业测试员工"});
        for (k, v) in overrides.as_object().unwrap() {
            claims[k] = v.clone();
        }
        let code = uuid::Uuid::new_v4().to_string();
        self.pending.lock().unwrap().insert(code.clone(), (claims, q["code_challenge"].clone()));
        json!({"tenant_slug":"default", "state":start["state"], "binding":start["binding"], "code":code})
    }
}
