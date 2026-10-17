//! Loopback OAuth server verifies protected-resource discovery, PKCE, binding and refresh.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use wiremock::{
    Mock, MockServer, Request as MockRequest, ResponseTemplate,
    matchers::{method, path},
};

async fn upstream(server: &MockServer, client_id_metadata: bool, dynamic_registration: bool) {
    let issuer = server.uri();
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-protected-resource/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "resource":format!("{issuer}/mcp"),"authorization_servers":[issuer]
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer":issuer,"authorization_endpoint":format!("{issuer}/authorize"),
            "token_endpoint":format!("{issuer}/token"),"response_types_supported":["code"],
            "code_challenge_methods_supported":["S256"],
            "token_endpoint_auth_methods_supported":["none","client_secret_basic"],
            "authorization_response_iss_parameter_supported":true,
            "client_id_metadata_document_supported":client_id_metadata,
            "registration_endpoint":dynamic_registration.then(|| format!("{issuer}/register"))
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(|request: &MockRequest| {
            let form =
                url::form_urlencoded::parse(&request.body).into_owned().collect::<std::collections::BTreeMap<_, _>>();
            if form.get("resource").is_none_or(|value| !value.ends_with("/mcp")) {
                return ResponseTemplate::new(400);
            }
            match form.get("grant_type").map(String::as_str) {
                Some("authorization_code")
                    if form.get("code").map(String::as_str) == Some("test-code")
                        && form.get("code_verifier").is_some_and(|value| value.len() >= 32) =>
                {
                    ResponseTemplate::new(200).set_body_json(json!({"access_token":"first-secret-token",
                        "refresh_token":"refresh-secret-token","token_type":"Bearer","expires_in":1}))
                }
                Some("refresh_token")
                    if form.get("refresh_token").map(String::as_str) == Some("refresh-secret-token") =>
                {
                    ResponseTemplate::new(200).set_body_json(json!({"access_token":"refreshed-secret-token",
                        "token_type":"Bearer","expires_in":3600}))
                }
                _ => ResponseTemplate::new(400),
            }
        })
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(|request: &MockRequest| {
            if request.headers.get("authorization").and_then(|value| value.to_str().ok())
                != Some("Bearer refreshed-secret-token")
            {
                return ResponseTemplate::new(401).set_body_string("secret upstream challenge");
            }
            ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0","id":7,
                "result":{"tools":[{"name":"readonly_echo"}]}}))
        })
        .mount(server)
        .await;
}

async fn endpoint(h: &Harness, server: &MockServer) -> Value {
    let row = h
        .post(
            "/api/v1/mcp/endpoints",
            json!({
                "expected_version":0,"name":"OAuth loopback","url":format!("{}/mcp",server.uri()),
                "enabled":true,"idle_timeout_secs":30,"allowed_origins":[]
            }),
        )
        .await;
    assert_eq!(row.status, StatusCode::OK, "{}", row.text);
    row.json()
}

#[tokio::test]
async fn oauth_discovers_resource_checks_browser_binding_and_refreshes_before_proxying() {
    let h = setup().await;
    let server = MockServer::start().await;
    upstream(&server, false, false).await;
    let row = endpoint(&h, &server).await;
    let id = row["id"].as_str().unwrap();
    let base = format!("/api/v1/mcp/endpoints/{id}/oauth");
    let saved = h
        .request(
            "PUT",
            &base,
            Some(&h.admin),
            Some(json!({
                "expected_revision":null,"issuer":server.uri(),"client_id":"mcp-test-client",
                "client_auth":"none","client_secret":null,"scope":"mcp:tools offline_access",
                "redirect_uri":"http://127.0.0.1:8081/mcp/oauth/callback"
            })),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.json()["resource"], format!("{}/mcp", server.uri()));
    assert!(!saved.text.contains("first-secret-token"));
    let start = h.post(&format!("{base}/start"), json!({})).await;
    assert_eq!(start.status, StatusCode::OK, "{}", start.text);
    let url = url::Url::parse(start.json()["authorization_url"].as_str().unwrap()).unwrap();
    let params = url.query_pairs().into_owned().collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(params["resource"], format!("{}/mcp", server.uri()));
    assert_eq!(params["code_challenge_method"], "S256");
    assert!(!params["code_challenge"].is_empty());
    let mut body = json!({"state":start.json()["state"],"binding":start.json()["binding"],
        "code":"test-code","iss":server.uri()});
    body["iss"] = json!("http://127.0.0.1:9");
    assert_eq!(h.post(&format!("{base}/complete"), body.clone()).await.status, StatusCode::UNAUTHORIZED);
    body["iss"] = json!(server.uri());
    body["binding"] = json!("wrong-browser-binding-secret-aaaaaaaaaaaa");
    assert_eq!(h.post(&format!("{base}/complete"), body.clone()).await.status, StatusCode::UNAUTHORIZED);
    body["binding"] = start.json()["binding"].clone();
    let completed = h.post(&format!("{base}/complete"), body.clone()).await;
    assert_eq!(completed.status, StatusCode::OK, "{}", completed.text);
    assert_eq!(h.post(&format!("{base}/complete"), body).await.status, StatusCode::UNAUTHORIZED);
    let status = h.get(&base).await;
    assert_eq!(status.json()["status"]["connected"], true);
    assert_eq!(status.json()["status"]["refreshable"], true);
    assert!(!status.text.contains("secret-token"));
    let frame = json!({"jsonrpc":"2.0","id":7,"method":"tools/list","params":{
        "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}}});
    let authorization = format!("Bearer {}", h.admin);
    let reply = h
        .request_with(
            "POST",
            &format!("/api/v1/mcp/proxy/{id}"),
            &[
                ("authorization", authorization.as_str()),
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "tools/list"),
                ("accept", "application/json, text/event-stream"),
            ],
            Some(frame),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
    assert_eq!(reply.json()["result"]["tools"][0]["name"], "readonly_echo");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.iter().filter(|request| request.url.path() == "/token").count(), 2);
    let changed = h
        .post(
            "/api/v1/mcp/endpoints",
            json!({
                "id":id,"expected_version":1,"name":"OAuth loopback moved",
                "url":format!("{}/another-resource",server.uri()),"enabled":true,
                "idle_timeout_secs":30,"allowed_origins":[]
            }),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    assert_eq!(h.get(&base).await.json()["status"]["connected"], false);
    let disconnected = h.post(&format!("{base}/disconnect"), json!({})).await;
    assert_eq!(disconnected.status, StatusCode::OK, "{}", disconnected.text);
    assert_eq!(h.get(&base).await.json()["status"]["connected"], false);
}

#[tokio::test]
async fn oauth_configuration_rejects_static_bearer_and_viewer_write() {
    let h = setup().await;
    let server = MockServer::start().await;
    upstream(&server, false, false).await;
    let row = endpoint(&h, &server).await;
    let id = row["id"].as_str().unwrap();
    let base = format!("/api/v1/mcp/endpoints/{id}/oauth");
    let configuration = json!({"expected_revision":null,"issuer":server.uri(),
        "client_id":"mcp-test-client","client_auth":"none","client_secret":null,
        "scope":"","redirect_uri":"http://127.0.0.1:8081/mcp/oauth/callback"});
    assert_eq!(
        h.request("PUT", &base, Some(&h.viewer), Some(configuration.clone())).await.status,
        StatusCode::FORBIDDEN
    );
    let changed = h
        .post(
            "/api/v1/mcp/endpoints",
            json!({"id":id,"expected_version":1,
        "name":"OAuth loopback","url":format!("{}/mcp",server.uri()),
        "enabled":true,"idle_timeout_secs":30,"allowed_origins":[],"bearer_token":"static-secret"}),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    assert_eq!(h.request("PUT", &base, Some(&h.admin), Some(configuration)).await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn oauth_accepts_same_origin_bearer_resource_metadata_challenge() {
    let h = setup().await;
    let server = MockServer::start().await;
    let issuer = server.uri();
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-protected-resource/mcp"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-protected-resource"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("HEAD"))
        .and(path("/mcp"))
        .respond_with(
            ResponseTemplate::new(401)
                .insert_header("www-authenticate", format!("Bearer resource_metadata=\"{issuer}/metadata\"")),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "resource":format!("{issuer}/mcp"),"authorization_servers":[issuer]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer":issuer,"authorization_endpoint":format!("{issuer}/authorize"),
            "token_endpoint":format!("{issuer}/token"),"response_types_supported":["code"],
            "code_challenge_methods_supported":["S256"],
            "token_endpoint_auth_methods_supported":["none"]
        })))
        .mount(&server)
        .await;
    let row = endpoint(&h, &server).await;
    let uri = format!("/api/v1/mcp/endpoints/{}/oauth", row["id"].as_str().unwrap());
    let saved = h
        .request(
            "PUT",
            &uri,
            Some(&h.admin),
            Some(json!({
                "expected_revision":null,"issuer":issuer,"client_id":"mcp-test-client",
                "client_auth":"none","scope":"mcp:tools","redirect_uri":"http://127.0.0.1:8081/mcp/oauth/callback"
            })),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.json()["resource"], format!("{issuer}/mcp"));
}

#[tokio::test]
async fn hosted_client_id_metadata_is_public_exact_and_revision_bound() {
    let h = setup().await;
    let server = MockServer::start().await;
    upstream(&server, true, false).await;
    let endpoint = endpoint(&h, &server).await;
    let id = endpoint["id"].as_str().unwrap();
    let base = format!("/api/v1/mcp/endpoints/{id}/oauth");
    let mut input = json!({
        "expected_revision":null,"registration":"client_id_metadata",
        "issuer":server.uri(),"client_id":"","client_auth":"none",
        "scope":"mcp:tools","redirect_uri":"http://127.0.0.1:8081/mcp/oauth/callback"
    });
    assert_eq!(h.request("PUT", &base, Some(&h.admin), Some(input.clone())).await.status, StatusCode::BAD_REQUEST);
    input["redirect_uri"] = json!("https://console.example.com/mcp/oauth/callback");
    let saved = h.request("PUT", &base, Some(&h.admin), Some(input.clone())).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.json()["registration"], "client_id_metadata");
    let client_id = saved.json()["client_id"].as_str().unwrap().to_owned();
    let url = url::Url::parse(&client_id).unwrap();
    assert_eq!(url.origin().ascii_serialization(), "https://console.example.com");
    let public = h.request("GET", url.path(), None, None).await;
    assert_eq!(public.status, StatusCode::OK, "{}", public.text);
    assert_eq!(public.json()["client_id"], client_id);
    assert_eq!(public.json()["redirect_uris"], json!(["https://console.example.com/mcp/oauth/callback"]));
    assert_eq!(public.json()["token_endpoint_auth_method"], "none");
    assert!(!public.text.contains("mcp:tools"));
    let started = h.post(&format!("{base}/start"), json!({})).await;
    assert_eq!(started.status, StatusCode::OK, "{}", started.text);
    let auth_url = url::Url::parse(started.json()["authorization_url"].as_str().unwrap()).unwrap();
    let params = auth_url.query_pairs().into_owned().collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(params["client_id"], client_id);
    input["expected_revision"] = saved.json()["revision"].clone();
    let revised = h.request("PUT", &base, Some(&h.admin), Some(input)).await;
    assert_eq!(revised.status, StatusCode::OK, "{}", revised.text);
    assert_ne!(revised.json()["client_id"], client_id);
    assert_eq!(h.request("GET", url.path(), None, None).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn dynamic_registration_seals_secret_and_reuses_unchanged_client() {
    let h = setup().await;
    let server = MockServer::start().await;
    upstream(&server, false, true).await;
    let callback = "http://127.0.0.1:8081/mcp/oauth/callback";
    Mock::given(method("POST"))
        .and(path("/register"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "client_id":"dynamic-client","client_secret":"registered-secret",
            "client_secret_expires_at":0,"token_endpoint_auth_method":"client_secret_basic",
            "redirect_uris":[callback],"grant_types":["authorization_code","refresh_token"],
            "response_types":["code"],"registration_access_token":"registration-management-secret"
        })))
        .mount(&server)
        .await;
    let endpoint = endpoint(&h, &server).await;
    let base = format!("/api/v1/mcp/endpoints/{}/oauth", endpoint["id"].as_str().unwrap());
    let mut input = json!({
        "expected_revision":null,"registration":"dynamic","issuer":server.uri(),
        "client_id":"","client_auth":"client_secret_basic","client_secret":null,
        "scope":"mcp:tools","redirect_uri":callback
    });
    let saved = h.request("PUT", &base, Some(&h.admin), Some(input.clone())).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.json()["client_id"], "dynamic-client");
    assert_eq!(saved.json()["client_auth"], "client_secret_basic");
    assert_eq!(saved.json()["client_secret_configured"], true);
    assert!(!saved.text.contains("registered-secret"));
    assert!(!saved.text.contains("registration-management-secret"));
    let revision = saved.json()["revision"].clone();
    input["expected_revision"] = revision.clone();
    let same = h.request("PUT", &base, Some(&h.admin), Some(input.clone())).await;
    assert_eq!(same.status, StatusCode::OK, "{}", same.text);
    assert_eq!(same.json()["revision"], revision);
    let started = h.post(&format!("{base}/start"), json!({})).await;
    assert_eq!(started.status, StatusCode::OK, "{}", started.text);
    let completed = h
        .post(
            &format!("{base}/complete"),
            json!({
                "state":started.json()["state"],"binding":started.json()["binding"],
                "code":"test-code","iss":server.uri()
            }),
        )
        .await;
    assert_eq!(completed.status, StatusCode::OK, "{}", completed.text);
    assert_eq!(h.get(&base).await.json()["status"]["connected"], true);
    let requests = server.received_requests().await.unwrap();
    let registrations = requests.iter().filter(|request| request.url.path() == "/register").collect::<Vec<_>>();
    assert_eq!(registrations.len(), 1);
    let registration: Value = serde_json::from_slice(&registrations[0].body).unwrap();
    assert_eq!(registration["redirect_uris"], json!([callback]));
    assert_eq!(registration["token_endpoint_auth_method"], "client_secret_basic");
    assert!(!registration.to_string().contains("registered-secret"));
    let token = requests.iter().find(|request| request.url.path() == "/token").unwrap();
    assert!(
        token
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("Basic "))
    );
    assert!(!String::from_utf8_lossy(&token.body).contains("registered-secret"));
    input["scope"] = json!("mcp:tools offline_access");
    let changed = h.request("PUT", &base, Some(&h.admin), Some(input)).await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    assert_ne!(changed.json()["revision"], revision);
    assert_eq!(h.get(&base).await.json()["status"]["connected"], false);
    assert_eq!(
        server.received_requests().await.unwrap().iter().filter(|request| request.url.path() == "/register").count(),
        2
    );
}

#[tokio::test]
async fn dynamic_registration_uses_initial_token_once_without_storing_it() {
    let h = setup().await;
    let server = MockServer::start().await;
    upstream(&server, false, true).await;
    let callback = "http://127.0.0.1:8081/mcp/oauth/callback";
    Mock::given(method("POST"))
        .and(path("/register"))
        .respond_with(move |request: &MockRequest| {
            if request.headers.get("authorization").and_then(|value| value.to_str().ok())
                != Some("Bearer one-time-registration-token")
            {
                return ResponseTemplate::new(401);
            }
            ResponseTemplate::new(201).set_body_json(json!({
                "client_id":"private-dynamic-client","token_endpoint_auth_method":"none",
                "redirect_uris":[callback],"grant_types":["authorization_code"],"response_types":["code"]
            }))
        })
        .mount(&server)
        .await;
    let endpoint = endpoint(&h, &server).await;
    let base = format!("/api/v1/mcp/endpoints/{}/oauth", endpoint["id"].as_str().unwrap());
    let mut input = json!({
        "expected_revision":null,"registration":"dynamic","issuer":server.uri(),
        "client_id":"","client_auth":"none","client_secret":null,
        "scope":"mcp:tools","redirect_uri":callback
    });
    assert_ne!(h.request("PUT", &base, Some(&h.admin), Some(input.clone())).await.status, StatusCode::OK);
    input["registration_access_token"] = json!("one-time-registration-token");
    let saved = h.request("PUT", &base, Some(&h.admin), Some(input.clone())).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert!(!saved.text.contains("one-time-registration-token"));
    input["expected_revision"] = saved.json()["revision"].clone();
    input["registration_access_token"] = Value::Null;
    let repeated = h.request("PUT", &base, Some(&h.admin), Some(input)).await;
    assert_eq!(repeated.status, StatusCode::OK, "{}", repeated.text);
    assert_eq!(repeated.json()["revision"], saved.json()["revision"]);
    assert_eq!(
        server.received_requests().await.unwrap().iter().filter(|request| request.url.path() == "/register").count(),
        2
    );
}
