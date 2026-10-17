//! Both model and MCP assertions count actual requests at an owned loopback HTTP server.
use super::*;
use std::time::Duration;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

const MODEL: &str = "owned-policy-model";
const SECRET: &str = "synthetic-owned-policy-upstream";
const VERSION: &str = "2026-07-28";

pub(crate) struct Fixture {
    pub(crate) h: Harness,
    server: MockServer,
    mcp_id: Id,
}

impl Fixture {
    pub(crate) async fn attach(h: Harness) -> Self {
        let h = live(h);
        let server = MockServer::start().await;
        let address = url::Url::parse(&server.uri()).unwrap();
        assert_eq!(address.host_str(), Some("127.0.0.1"));
        assert!(address.port().is_some_and(|port| port > 0));
        Mock::given(method("POST")).and(path("/chat/completions")).and(header("authorization",format!("Bearer {SECRET}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id":"owned-response","object":"chat.completion","created":1,"model":MODEL,
                "choices":[{"index":0,"message":{"role":"assistant","content":"owned response"},"finish_reason":"stop"}],
                "usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}))).mount(&server).await;
        Mock::given(method("POST")).and(path("/mcp")).and(header("authorization",format!("Bearer {SECRET}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"owned result"}],"isError":false}})))
            .mount(&server).await;
        let endpoint = h
            .post(
                "/api/v1/gateway/endpoints",
                json!({"name":"owned-policy-loopback","provider":"openai","model":MODEL,
            "base_url":server.uri(),"api_key":SECRET,"expected_version":0}),
            )
            .await;
        assert_eq!(endpoint.status, StatusCode::CREATED, "{}", endpoint.text);
        assert_eq!(endpoint.json()["mocked"], false);
        assert_eq!(h.get("/api/v1/gateway/endpoints").await.json()["items"].as_array().unwrap().len(), 1);
        let mcp = h
            .post(
                "/api/v1/mcp/endpoints",
                json!({"expected_version":0,"name":"owned-policy-mcp","url":format!("{}/mcp",server.uri()),
            "enabled":true,"idle_timeout_secs":5,"bearer_token":SECRET}),
            )
            .await;
        assert_eq!(mcp.status, StatusCode::OK, "{}", mcp.text);
        let mcp_id = serde_json::from_value(mcp.json()["id"].clone()).unwrap();
        Self { h, server, mcp_id }
    }

    pub(crate) async fn gateway_for(&self, h: &Harness) -> Resp {
        tokio::time::timeout(
            Duration::from_secs(20),
            h.post(
                "/v1/chat/completions",
                json!({"model":MODEL,"max_tokens":4,"temperature":1,
            "messages":[{"role":"user","content":"hello owned policy"}]}),
            ),
        )
        .await
        .unwrap()
    }
    pub(crate) async fn gateway(&self) -> Resp {
        self.gateway_for(&self.h).await
    }

    pub(crate) async fn mcp(&self) -> Resp {
        let bearer = format!("Bearer {}", self.h.admin);
        let frame = json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"owned-query","arguments":{"query":"hello"},
            "_meta":{"io.modelcontextprotocol/protocolVersion":VERSION,"io.modelcontextprotocol/clientInfo":{"name":"owned-policy-test","version":"1"}}}});
        tokio::time::timeout(
            Duration::from_secs(20),
            self.h.request_with(
                "POST",
                &format!("/api/v1/mcp/proxy/{}", self.mcp_id),
                &[
                    ("authorization", bearer.as_str()),
                    ("mcp-protocol-version", VERSION),
                    ("mcp-method", "tools/call"),
                    ("mcp-name", "owned-query"),
                    ("accept", "application/json, text/event-stream"),
                ],
                Some(frame),
            ),
        )
        .await
        .unwrap()
    }

    pub(crate) async fn calls(&self, uri: &str) -> usize {
        self.server.received_requests().await.unwrap().iter().filter(|request| request.url.path() == uri).count()
    }

    pub(crate) async fn assert_gateway(&self, denied: bool) {
        let before = self.calls("/chat/completions").await;
        let response = self.gateway().await;
        assert_eq!(response.status, if denied { StatusCode::FORBIDDEN } else { StatusCode::OK }, "{}", response.text);
        if !denied {
            assert_eq!(response.header("x-agf-mocked"), "false");
            assert_eq!(response.header("x-agf-cached"), "false");
            assert_eq!(response.json()["usage"]["total_tokens"], 6);
        }
        assert_eq!(self.calls("/chat/completions").await, before + usize::from(!denied));
    }

    pub(crate) async fn assert_both(&self, denied: bool) {
        self.assert_gateway(denied).await;
        let before = self.calls("/mcp").await;
        let response = self.mcp().await;
        assert_eq!(response.status, if denied { StatusCode::FORBIDDEN } else { StatusCode::OK }, "{}", response.text);
        if !denied {
            assert_eq!(response.json()["result"]["isError"], false);
        }
        assert_eq!(self.calls("/mcp").await, before + usize::from(!denied));
    }
}
