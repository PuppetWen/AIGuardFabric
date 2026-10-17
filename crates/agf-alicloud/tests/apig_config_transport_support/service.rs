use super::{Captured, Reply, Server, fixture_error};
use agf_alicloud::apig::config_driver::{ContentBinding, ModelBinding, ServicePatch};
use agf_core::error::DomainResult;
use serde_json::{Value, json};
use std::{
    fmt,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
pub(crate) struct Service {
    values: Arc<Mutex<Value>>,
}
impl fmt::Debug for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Service").field("raw", &"[redacted]").finish_non_exhaustive()
    }
}
impl Service {
    pub(crate) fn new() -> DomainResult<Self> {
        Ok(Self {
            values: Arc::new(Mutex::new(serde_json::from_str(include_str!(
                "../../src/apig/config_driver/fixture.json"
            ))?)),
        })
    }
    pub(crate) fn snapshot(&self) -> DomainResult<Value> {
        Ok(self.values.lock().map_err(|_| fixture_error("fixture lock failed"))?.clone())
    }
    pub(crate) fn mutate(&self, op: impl FnOnce(&mut Value)) -> DomainResult<()> {
        let mut value = self.values.lock().map_err(|_| fixture_error("fixture lock failed"))?;
        op(&mut value);
        Ok(())
    }
    pub(crate) fn content(&self) -> DomainResult<ContentBinding> {
        Ok(serde_json::from_value(self.snapshot()?["contentBinding"].clone())?)
    }
    pub(crate) fn models(&self) -> DomainResult<ModelBinding> {
        Ok(serde_json::from_value(self.snapshot()?["modelBinding"].clone())?)
    }
    pub(crate) async fn server(&self) -> DomainResult<Server> {
        let own = self.clone();
        Server::start(move |request| own.respond(request)).await
    }
    pub(crate) fn respond(&self, request: &Captured) -> DomainResult<Reply> {
        let action = request.headers.get("x-acs-action").ok_or_else(|| fixture_error("missing action"))?;
        let (method, path) = match action.as_str() {
            "GetPluginAttachment" => ("GET", "/v1/plugin-attachments/pa-owned"),
            "GetHttpApi" => ("GET", "/v1/http-apis/api-owned?expandPolicyConfigs=false"),
            "UpdatePluginAttachment" => ("PUT", "/v1/plugin-attachments/pa-owned"),
            "UpdateHttpApi" => ("PUT", "/v1/http-apis/api-owned"),
            _ => return Err(fixture_error("unexpected action")),
        };
        if request.method != method || request.target != path {
            return Err(fixture_error("incorrect exact method/path"));
        }
        if method == "GET" {
            if !request.body.is_empty() {
                return Err(fixture_error("GET body forbidden"));
            }
            return Ok(Reply::json(200, &self.snapshot()?["responses"][action]));
        }
        let body: Value = serde_json::from_str(&request.body)?;
        let fields = body.as_object().ok_or_else(|| fixture_error("non-object body"))?;
        let mut values = self.values.lock().map_err(|_| fixture_error("fixture lock failed"))?;
        if action == "UpdatePluginAttachment" {
            if fields.len() != 3
                || body["attachResourceIds"] != json!(["api-owned"])
                || !body["enable"].is_boolean()
                || !body["pluginConfig"].is_string()
            {
                return Err(fixture_error("incorrect plugin body"));
            }
            let data = &mut values["responses"]["GetPluginAttachment"]["data"];
            data["pluginConfig"] = body["pluginConfig"].clone();
            data["enable"] = body["enable"].clone();
        } else {
            if body["onlyChangeConfig"] != json!(true) || body["basePath"] != json!("/v1") {
                return Err(fixture_error("model save must not deploy"));
            }
            let data = &mut values["responses"]["GetHttpApi"]["data"];
            for (key, value) in fields {
                if key != "onlyChangeConfig" {
                    data[key] = value.clone();
                }
            }
        }
        Ok(Reply::json(200, &json!({"code":"Ok","requestId":"owned-config-write"})))
    }
}
pub(crate) fn patches() -> Vec<ServicePatch> {
    vec![
        ServicePatch {
            service_id: "svc-one".into(),
            version: Some("r1".into()),
            expected_model_name: "observed-one".into(),
            model_name: "observed-one".into(),
            weight: 25,
        },
        ServicePatch {
            service_id: "svc-two".into(),
            version: Some("r2".into()),
            expected_model_name: "observed-two".into(),
            model_name: "observed-two".into(),
            weight: 75,
        },
    ]
}
