//! RPC form parameters participate in the same signature as the query parameters.
use super::*;
use crate::signer::percent_encode;

impl RpcClient {
    pub fn build_form(
        &self,
        action: &str,
        version: &str,
        query: &[(String, String)],
        form: &[(String, String)],
    ) -> DomainResult<RpcRequest> {
        if query.iter().any(|(key, _)| form.iter().any(|(other, _)| key == other)) {
            return Err(DomainError::Validation("云 API 查询参数和表单参数不能重名".into()));
        }
        let body = canonicalized_query(form);
        let mut request = match self.config.style {
            SignStyle::Rpc => {
                let mut all = query.to_vec();
                all.extend_from_slice(form);
                let mut request = self.build(action, version, "POST", &all)?;
                let form_keys: Vec<String> = form.iter().map(|(key, _)| percent_encode(key)).collect();
                request.query = request
                    .query
                    .split('&')
                    .filter(|part| !form_keys.iter().any(|key| part.starts_with(&format!("{key}="))))
                    .collect::<Vec<_>>()
                    .join("&");
                request.body = body;
                request
            }
            SignStyle::V3 => {
                self.build_roa(&RoaCall { action, version, method: "POST", path: "/", params: query, body: &body })?
            }
        };
        request.headers.insert("content-type".into(), "application/x-www-form-urlencoded".into());
        Ok(request)
    }
    pub async fn call_form(
        &self,
        action: &str,
        version: &str,
        query: &[(String, String)],
        form: &[(String, String)],
    ) -> DomainResult<RpcResponse> {
        self.execute_async(&self.build_form(action, version, query, form)?).await
    }
}
