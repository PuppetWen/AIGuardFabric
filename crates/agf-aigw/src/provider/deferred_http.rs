//! Opt-in atomic attempts use one HTTP dispatch, no redirects, protocol retry or environment proxy.
use super::*;

pub(crate) fn single_dispatch(
    endpoint: &ModelEndpoint,
    credentials: &dyn CredentialResolver,
) -> DomainResult<Arc<dyn ProviderAdapter>> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_proxy()
        .timeout(Duration::from_secs(110))
        .build()
        .map_err(|_| DomainError::Config("Cannot construct the single-dispatch model client".into()))?;
    let provider: Arc<dyn ProviderAdapter> = match endpoint.provider {
        LlmProvider::Anthropic => {
            let mut provider = AnthropicProvider::from_endpoint(endpoint, credentials);
            provider.client = client;
            Arc::new(provider)
        }
        LlmProvider::Gemini => {
            let mut provider = GeminiProvider::from_endpoint(endpoint, credentials);
            provider.client = client;
            Arc::new(provider)
        }
        LlmProvider::Bedrock => {
            let mut provider = BedrockProvider::from_endpoint(endpoint, credentials);
            provider.client = client;
            Arc::new(provider)
        }
        _ => {
            let mut provider = OpenAiCompatProvider::from_endpoint(endpoint, credentials);
            provider.client = client;
            Arc::new(provider)
        }
    };
    Ok(provider)
}
