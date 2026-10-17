use std::{
    fmt,
    sync::atomic::{AtomicU8, Ordering},
};

use reqwest::header::{ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE, HeaderValue};
use tokio::time::Instant;

use super::{
    EmbeddingAttempt, EmbeddingCancellation, EmbeddingDispatch, EmbeddingFailure, EmbeddingOutcome, EmbeddingProfile,
    EmbeddingReservation, MAX_INPUT_BYTES, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, wire,
};

/// One explicit attempt, with an immutable service profile and sensitive credential header.
/// No permission, tokenizer, reservation commit, retry, cache or billing settlement is performed here.
pub struct EmbeddingClient {
    profile: EmbeddingProfile,
    http: reqwest::Client,
    authorization: HeaderValue,
}

impl fmt::Debug for EmbeddingClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("EmbeddingClient").field("profile", &self.profile).finish_non_exhaustive()
    }
}

impl EmbeddingClient {
    pub fn from_service_profile(profile: EmbeddingProfile, api_key: &str) -> Result<Self, EmbeddingFailure> {
        if api_key.is_empty() || api_key.len() > 4096 || !api_key.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(EmbeddingFailure::Credentials);
        }
        let mut authorization =
            HeaderValue::from_str(&format!("Bearer {api_key}")).map_err(|_| EmbeddingFailure::Credentials)?;
        authorization.set_sensitive(true);
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .http1_only()
            .pool_max_idle_per_host(0)
            .https_only(!profile.loopback_test)
            .build()
            .map_err(|_| EmbeddingFailure::Configuration)?;
        Ok(Self { profile, http, authorization })
    }

    /// The token bound must come from the outer trusted model tokenizer or conservative estimator.
    /// Passing a reservation does not authorize this call. Drop/cancel after dispatch is possibly consumed.
    pub async fn embed(
        &self,
        input: &str,
        input_tokens_bound: u64,
        reservation: EmbeddingReservation,
        original_deadline: Instant,
        cancellation: &EmbeddingCancellation,
    ) -> EmbeddingAttempt {
        let not_sent = |failure| self.failure(reservation, EmbeddingDispatch::NotSent, failure);
        if cancellation.is_cancelled() {
            return not_sent(EmbeddingFailure::Cancelled);
        }
        if Instant::now() >= original_deadline {
            return not_sent(EmbeddingFailure::Deadline);
        }
        let body = match self.request_body(input, input_tokens_bound, reservation) {
            Ok(body) => body,
            Err(failure) => return not_sent(failure),
        };
        let request = match self
            .http
            .post(self.profile.request_url.clone())
            .header(AUTHORIZATION, self.authorization.clone())
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .header(ACCEPT_ENCODING, "identity")
            .body(body)
            .build()
        {
            Ok(request) => request,
            Err(_) => return not_sent(EmbeddingFailure::Configuration),
        };
        let dispatch = AtomicU8::new(0);
        let exchange = self.exchange(request, reservation, &dispatch, original_deadline, cancellation);
        tokio::pin!(exchange);
        let mut attempt = tokio::select! {
            // Preserve completed, trustworthy usage even if cancellation becomes ready in the same poll.
            biased;
            result = &mut exchange => result,
            () = cancellation.cancelled() => self.failure(reservation, dispatch_state(&dispatch), EmbeddingFailure::Cancelled),
            () = tokio::time::sleep_until(original_deadline) => self.failure(reservation, dispatch_state(&dispatch), EmbeddingFailure::Deadline),
        };
        if cancellation.is_cancelled() {
            attempt.outcome = EmbeddingOutcome::Failed(EmbeddingFailure::Cancelled);
        } else if Instant::now() >= original_deadline {
            attempt.outcome = EmbeddingOutcome::Failed(EmbeddingFailure::Deadline);
        }
        attempt
    }

    fn request_body(
        &self,
        input: &str,
        input_tokens_bound: u64,
        reservation: EmbeddingReservation,
    ) -> Result<Vec<u8>, EmbeddingFailure> {
        if input.trim().is_empty() {
            return Err(EmbeddingFailure::EmptyInput);
        }
        if input.len() > MAX_INPUT_BYTES {
            return Err(EmbeddingFailure::InputLimit);
        }
        if input_tokens_bound == 0
            || input_tokens_bound > reservation.reserved_tokens
            || reservation.reserved_tokens > u64::from(self.profile.configuration.max_input_tokens)
            || reservation.reserved_cost_micro < self.profile.cost_for(reservation.reserved_tokens)
        {
            return Err(EmbeddingFailure::Budget);
        }
        let request = wire::Request {
            input,
            model: &self.profile.configuration.model,
            encoding_format: "float",
            dimensions: self.profile.configuration.send_dimensions.then_some(self.profile.configuration.dimensions),
        };
        let body = serde_json::to_vec(&request).map_err(|_| EmbeddingFailure::Configuration)?;
        if body.len() > MAX_REQUEST_BYTES {
            return Err(EmbeddingFailure::InputLimit);
        }
        Ok(body)
    }

    async fn exchange(
        &self,
        request: reqwest::Request,
        reservation: EmbeddingReservation,
        dispatch: &AtomicU8,
        original_deadline: Instant,
        cancellation: &EmbeddingCancellation,
    ) -> EmbeddingAttempt {
        if cancellation.is_cancelled() {
            return self.failure(reservation, EmbeddingDispatch::NotSent, EmbeddingFailure::Cancelled);
        }
        if Instant::now() >= original_deadline {
            return self.failure(reservation, EmbeddingDispatch::NotSent, EmbeddingFailure::Deadline);
        }
        // Mark before polling the transport; it may send bytes before returning control.
        dispatch.store(1, Ordering::Release);
        let mut response = match self.http.execute(request).await {
            Ok(response) => response,
            Err(_) => return self.failure(reservation, dispatch_state(dispatch), EmbeddingFailure::Transport),
        };
        dispatch.store(2, Ordering::Release);
        let failure = |failure| self.failure(reservation, EmbeddingDispatch::ResponseReceived, failure);
        if response.status().is_redirection() {
            return failure(EmbeddingFailure::Redirect);
        }
        if response.status().as_u16() != 200 {
            return failure(EmbeddingFailure::HttpStatus(response.status().as_u16()));
        }
        if response.headers().get(CONTENT_ENCODING).is_some_and(|value| value.as_bytes() != b"identity") {
            return failure(EmbeddingFailure::ResponseEncoding);
        }
        let json = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
        if !json {
            return failure(EmbeddingFailure::ResponseType);
        }
        if response.content_length().is_some_and(|length| length > MAX_RESPONSE_BYTES as u64) {
            return failure(EmbeddingFailure::ResponseLimit);
        }
        let mut body = Vec::new();
        loop {
            let chunk = match response.chunk().await {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break,
                Err(_) => return failure(EmbeddingFailure::Transport),
            };
            if chunk.len() > MAX_RESPONSE_BYTES.saturating_sub(body.len()) {
                return failure(EmbeddingFailure::ResponseLimit);
            }
            body.extend_from_slice(&chunk);
        }
        let value = match serde_json::from_slice::<serde_json::Value>(&body) {
            Ok(value) => value,
            Err(_) => return failure(EmbeddingFailure::MalformedResponse),
        };
        let Some(usage) = wire::usage(&value) else {
            return failure(EmbeddingFailure::InvalidUsage);
        };
        let with_usage = |failure| {
            EmbeddingAttempt::failed(
                &self.profile,
                reservation,
                EmbeddingDispatch::ResponseReceived,
                failure,
                Some(usage),
            )
        };
        if usage.total_tokens > reservation.reserved_tokens {
            return with_usage(EmbeddingFailure::UsageOverReservation);
        }
        match wire::vector(&value, &self.profile) {
            Ok(vector) => {
                let mut attempt = with_usage(EmbeddingFailure::InvalidVector);
                attempt.outcome = EmbeddingOutcome::Vector(vector);
                attempt
            }
            Err(failure) => with_usage(failure),
        }
    }

    fn failure(
        &self,
        reservation: EmbeddingReservation,
        dispatch: EmbeddingDispatch,
        failure: EmbeddingFailure,
    ) -> EmbeddingAttempt {
        EmbeddingAttempt::failed(&self.profile, reservation, dispatch, failure, None)
    }
}

fn dispatch_state(dispatch: &AtomicU8) -> EmbeddingDispatch {
    match dispatch.load(Ordering::Acquire) {
        0 => EmbeddingDispatch::NotSent,
        1 => EmbeddingDispatch::PossiblySent,
        _ => EmbeddingDispatch::ResponseReceived,
    }
}
