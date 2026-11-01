//! Sending requests with `reqwest`, for merchant backends and tests
//! (feature `reqwest`). Wallet apps don't use this: they send the bytes
//! with their own HTTP stack (URLSession, OkHttp), and the feature is off
//! by default, so the core still pulls in no TLS stack or async runtime.

use crate::transport::{HttpRequest, HttpResponse};

/// A response as received, owned. [`as_response`](Self::as_response)
/// lends it to the `finish_*` calls. `Debug` hides the body.
#[derive(Clone)]
pub struct Received {
    pub status: u16,
    pub retry_after: Option<String>,
    pub date: Option<String>,
    pub body: Vec<u8>,
}

impl std::fmt::Debug for Received {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Received")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

impl Received {
    pub fn as_response(&self) -> HttpResponse<'_> {
        HttpResponse {
            status: self.status,
            retry_after: self.retry_after.as_deref(),
            date: self.date.as_deref(),
            body: &self.body,
        }
    }
}

/// Sends `request` to `target`: over OHTTP, the URL of a relay that
/// forwards to `request.url` (addressing is relay-specific; spec §1.1);
/// over Tor, `request.url` itself. Give `client` a timeout longer than a
/// long-poll's wait plus a few seconds (at least 35 s).
pub async fn send(
    client: &reqwest::Client,
    target: &str,
    request: &HttpRequest,
) -> Result<Received, reqwest::Error> {
    let method =
        reqwest::Method::from_bytes(request.method.as_bytes()).unwrap_or(reqwest::Method::POST);
    let mut builder = client.request(method, target);
    for (name, value) in &request.headers {
        builder = builder.header(*name, value.as_str());
    }
    let resp = builder.body(request.body.clone()).send().await?;
    let header = |name: reqwest::header::HeaderName| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let (retry_after, date) = (
        header(reqwest::header::RETRY_AFTER),
        header(reqwest::header::DATE),
    );
    let status = resp.status().as_u16();
    let body = resp.bytes().await?.to_vec();
    Ok(Received {
        status,
        retry_after,
        date,
        body,
    })
}
