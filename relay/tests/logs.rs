//! Nothing about clients reaches the logs (relay/DESIGN.md, "Rules"): no
//! client address and no gateway origin, even at trace level and from the
//! HTTP crates. Its own test binary, because it installs the global
//! subscriber.

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use common::{Fake, Relay};

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn logs_name_no_client_and_no_gateway() {
    let captured = Captured::default();
    let writer = captured.clone();
    tracing_subscriber::fmt()
        .with_env_filter(lz_relay::log_filter("trace"))
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .init();

    let gw = Fake::start().await;
    let refusing = Fake::start().await;
    refusing.set(|b| b.purposes = None);
    let relay = Relay::start("trusted_proxies = [\"127.0.0.1\"]\n[limits]\nper_minute = 6").await;
    let client_ip = "203.0.113.77";
    let send = |target: String, method: reqwest::Method| {
        relay
            .client
            .request(method, relay.url(&target))
            .header("content-type", "message/ohttp-req")
            .header("x-forwarded-for", client_ip)
            .body(&b"encapsulated"[..])
            .send()
    };
    // Forwarded, key fetch, refused, unreachable, bad origin, rate-limited.
    for (target, method) in [
        (gw.origin(), reqwest::Method::POST),
        (gw.origin(), reqwest::Method::GET),
        (refusing.origin(), reqwest::Method::POST),
        ("http://127.0.0.1:1".into(), reqwest::Method::POST),
        (
            "https://user@secret-gateway.example".into(),
            reqwest::Method::POST,
        ),
        (gw.origin(), reqwest::Method::POST),
        (gw.origin(), reqwest::Method::POST),
    ] {
        send(target, method).await.unwrap();
    }
    let totals = tokio::spawn(lz_relay::log_totals(
        relay.state.clone(),
        std::time::Duration::from_millis(10),
    ));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    totals.abort();

    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("totals"), "the totals line is logged: {logs}");
    for secret in [
        client_ip.to_owned(),
        gw.addr.to_string(),
        refusing.addr.to_string(),
        "secret-gateway".to_owned(),
        "127.0.0.1:1".to_owned(),
        "encapsulated".to_owned(),
    ] {
        assert!(!logs.contains(&secret), "{secret:?} in logs:\n{logs}");
    }
}
