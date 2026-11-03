//! The relay against a fake gateway: what it forwards, what it refuses,
//! and what it remembers (relay/DESIGN.md).

mod common;

use std::time::Duration;

use axum::http::{Method, StatusCode, header};
use common::{Fake, Relay, test_timing};
use lz_relay::{MAX_REQUEST, MAX_RESPONSE, Timing};

const BODY: &[u8] = b"encapsulated request bytes";

#[tokio::test]
async fn forwards_only_content_type_and_returns_only_content_type() {
    let gw = Fake::start().await;
    let relay = Relay::start("").await;
    let resp = relay
        .client
        .post(relay.url(&gw.origin()))
        .header(header::CONTENT_TYPE, "message/ohttp-req")
        .header(header::USER_AGENT, "WalletApp/1.2 (iPhone; iOS 19)")
        .header(header::COOKIE, "session=abc")
        .header(header::AUTHORIZATION, "Bearer lzt_secret")
        .header(header::ACCEPT_LANGUAGE, "de-CH")
        .header("x-forwarded-for", "203.0.113.9")
        .header("forwarded", "for=203.0.113.9")
        .header("x-real-ip", "203.0.113.9")
        .header("region-ingress", "lax")
        .body(BODY)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // What reached the gateway.
    let post = gw
        .seen()
        .into_iter()
        .find(|s| s.method == Method::POST)
        .unwrap();
    assert_eq!(&post.body[..], BODY);
    let mut names: Vec<&str> = post.headers.keys().map(|k| k.as_str()).collect();
    names.sort();
    assert_eq!(names, ["accept", "content-length", "content-type", "host"]);
    assert_eq!(post.headers[header::CONTENT_TYPE], "message/ohttp-req");
    assert_eq!(post.headers[header::ACCEPT], "message/ohttp-res");
    assert_eq!(post.headers[header::HOST], gw.addr.to_string());

    // What came back: the gateway's status, Content-Type, and body, plus
    // framing, CORS, and the relay's own Date; none of its other headers.
    let mut names: Vec<String> = resp.headers().keys().map(|k| k.to_string()).collect();
    names.sort();
    assert_eq!(
        names,
        [
            "access-control-allow-origin",
            "content-length",
            "content-type",
            "date"
        ]
    );
    assert_eq!(resp.headers()[header::CONTENT_TYPE], "message/ohttp-res");
    assert_eq!(&resp.bytes().await.unwrap()[..], BODY);
}

#[tokio::test]
async fn passes_the_gateways_status_through() {
    let gw = Fake::start().await;
    gw.set(|b| {
        b.post_status = 415;
        b.post_body = Some(vec![]);
    });
    let relay = Relay::start("").await;
    assert_eq!(relay.post(&gw.origin(), BODY.to_vec()).await.status(), 415);
}

#[tokio::test]
async fn forwards_only_to_gateways_that_opt_in() {
    let gw = Fake::start().await;
    gw.set(|b| b.purposes = None);
    let relay = Relay::start("").await;
    assert_eq!(relay.post(&gw.origin(), BODY.to_vec()).await.status(), 403);
    assert_eq!(relay.get(&gw.origin()).await.status(), 403);

    let other = Fake::start().await;
    other.set(|b| b.purposes = Some(vec!["BIP77 454403bb-9f7b-4385-b31f-acd2dae20b7e".into()]));
    assert_eq!(
        relay.post(&other.origin(), BODY.to_vec()).await.status(),
        403
    );

    let both = Fake::start().await;
    both.set(|b| {
        b.purposes = Some(vec![
            "BIP77 454403bb-9f7b-4385-b31f-acd2dae20b7e".into(),
            lz_proto::OHTTP_PURPOSE.into(),
        ])
    });
    assert_eq!(
        relay.post(&both.origin(), BODY.to_vec()).await.status(),
        200
    );

    for g in [&gw, &other] {
        assert_eq!(g.posts(), 0, "nothing forwarded before the opt-in");
        assert_eq!(g.key_fetches(), 0);
    }
}

#[tokio::test]
async fn remembers_opt_ins_and_refusals_for_their_times() {
    let gw = Fake::start().await;
    let relay = Relay::start("").await;
    let t = Timing::default();
    for _ in 0..3 {
        assert_eq!(relay.post(&gw.origin(), BODY.to_vec()).await.status(), 200);
    }
    assert_eq!(gw.probes(), 1, "one opt-in check for many requests");
    relay.state.clock.advance(t.opted_in);
    relay.post(&gw.origin(), BODY.to_vec()).await;
    assert_eq!(gw.probes(), 2, "checked again after a day");

    // A refusal is remembered for an hour, then checked again.
    let gw = Fake::start().await;
    gw.set(|b| b.purposes = None);
    assert_eq!(relay.post(&gw.origin(), BODY.to_vec()).await.status(), 403);
    gw.set(|b| b.purposes = Some(vec![lz_proto::OHTTP_PURPOSE.into()]));
    assert_eq!(relay.post(&gw.origin(), BODY.to_vec()).await.status(), 403);
    relay.state.clock.advance(t.opted_out);
    assert_eq!(relay.post(&gw.origin(), BODY.to_vec()).await.status(), 200);
    assert_eq!(gw.probes(), 2);
}

#[tokio::test]
async fn an_unreachable_gateway_is_a_bad_gateway() {
    // A port nothing listens on.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let relay = Relay::start("").await;
    let target = format!("http://127.0.0.1:{port}");
    assert_eq!(relay.post(&target, BODY.to_vec()).await.status(), 502);
}

#[tokio::test]
async fn serves_every_client_the_same_cached_key_configuration() {
    let gw = Fake::start().await;
    let relay = Relay::start("").await;
    let a = relay.get(&gw.origin()).await;
    assert_eq!(a.status(), 200);
    assert_eq!(a.headers()[header::CONTENT_TYPE], "application/ohttp-keys");
    assert_eq!(a.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    let a = a.bytes().await.unwrap();
    gw.set(|b| b.keys = vec![0x09; 4]);
    let b = relay.get(&gw.origin()).await.bytes().await.unwrap();
    assert_eq!(a, b, "the cached copy, not the gateway's new one");
    assert_eq!(&a[..], [1, 2, 3, 4]);
    assert_eq!(gw.key_fetches(), 1);

    // At most an hour, whatever the gateway's max-age (a day here).
    relay.state.clock.advance(Timing::default().key_max_age);
    let c = relay.get(&gw.origin()).await.bytes().await.unwrap();
    assert_eq!(&c[..], [9; 4]);
    assert_eq!(gw.key_fetches(), 2);
}

#[tokio::test]
async fn honors_a_shorter_max_age_and_no_store() {
    let gw = Fake::start().await;
    gw.set(|b| b.keys_cache_control = Some("max-age=5".into()));
    let relay = Relay::start("").await;
    relay.get(&gw.origin()).await;
    relay.get(&gw.origin()).await;
    assert_eq!(gw.key_fetches(), 1);
    relay.state.clock.advance(Duration::from_secs(5));
    relay.get(&gw.origin()).await;
    assert_eq!(gw.key_fetches(), 2);

    let gw = Fake::start().await;
    gw.set(|b| b.keys_cache_control = Some("no-store".into()));
    relay.get(&gw.origin()).await;
    relay.get(&gw.origin()).await;
    assert_eq!(gw.key_fetches(), 2);
}

#[tokio::test]
async fn refuses_an_empty_key_configuration() {
    let gw = Fake::start().await;
    gw.set(|b| b.keys = vec![]);
    let relay = Relay::start("").await;
    assert_eq!(relay.get(&gw.origin()).await.status(), 502);
}

#[tokio::test]
async fn an_ohttp_key_answer_refetches_at_most_once_a_minute() {
    let gw = Fake::start().await;
    let relay = Relay::start("").await;
    relay.get(&gw.origin()).await;
    // The server drops its old key (`rotate-ohttp --drop-old`) and answers
    // old-key requests with the unencrypted `ohttp-key` problem.
    gw.set(|b| {
        b.keys = vec![0x07; 4];
        b.post_status = 400;
        b.post_content_type = "application/problem+json".into();
        b.post_body = Some(
            br#"{"type":"https://iana.org/assignments/http-problem-types#ohttp-key","status":400}"#
                .to_vec(),
        );
    });
    // A fresh copy is kept, so bad requests can't make the relay hammer
    // the gateway.
    assert_eq!(relay.post(&gw.origin(), BODY.to_vec()).await.status(), 400);
    relay.get(&gw.origin()).await;
    assert_eq!(gw.key_fetches(), 1);
    // A minute later, the same answer drops it, and the next fetch is new.
    relay
        .state
        .clock
        .advance(Timing::default().key_refetch_after);
    relay.post(&gw.origin(), BODY.to_vec()).await;
    let k = relay.get(&gw.origin()).await.bytes().await.unwrap();
    assert_eq!(&k[..], [7; 4]);
    assert_eq!(gw.key_fetches(), 2);
}

#[tokio::test]
async fn honors_allow_and_deny_lists() {
    let gw = Fake::start().await;
    let relay = Relay::start("[gateways]\ndeny = [\"127.0.0.1\"]").await;
    assert_eq!(relay.post(&gw.origin(), BODY.to_vec()).await.status(), 403);
    let relay = Relay::start("[gateways]\nallow = [\"lz.example.org\"]").await;
    assert_eq!(relay.post(&gw.origin(), BODY.to_vec()).await.status(), 403);
    assert_eq!(gw.seen().len(), 0, "listed gateways aren't even asked");
    let relay = Relay::start("[gateways]\nallow = [\"127.0.0.1\"]").await;
    assert_eq!(relay.post(&gw.origin(), BODY.to_vec()).await.status(), 200);
}

#[tokio::test]
async fn refuses_targets_that_arent_public_gateways() {
    let gw = Fake::start().await;
    // The production setting: no private targets, https only.
    let relay = Relay::start_with("", "", test_timing()).await;
    let port = gw.addr.port();
    for (target, want) in [
        (format!("http://127.0.0.1:{port}"), 400),
        (format!("https://127.0.0.1:{port}"), 403),
        ("https://127.0.0.1".into(), 403),
        ("https://[::1]".into(), 403),
        ("https://169.254.169.254".into(), 403),
        ("https://10.0.0.1".into(), 403),
        // Other spellings of 127.0.0.1 and 169.254.169.254, which the HTTP
        // client would read as those addresses.
        ("https://2130706433".into(), 403),
        ("https://0x7f.0.0.1".into(), 403),
        ("https://127.1".into(), 403),
        ("https://2852039166".into(), 403),
        // Port 443 is allowed, but the name resolves only to loopback.
        ("https://localhost".into(), 502),
        ("localhost".into(), 502),
        (format!("https://localhost:{port}"), 403),
        ("https://user@lz.example.org".into(), 400),
        ("https://lz.example.org/path".into(), 400),
    ] {
        let status = relay.post(&target, BODY.to_vec()).await.status();
        assert_eq!(status, want, "{target}");
        assert_eq!(relay.get(&target).await.status(), want, "GET {target}");
    }
    let r = relay
        .client
        .post(format!("{}/https://lz.example.org?x=1", relay.base))
        .header(header::CONTENT_TYPE, "message/ohttp-req")
        .body(BODY)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    assert_eq!(gw.seen().len(), 0, "nothing reached the loopback gateway");
}

#[tokio::test]
async fn never_follows_a_redirect() {
    let gw = Fake::start().await;
    let elsewhere = Fake::start().await;
    gw.set(|b| b.post_redirect = Some(format!("{}/.well-known/ohttp-gateway", elsewhere.origin())));
    let relay = Relay::start("").await;
    let resp = relay.post(&gw.origin(), BODY.to_vec()).await;
    assert_eq!(resp.status(), 307);
    assert!(resp.headers().get(header::LOCATION).is_none());
    assert_eq!(elsewhere.seen().len(), 0);
}

#[tokio::test]
async fn refuses_oversize_bodies_rather_than_truncating() {
    let gw = Fake::start().await;
    let relay = Relay::start("").await;
    assert_eq!(
        relay
            .post(&gw.origin(), vec![0; MAX_REQUEST])
            .await
            .status(),
        200
    );
    assert_eq!(
        relay
            .post(&gw.origin(), vec![0; MAX_REQUEST + 1])
            .await
            .status(),
        413
    );
    // A chunked body with no Content-Length is counted as it arrives.
    let status = raw_chunked(&relay, &gw.origin(), &[vec![0; MAX_REQUEST], vec![0; 1]]).await;
    assert_eq!(status, "413");
    assert_eq!(gw.posts(), 1);

    gw.set(|b| b.post_body = Some(vec![0; MAX_RESPONSE + 1]));
    assert_eq!(relay.post(&gw.origin(), BODY.to_vec()).await.status(), 502);
}

/// Sends a chunked POST over a plain socket; returns the status code.
async fn raw_chunked(relay: &Relay, target: &str, chunks: &[Vec<u8>]) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let addr = relay.base.trim_start_matches("http://");
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut req = format!(
        "POST /{target} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: message/ohttp-req\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    for c in chunks {
        req.extend_from_slice(format!("{:x}\r\n", c.len()).as_bytes());
        req.extend_from_slice(c);
        req.extend_from_slice(b"\r\n");
    }
    req.extend_from_slice(b"0\r\n\r\n");
    // The relay may answer and close before reading everything.
    let _ = sock.write_all(&req).await;
    let mut resp = Vec::new();
    let _ = sock.read_to_end(&mut resp).await;
    let resp = String::from_utf8_lossy(&resp);
    resp.split(' ').nth(1).unwrap_or("").to_owned()
}

#[tokio::test]
async fn gives_up_on_a_client_that_sends_its_body_slowly() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let gw = Fake::start().await;
    let relay = Relay::start_with(
        "allow_private_targets = true",
        "",
        Timing {
            body_read: Duration::from_millis(200),
            ..test_timing()
        },
    )
    .await;
    let addr = relay.base.trim_start_matches("http://");
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "POST /{} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: message/ohttp-req\r\nContent-Length: 100\r\n\r\npartial",
        gw.origin()
    );
    sock.write_all(head.as_bytes()).await.unwrap();
    let mut resp = vec![0; 64];
    let n = sock.read(&mut resp).await.unwrap();
    let resp = String::from_utf8_lossy(&resp[..n]);
    assert!(resp.starts_with("HTTP/1.1 408"), "{resp}");
    assert_eq!(gw.posts(), 0);
}

#[tokio::test]
async fn holds_a_slow_gateway_until_the_first_byte_limit() {
    let gw = Fake::start().await;
    gw.set(|b| b.post_delay = Duration::from_millis(800));
    // A held long-poll: answered within the limit, so it goes through.
    let relay = Relay::start("").await;
    assert_eq!(relay.post(&gw.origin(), BODY.to_vec()).await.status(), 200);
    // Past the limit, a gateway timeout.
    let relay = Relay::start_with(
        "allow_private_targets = true",
        "",
        Timing {
            first_byte: Duration::from_millis(200),
            ..test_timing()
        },
    )
    .await;
    assert_eq!(relay.post(&gw.origin(), BODY.to_vec()).await.status(), 504);
}

#[tokio::test]
async fn limits_requests_per_client() {
    let gw = Fake::start().await;
    let relay = Relay::start("[limits]\nper_minute = 3").await;
    for _ in 0..3 {
        assert_eq!(relay.post(&gw.origin(), BODY.to_vec()).await.status(), 200);
    }
    let r = relay.post(&gw.origin(), BODY.to_vec()).await;
    assert_eq!(r.status(), 429);
    assert!(r.headers().get(header::RETRY_AFTER).is_some());
    relay.state.clock.advance(Duration::from_secs(60));
    assert_eq!(relay.post(&gw.origin(), BODY.to_vec()).await.status(), 200);
}

#[tokio::test]
async fn limits_requests_in_flight_per_client() {
    let gw = Fake::start().await;
    gw.set(|b| b.post_delay = Duration::from_millis(600));
    let relay = Relay::start("[limits]\nconcurrent = 1").await;
    let held = {
        let (relay, target) = (relay.clone(), gw.origin());
        tokio::spawn(async move { relay.post(&target, BODY.to_vec()).await.status() })
    };
    // Wait until the held request reached the gateway.
    while gw.posts() == 0 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(relay.post(&gw.origin(), BODY.to_vec()).await.status(), 429);
    assert_eq!(held.await.unwrap(), 200);
    assert_eq!(relay.post(&gw.origin(), BODY.to_vec()).await.status(), 200);
}

#[tokio::test]
async fn answers_cors_preflights_and_rejects_other_methods() {
    let gw = Fake::start().await;
    let relay = Relay::start("").await;
    let r = relay
        .client
        .request(reqwest::Method::OPTIONS, relay.url(&gw.origin()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    let h = r.headers();
    assert_eq!(h[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    assert_eq!(
        h[header::ACCESS_CONTROL_ALLOW_METHODS],
        "GET, POST, OPTIONS"
    );
    assert_eq!(h[header::ACCESS_CONTROL_ALLOW_HEADERS], "content-type");

    let r = relay
        .client
        .put(relay.url(&gw.origin()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 405);
    assert_eq!(r.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");

    let r = relay
        .client
        .post(relay.url(&gw.origin()))
        .header(header::CONTENT_TYPE, "application/json")
        .body(BODY)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 415);
    assert_eq!(relay.get("health").await.status(), StatusCode::OK);
    assert_eq!(gw.seen().len(), 0);
}

#[tokio::test]
async fn counts_totals_without_naming_anyone() {
    let gw = Fake::start().await;
    let relay = Relay::start("").await;
    relay.post(&gw.origin(), BODY.to_vec()).await;
    relay.get(&gw.origin()).await;
    relay.post("https://user@x", BODY.to_vec()).await;
    let [forwarded, key_configs, refused, limited, failed] = relay.state.totals.take();
    assert_eq!(
        (forwarded, key_configs, refused, limited, failed),
        (1, 1, 1, 0, 0)
    );
    assert_eq!(
        relay.state.totals.take(),
        [0; 5],
        "each period starts at zero"
    );
}
