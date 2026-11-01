//! Account issuance over the issuer socket, idle expiry, and `info`
//! (spec §4.6, §4.7; `server/ISSUER.md`).

use std::time::{SystemTime, UNIX_EPOCH};

use lz_proto::token::AccountToken;
use lz_server::config::{AccountsConfig, LimitsConfig};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::harness::{HOST, Harness, harness_accounts};

fn issuer_harness(idle_account_days: u32) -> Harness {
    harness_accounts(
        false,
        LimitsConfig::default(),
        None,
        AccountsConfig {
            idle_account_days,
            issuer_socket: true,
            ..AccountsConfig::default()
        },
    )
}

/// One HTTP/1.1 request over the issuer socket, as `curl --unix-socket`
/// would send it. Returns the status and the JSON body (`Null` if empty).
async fn issuer_call(socket: &std::path::Path, path: &str, body: &Value) -> (u16, Value) {
    let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    let body = serde_json::to_vec(body).unwrap();
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    let mut out = Vec::new();
    stream.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8(out).unwrap();
    let status: u16 = text[9..12].parse().unwrap();
    let (_, body) = text.split_once("\r\n\r\n").unwrap();
    let json = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(body).unwrap()
    };
    (status, json)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn info_publishes_idle_account_days() {
    let h = issuer_harness(90);
    let inner = h.inner("POST", HOST, "/v0/info", None, SystemTime::now(), None);
    let r = h.send_raw(&inner).await;
    assert_eq!(r.json["idle_account_days"], 90);

    let h = super::harness::harness(false);
    let inner = h.inner("POST", HOST, "/v0/info", None, SystemTime::now(), None);
    let r = h.send_raw(&inner).await;
    assert_eq!(r.json["idle_account_days"], Value::Null);
}

/// The issuer creates an account that works at once, resolves it, gives it
/// scanning time idempotently, and deletes it; the deletion log shows it.
#[tokio::test]
async fn issuer_socket_lifecycle() {
    use std::os::unix::fs::PermissionsExt;

    let mut h = issuer_harness(0);
    let dir = h.state.config.data_dir.clone();
    let listener = lz_server::issuer::bind(&dir).unwrap();
    let socket = lz_server::issuer::socket_path(&dir);
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    tokio::spawn(axum::serve(listener, lz_server::issuer::router(h.state.clone())).into_future());

    // The token is made where the user is; the issuer sees only its hash.
    let token = AccountToken::generate().unwrap();
    let hash = token.hash().to_hex();
    let (status, r) = issuer_call(&socket, "/create", &json!({ "token_hash": hash })).await;
    assert_eq!(status, 201, "{r}");
    let account = r["account"].as_str().unwrap().to_owned();
    assert_eq!(account.len(), 32);
    let (status, r) = issuer_call(&socket, "/create", &json!({ "token_hash": hash })).await;
    assert_eq!(
        (status, r["type"].as_str().unwrap()),
        (409, "https://lanternzero.com/problems/hash-taken")
    );

    // Live without a restart.
    h.token = token.encode().to_string();
    let r = h.register("https://push.example/sub/1").await;
    assert_eq!(r.status, 201, "{}", r.json);

    let (_, r) = issuer_call(&socket, "/resolve", &json!({ "token_hash": hash })).await;
    assert_eq!(r["account"], account.as_str());
    let other = AccountToken::generate().unwrap().hash().to_hex();
    let (_, r) = issuer_call(&socket, "/resolve", &json!({ "token_hash": other })).await;
    assert_eq!(r["account"], Value::Null);

    let (_, r) = issuer_call(&socket, "/scan_until", &json!({ "account": account })).await;
    assert_eq!(r["until"], Value::Null);
    let grant = json!({ "account": account, "secs": 86400, "key": "invoice-7" });
    let (status, r) = issuer_call(&socket, "/add_scan_time", &grant).await;
    assert_eq!(status, 200, "{r}");
    let until = r["until"].as_u64().unwrap();
    assert!(until >= now() + 86_390);
    // A retry adds nothing.
    let (_, r) = issuer_call(&socket, "/add_scan_time", &grant).await;
    assert_eq!(r["until"].as_u64(), Some(until));
    let (_, r) = issuer_call(&socket, "/scan_until", &json!({ "account": account })).await;
    assert_eq!(r["until"].as_u64(), Some(until));
    let bad = json!({ "account": account, "secs": 0, "key": "x" });
    assert_eq!(issuer_call(&socket, "/add_scan_time", &bad).await.0, 400);

    let (status, _) = issuer_call(&socket, "/delete", &json!({ "account": account })).await;
    assert_eq!(status, 204);
    let seq = h.next_seq();
    let r = h
        .call("DELETE", "/v0/account", Some(json!({ "seq": seq })))
        .await;
    assert_eq!(r.status, 401);
    let (status, _) = issuer_call(&socket, "/scan_until", &json!({ "account": account })).await;
    assert_eq!(status, 404);

    let (_, r) = issuer_call(&socket, "/deletions", &json!({ "after": 0 })).await;
    assert_eq!(r["accounts"], json!([account]));
    let next = r["next"].as_u64().unwrap();
    let (_, r) = issuer_call(&socket, "/deletions", &json!({ "after": next })).await;
    assert_eq!(r["accounts"], json!([]));
    assert_eq!(r["next"].as_u64(), Some(next));
}

/// Spec §4.6: an account idle past `idle_account_days` is deleted as
/// `DELETE /v0/account` would, unless it has scanning time left.
#[tokio::test]
async fn idle_accounts_are_deleted_unless_they_have_scanning_time() {
    let h = issuer_harness(30);
    let store = &h.state.store;
    let t0 = now();
    let idle = store
        .create_account(&AccountToken::generate().unwrap().hash(), t0)
        .unwrap();
    let paid = store
        .create_account(&AccountToken::generate().unwrap().hash(), t0)
        .unwrap();
    store.add_scan_time(paid, 365 * 86_400, "year", t0).unwrap();
    // The harness's own account is used every day.
    let mine = lz_proto::token::TokenHash::of_text(&h.token);
    let mut deleted = 0;
    for d in 0..=31 {
        let t = t0 + d * 86_400;
        assert!(store.authenticate_at(&mine, t).is_some());
        deleted += h.state.sweep_accounts(t);
    }
    assert_eq!(deleted, 1);
    assert!(!store.has_account(idle));
    assert!(store.has_account(paid));
    assert!(store.authenticate(&mine).is_some());
}
