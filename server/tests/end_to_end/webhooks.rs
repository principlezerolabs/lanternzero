//! Webhooks (spec §4.5) for a client without a device (§4.2): set over
//! OHTTP, delivered signed to a local receiver as each event changes,
//! retried, deleted on `410`, and kept across restarts.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::http::StatusCode;
use lz_proto::api::EventStatus;
use lz_proto::webhook::{SigningSecret, verify, webhook_id};
use lz_server::config::LimitsConfig;
use lz_server::scanner::FINALITY_DEPTH;
use lz_server::store::AccountId;
use serde_json::{Value, json};
use tokio::sync::Semaphore;

use super::harness::{Captured, Harness, harness_full, receiver};
use super::scanning::sync_tip;
use crate::common::fake_lwd;
use crate::common::wallet::{self, Wallet, action, block, tx};

struct Shop {
    h: Harness,
    account: AccountId,
    alice: Wallet,
    _chain: Arc<Mutex<fake_lwd::FakeChain>>,
}

async fn shop() -> Shop {
    let chain = fake_lwd::genesis();
    chain.lock().unwrap().build(1, 100, 1);
    let url = fake_lwd::serve(chain.clone()).await;
    let h = harness_full(true, LimitsConfig::default(), Some(url));
    sync_tip(&h).await;
    let account = h
        .state
        .store
        .authenticate(&lz_proto::token::TokenHash::of_text(&h.token))
        .unwrap();
    Shop {
        h,
        account,
        alice: Wallet::new(5),
        _chain: chain,
    }
}

impl Shop {
    async fn put_webhook(&mut self, url: &str) -> SigningSecret {
        let seq = self.h.next_seq();
        let r = self
            .h
            .call(
                "PUT",
                "/v0/webhook",
                Some(json!({ "seq": seq, "url": url })),
            )
            .await;
        assert_eq!(r.status, 200, "{:?}", r.json);
        SigningSecret::parse(r.json["secret"].as_str().unwrap()).unwrap()
    }

    /// A `wake` without a device, holding a lease for Alice's key.
    async fn lease(&mut self) {
        let seq = self.h.next_seq();
        let lease = json!({
            "keys": [self.alice.uivk_main()],
            "from_height": 95,
            "duration_secs": 604800,
            "spend_alerts": false,
            "alert_mode": "private",
        });
        let r = self
            .h
            .call(
                "POST",
                "/v0/wake",
                Some(json!({ "device_id": null, "seq": seq, "ack": [], "lease": lease })),
            )
            .await;
        assert_eq!(r.status, 200, "{:?}", r.json);
    }

    async fn pay(&self, height: u64, txid: u8) {
        let b = block(
            height,
            vec![tx(
                txid,
                vec![],
                vec![action(&self.alice.orchard, txid, false)],
                vec![],
            )],
        );
        lz_server::scanner::scan_block(&self.h.state, Arc::new(b)).await;
    }

    /// Starts the deliveries due at `at` and waits for them to finish.
    async fn deliver(&self, at: SystemTime) {
        lz_server::webhook::deliver_due(&self.h.state, &Arc::new(Semaphore::new(8)), at);
        self.h.state.settle().await;
    }
}

fn deliveries(c: &Captured) -> usize {
    c.0.lock().unwrap().len()
}

/// The bodies delivered so far, parsed.
fn bodies(c: &Captured) -> Vec<Value> {
    c.0.lock()
        .unwrap()
        .iter()
        .map(|(_, body)| serde_json::from_slice(body).unwrap())
        .collect()
}

/// A ZIP 302 text memo.
fn text_memo(text: &str) -> [u8; 512] {
    let mut memo = [0u8; 512];
    memo[..text.len()].copy_from_slice(text.as_bytes());
    memo
}

fn memo_of(delivery: &Value) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let b64 = delivery["memo"].as_str()?;
    Some(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .unwrap(),
    )
}

const BRANCH: zcash_protocol::consensus::BranchId = zcash_protocol::consensus::BranchId::Nu6_3;

#[tokio::test]
async fn deliveries_are_signed_follow_each_change_and_end_when_final() {
    let mut s = shop().await;
    let (url, got) = receiver(StatusCode::OK).await;
    let secret = s.put_webhook(&url).await;
    s.lease().await;
    s.pay(101, 0xC1).await;

    s.deliver(SystemTime::now()).await;
    assert_eq!(deliveries(&got), 1);
    let (headers, body) = got.0.lock().unwrap()[0].clone();
    let d: Value = serde_json::from_slice(&body).unwrap();
    let id = headers["webhook-id"].to_str().unwrap();
    let event = d["id"].as_str().unwrap();
    assert_eq!(
        id,
        webhook_id(event, EventStatus::Mined, Some(101), 1),
        "derived from the state"
    );
    let ts: u64 = headers["webhook-timestamp"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let sig = headers["webhook-signature"].to_str().unwrap();
    assert!(verify(&secret, id, ts, &body, sig));
    assert_eq!(d["status"], "mined");
    assert_eq!(d["pool"], "orchard");
    assert_eq!(d["amount"], 5_000);
    assert_eq!(d["memo"], Value::Null);
    assert!(d.get("compact_tx").is_none(), "kept small, as in pushes");
    // Display order: the test txid is 32 bytes of 0xC1 either way, so
    // check only its form here.
    assert_eq!(d["txid"].as_str().unwrap().len(), 64);

    // The same state isn't sent again.
    s.deliver(SystemTime::now()).await;
    assert_eq!(deliveries(&got), 1);

    // Final: delivered once more, under a new id, then the event is gone.
    s.h.state.scanner.on_tip(100 + u64::from(FINALITY_DEPTH));
    s.deliver(SystemTime::now()).await;
    assert_eq!(deliveries(&got), 2);
    let final_id = got.0.lock().unwrap()[1].0["webhook-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        final_id,
        webhook_id(event, EventStatus::Mined, Some(101), FINALITY_DEPTH)
    );
    assert!(
        s.h.state
            .scanner
            .page(s.account, None, 3500)
            .events
            .is_empty()
    );
    assert!(s.h.state.scanner.hints(s.account).is_empty());
}

#[tokio::test]
async fn failures_are_retried_later_and_410_deletes_the_webhook() {
    let mut s = shop().await;
    let (url, got) = receiver(StatusCode::INTERNAL_SERVER_ERROR).await;
    s.put_webhook(&url).await;
    s.lease().await;
    s.pay(101, 0xC2).await;

    let t0 = SystemTime::now();
    s.deliver(t0).await;
    assert_eq!(deliveries(&got), 1);
    // Not again at once: the first retry waits 5 s or more.
    s.deliver(t0 + Duration::from_secs(1)).await;
    assert_eq!(deliveries(&got), 1);
    s.deliver(t0 + Duration::from_secs(10)).await;
    assert_eq!(deliveries(&got), 2);
    // The undelivered event is kept, whatever the cap.
    assert_eq!(
        s.h.state.scanner.page(s.account, None, 3500).events.len(),
        1
    );
    // After 24 hours of retries the state is given up on, not sent again.
    s.deliver(t0 + lz_server::scanner::RETRY_WINDOW + Duration::from_secs(60))
        .await;
    s.deliver(t0 + lz_server::scanner::RETRY_WINDOW + Duration::from_secs(120))
        .await;
    assert_eq!(deliveries(&got), 2);

    // A receiver that is gone for good loses its webhook.
    let (gone, gone_got) = receiver(StatusCode::GONE).await;
    s.put_webhook(&gone).await;
    s.deliver(SystemTime::now()).await;
    assert_eq!(deliveries(&gone_got), 1);
    assert!(!s.h.state.store.has_webhook(s.account));
}

#[tokio::test]
async fn the_webhook_survives_a_restart_and_needs_a_safe_url() {
    let mut s = shop().await;
    let (url, _got) = receiver(StatusCode::OK).await;
    let secret = s.put_webhook(&url).await;
    for bad in [
        "ftp://shop.example/hook".to_owned(),
        "https://user:pw@shop.example/hook".to_owned(),
        format!("https://shop.example/{}", "a".repeat(1100)),
    ] {
        let seq = s.h.next_seq();
        let r =
            s.h.call(
                "PUT",
                "/v0/webhook",
                Some(json!({ "seq": seq, "url": bad })),
            )
            .await;
        assert_eq!(r.status, 400, "{bad}");
    }

    let h = std::mem::replace(&mut s.h, shop().await.h).restart();
    let hooks = h.state.store.webhooks();
    assert_eq!(hooks.len(), 1);
    assert_eq!(hooks[0].url, url);
    assert_eq!(hooks[0].secret, secret);

    // Deleting the account deletes the webhook with it.
    let mut h = h;
    let seq = h.next_seq();
    let r = h
        .call("DELETE", "/v0/account", Some(json!({ "seq": seq })))
        .await;
    assert_eq!(r.status, 204);
    assert!(h.state.store.webhooks().is_empty());
}

/// The client core's webhook calls, sent with its `reqwest` feature to the
/// server's gateway over real HTTP (the test plays a relay that forwards
/// to it unchanged).
#[tokio::test]
async fn a_merchant_sets_and_deletes_its_webhook_through_the_client_core() {
    use lz_client::{Client, ClientState, KeyConfig, Transport};
    use lz_proto::lease::Network;
    use lz_proto::url::ConnectionUrl;

    let s = shop().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = lz_server::gateway::router(s.h.state.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let gateway = format!("http://{addr}{}", lz_server::gateway::GATEWAY_PATH);

    let config = s.h.key_config().await;
    let url = ConnectionUrl::parse(&format!(
        "lanternzero://{}{}#{}",
        super::harness::HOST,
        super::harness::BASE,
        s.h.token
    ))
    .unwrap();
    let mut c = Client::new(
        url,
        Network::Main,
        Transport::Ohttp(KeyConfig::from_two_sources(&config, &config).unwrap()),
        ClientState::default(),
    )
    .unwrap()
    .without_device();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(40))
        .build()
        .unwrap();
    let now = || {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    };

    let (hook, _got) = receiver(StatusCode::OK).await;
    let p = c.set_webhook(now(), &hook).unwrap();
    let r = lz_client::http::send(&http, &gateway, p.request())
        .await
        .unwrap();
    let secret = c.finish_set_webhook(p, r.as_response()).unwrap();
    let stored = s.h.state.store.webhooks();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].secret, secret);

    let p = c.delete_webhook(now()).unwrap();
    let r = lz_client::http::send(&http, &gateway, p.request())
        .await
        .unwrap();
    c.finish_delete_webhook(p, r.as_response()).unwrap();
    assert!(s.h.state.store.webhooks().is_empty());
}

#[tokio::test]
async fn mempool_payments_carry_their_memo_to_the_final_delivery() {
    let mut s = shop().await;
    let (url, got) = receiver(StatusCode::OK).await;
    let secret = s.put_webhook(&url).await;
    s.lease().await;
    let memo = text_memo("order 42");
    let raw = wallet::full_tx_with_memo(&s.alice, true, true, memo);
    assert_eq!(
        lz_server::mempool::scan_raw(&s.h.state, vec![raw.clone()], BRANCH).await,
        0
    );

    s.deliver(SystemTime::now()).await;
    assert_eq!(deliveries(&got), 2);
    let mut pools = Vec::new();
    for d in bodies(&got) {
        assert_eq!(d["status"], "mempool");
        assert_eq!(memo_of(&d).as_deref(), Some(&memo[..]), "the whole field");
        pools.push(d["pool"].as_str().unwrap().to_owned());
    }
    pools.sort();
    assert_eq!(pools, ["ironwood", "sapling"]);
    // As a merchant's receiver reads it (lz_proto::webhook::receive).
    let (headers, body) = got.0.lock().unwrap()[0].clone();
    let header = |name: &str| headers[name].to_str().unwrap().to_owned();
    let now = lz_server::clock::unix_now();
    let delivery = lz_proto::webhook::receive(
        &secret,
        &header("webhook-id"),
        &header("webhook-timestamp"),
        &header("webhook-signature"),
        &body,
        now,
    )
    .unwrap();
    assert_eq!(delivery.memo_text().as_deref(), Some("order 42"));
    // Not in what wallets fetch: they get their own memos (spec §6.3).
    let page = s.h.state.scanner.page(s.account, None, 3500);
    assert!(
        !serde_json::to_string(&page.events)
            .unwrap()
            .contains("memo")
    );

    // Mined from a compact block, which has no memo: the event keeps it.
    let mut mined = lz_server::mempool::to_compact(&raw, BRANCH).unwrap();
    mined.index = 1;
    lz_server::scanner::scan_block(&s.h.state, Arc::new(block(101, vec![mined]))).await;
    s.h.state.scanner.on_tip(100 + u64::from(FINALITY_DEPTH));
    s.deliver(SystemTime::now()).await;
    assert_eq!(deliveries(&got), 4);
    for d in &bodies(&got)[2..] {
        assert_eq!(d["status"], "mined");
        assert_eq!(memo_of(d).as_deref(), Some(&memo[..]));
    }
    // Final and delivered: the events, memos with them, are gone.
    assert!(
        s.h.state
            .scanner
            .page(s.account, None, 3500)
            .events
            .is_empty()
    );
}

#[tokio::test]
async fn a_memo_learned_later_waits_for_the_next_state() {
    let mut s = shop().await;
    let (url, got) = receiver(StatusCode::OK).await;
    s.put_webhook(&url).await;
    s.lease().await;
    let memo = text_memo("invoice 7");
    let raw = wallet::full_tx_with_memo(&s.alice, false, true, memo);
    let compact = lz_server::mempool::to_compact(&raw, BRANCH).unwrap();

    // Seen first in compact form (as a backfill sees the mempool): no memo.
    lz_server::mempool::scan_tx(&s.h.state, compact.clone()).await;
    s.deliver(SystemTime::now()).await;
    assert_eq!(deliveries(&got), 1);
    assert_eq!(bodies(&got)[0]["memo"], Value::Null);

    // Then in full, as the stream sends it: no delivery for the memo alone.
    lz_server::mempool::scan_raw(&s.h.state, vec![raw], BRANCH).await;
    s.deliver(SystemTime::now()).await;
    assert_eq!(deliveries(&got), 1);

    // The next state carries it.
    let mut mined = compact;
    mined.index = 1;
    lz_server::scanner::scan_block(&s.h.state, Arc::new(block(101, vec![mined]))).await;
    s.deliver(SystemTime::now()).await;
    assert_eq!(deliveries(&got), 2);
    let d = &bodies(&got)[1];
    assert_eq!(d["status"], "mined");
    assert_eq!(memo_of(d).as_deref(), Some(&memo[..]));
}

#[tokio::test]
async fn accounts_without_a_webhook_keep_no_memo() {
    let mut s = shop().await;
    s.lease().await;
    let raw = wallet::full_tx_with_memo(&s.alice, false, true, text_memo("not kept"));
    lz_server::mempool::scan_raw(&s.h.state, vec![raw.clone()], BRANCH).await;
    assert_eq!(
        s.h.state.scanner.page(s.account, None, 3500).events.len(),
        1
    );

    // A webhook set afterwards gets the payment, but not a memo the
    // server never kept.
    let (url, got) = receiver(StatusCode::OK).await;
    s.put_webhook(&url).await;
    let mut mined = lz_server::mempool::to_compact(&raw, BRANCH).unwrap();
    mined.index = 1;
    lz_server::scanner::scan_block(&s.h.state, Arc::new(block(101, vec![mined]))).await;
    s.deliver(SystemTime::now()).await;
    assert_eq!(deliveries(&got), 1);
    assert_eq!(bodies(&got)[0]["status"], "mined");
    assert_eq!(bodies(&got)[0]["memo"], Value::Null);
}
