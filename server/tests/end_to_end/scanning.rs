//! Lease scanning, long-poll, mempool, and push-budget tests.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use lz_proto::api::{DeviceRegistration, PushKeys};
use lz_proto::padding::RESPONSE_SIZE;
use lz_server::config::LimitsConfig;
use lz_server::push;
use serde_json::{Value, json};

use super::harness::{
    Captured, HOST, Harness, Reply, global_logs, harness_full, problem_slug, receiver, ua_keys,
};
use crate::common::fake_lwd;
use crate::common::wallet::{self, Wallet, action, block, sapling_output, tx};

/// A harness following a fake chain of `height` blocks, with one device
/// registered at a local push receiver.
struct Scanning {
    h: Harness,
    chain: Arc<Mutex<fake_lwd::FakeChain>>,
    device_id: String,
    push_keys: (p256::SecretKey, [u8; 16]),
    pushes: Captured,
    account: lz_server::store::AccountId,
}

async fn scanning(height: u64) -> Scanning {
    let chain = fake_lwd::genesis();
    chain.lock().unwrap().build(1, height, 1);
    let url = fake_lwd::serve(chain.clone()).await;
    let h = harness_full(true, LimitsConfig::default(), Some(url));
    sync_tip(&h).await;
    let (endpoint, pushes) = receiver(StatusCode::CREATED).await;
    let (push_keys, keys) = ua_keys();
    let account = h
        .state
        .store
        .authenticate(&lz_proto::token::TokenHash::of_text(&h.token))
        .unwrap();
    let reg = DeviceRegistration {
        seq: 1,
        endpoint,
        keys: PushKeys {
            p256dh: keys["p256dh"].as_str().unwrap().into(),
            auth: keys["auth"].as_str().unwrap().into(),
        },
    };
    let device_id = h.state.store.register_device(account, &reg, 10).unwrap();
    Scanning {
        h,
        chain,
        device_id,
        push_keys,
        pushes,
        account,
    }
}

/// Runs the chain follower until it has caught up with the fake.
async fn sync_tip(h: &Harness) {
    let source = h.state.chain_source.clone().unwrap();
    let mut f = lz_server::chain::Follower::new(h.state.chain.clone(), source);
    while f.step().await.unwrap() != lz_server::chain::Step::CaughtUp {}
}

impl Scanning {
    async fn wake(&mut self, ack: &[String], lease: Value) -> Reply {
        let seq = self.h.next_seq();
        self.h
            .call(
                "POST",
                "/v0/wake",
                Some(
                    json!({ "device_id": self.device_id, "seq": seq, "ack": ack, "lease": lease }),
                ),
            )
            .await
    }

    async fn poll(&mut self, cursor: &str, wait: u32) -> Reply {
        let seq = self.h.next_seq();
        self.h
            .call(
                "POST",
                "/v0/events",
                Some(json!({ "device_id": self.device_id, "seq": seq, "cursor": cursor, "wait": wait, "ack": [] })),
            )
            .await
    }

    fn page_len(&self) -> usize {
        self.h
            .state
            .scanner
            .page(self.account, None, 3500)
            .events
            .len()
    }
}

fn lease_json(w: &Wallet, from_height: u64, alert_mode: &str) -> Value {
    json!({
        "keys": [w.uivk_main()],
        "from_height": from_height,
        "duration_secs": 604800,
        "spend_alerts": false,
        "alert_mode": alert_mode,
    })
}

/// Waits up to 5 s for `cond`.
async fn eventually(mut cond: impl FnMut() -> bool) {
    for _ in 0..100 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("condition not met in time");
}

#[tokio::test]
async fn lease_live_match_long_poll_instant_push_and_ack() {
    let alice = Wallet::new(1);
    let mut s = scanning(100).await;

    let r = s.wake(&[], lease_json(&alice, 95, "instant")).await;
    assert_eq!(r.status, 200, "{}", r.json);
    assert_eq!(r.padded_len, RESPONSE_SIZE);
    assert_eq!(r.json["tip"], 100);
    assert_eq!(r.json["lease"]["active"], true);
    assert!(
        r.json["lease"]["expires_at"]
            .as_str()
            .unwrap()
            .ends_with('Z')
    );
    assert_eq!(r.json["events"], json!([]));
    let cursor = r.json["cursor"].as_str().unwrap().to_owned();

    // A long-poll waits; a payment in a new block releases it.
    let state = s.h.state.clone();
    let poll = {
        let cursor = cursor.clone();
        let seq = s.h.next_seq();
        let inner = s.h.inner(
            "POST",
            HOST,
            "/v0/events",
            Some(&s.h.token),
            SystemTime::now(),
            Some(&json!({ "device_id": s.device_id, "seq": seq, "cursor": cursor, "wait": 25, "ack": [] })),
        );
        let h = s.h.fork();
        tokio::spawn(async move { h.send_raw(&inner).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !poll.is_finished(),
        "a poll must not return without a release"
    );
    let started = std::time::Instant::now();
    let b = block(
        101,
        vec![tx(
            0xA1,
            vec![],
            vec![action(&alice.orchard, 7, false)],
            vec![],
        )],
    );
    lz_server::scanner::scan_block(&state, Arc::new(b)).await;
    let r = poll.await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(r.status, 200);
    assert_eq!(r.padded_len, RESPONSE_SIZE);
    let events = r.json["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["status"], "mined");
    assert_eq!(events[0]["height"], 101);
    assert!(events[0]["compact_tx"].is_string());
    let id = events[0]["id"].as_str().unwrap().to_owned();
    let cursor = r.json["cursor"].as_str().unwrap().to_owned();

    // An instant payment push went out, encrypted, fixed size, no tx data.
    eventually(|| !s.pushes.0.lock().unwrap().is_empty()).await;
    let (headers, body) = s.pushes.0.lock().unwrap().pop().unwrap();
    assert_eq!(headers["urgency"], "high");
    assert_eq!(headers["ttl"], "86400");
    assert!(headers.get("topic").is_none());
    let plain = lz_server::webpush::decrypt(&body, &s.push_keys.0, &s.push_keys.1).unwrap();
    assert_eq!(plain.len(), lz_proto::padding::PING_SIZE);
    let ping: Value = serde_json::from_slice(&plain).unwrap();
    assert_eq!(ping["t"], "payment");
    assert_eq!(ping["events"][0]["id"], id.as_str());
    assert!(ping["events"][0].get("compact_tx").is_none());

    // The next wake carries the event and a hint; an ack clears both.
    let r = s.wake(&[], lease_json(&alice, 101, "instant")).await;
    assert_eq!(r.json["events"][0]["id"], id.as_str());
    assert_eq!(r.json["hints"], json!([{ "start": 101, "end": 102 }]));
    let r = s
        .wake(
            std::slice::from_ref(&id),
            lease_json(&alice, 101, "instant"),
        )
        .await;
    assert_eq!(r.json["events"], json!([]));
    assert_eq!(r.json["hints"], json!([]));

    // Events already pending don't make a poll return early (that would
    // show the relay this account scans), but `wait: 0` does.
    let b = block(
        102,
        vec![tx(
            0xA2,
            vec![sapling_output(&alice.sapling, 3)],
            vec![],
            vec![],
        )],
    );
    lz_server::scanner::scan_block(&state, Arc::new(b)).await;
    let held = tokio::time::timeout(Duration::from_millis(500), s.poll(&cursor, 25)).await;
    assert!(held.is_err(), "a pending event released a poll early");
    let started = std::time::Instant::now();
    let r = s.poll(&cursor, 0).await;
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(r.json["events"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn default_mode_polls_are_released_by_new_blocks_too() {
    let mut s = scanning(10).await;
    let r = s.wake(&[], Value::Null).await;
    let cursor = r.json["cursor"].as_str().unwrap().to_owned();
    let state = s.h.state.clone();
    let release = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        lz_server::scanner::scan_block(&state, Arc::new(block(11, vec![]))).await;
    });
    let started = std::time::Instant::now();
    let r = s.poll(&cursor, 25).await;
    release.await.unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    assert_eq!((r.status, r.padded_len), (200, RESPONSE_SIZE));
    assert_eq!(r.json["events"], json!([]));
}

#[tokio::test]
async fn backfill_finds_older_payments_without_pushing() {
    let alice = Wallet::new(1);
    let mut s = scanning(100).await;
    s.chain.lock().unwrap().blocks[50].vtx = vec![tx(
        0xB1,
        vec![],
        vec![],
        vec![action(&alice.orchard, 9, true)],
    )];

    let r = s.wake(&[], lease_json(&alice, 40, "instant")).await;
    assert_eq!(r.status, 200);
    eventually(|| s.page_len() == 1).await;
    let r = s.wake(&[], lease_json(&alice, 40, "instant")).await;
    let e = &r.json["events"][0];
    assert_eq!(
        (e["height"].as_u64(), e["confirmations"].as_u64()),
        (Some(50), Some(10))
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        s.pushes.0.lock().unwrap().is_empty(),
        "backfill must not push"
    );
}

#[tokio::test]
async fn private_mode_events_ride_in_the_scheduled_ping() {
    let alice = Wallet::new(1);
    let mut s = scanning(10).await;
    s.wake(&[], lease_json(&alice, 10, "private")).await;
    let b = block(
        11,
        vec![tx(
            0xC1,
            vec![],
            vec![action(&alice.orchard, 4, false)],
            vec![],
        )],
    );
    lz_server::scanner::scan_block(&s.h.state, Arc::new(b)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        s.pushes.0.lock().unwrap().is_empty(),
        "private mode: no extra push"
    );

    push::wake_round(&s.h.state, Duration::ZERO).await;
    let (headers, body) = s.pushes.0.lock().unwrap().pop().unwrap();
    assert_eq!(headers["topic"], "wake");
    let plain = lz_server::webpush::decrypt(&body, &s.push_keys.0, &s.push_keys.1).unwrap();
    assert_eq!(plain.len(), lz_proto::padding::PING_SIZE);
    let ping: Value = serde_json::from_slice(&plain).unwrap();
    assert_eq!(ping["t"], "wake");
    assert_eq!(ping["events"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn opt_out_drops_lease_and_events() {
    let alice = Wallet::new(1);
    let mut s = scanning(10).await;
    s.wake(&[], lease_json(&alice, 10, "private")).await;
    let b = block(
        11,
        vec![tx(
            0xD1,
            vec![],
            vec![action(&alice.orchard, 5, false)],
            vec![],
        )],
    );
    lz_server::scanner::scan_block(&s.h.state, Arc::new(b)).await;
    assert_eq!(s.page_len(), 1);
    let r = s.wake(&[], Value::Null).await;
    assert_eq!(r.json["lease"]["active"], false);
    assert_eq!(r.json["events"], json!([]));
    assert!(!s.h.state.scanner.has_lease(s.account));
    assert_eq!(s.page_len(), 0);
}

#[tokio::test]
async fn lease_errors() {
    let alice = Wallet::new(1);
    let mut s = scanning(10).await;
    let mut spend = lease_json(&alice, 1, "instant");
    spend["spend_alerts"] = json!(true);
    spend["keys"] = json!(["uview1qqqqqq"]);
    let r = s.wake(&[], spend).await;
    assert_eq!(
        (r.status, problem_slug(&r).as_str()),
        (501, "spend-alerts-unavailable")
    );
    let mut bad = lease_json(&alice, 1, "instant");
    bad["keys"] = json!(["uivk1qqqqqqqq"]);
    let r = s.wake(&[], bad).await;
    assert_eq!(r.status, 400);
    let r = s.poll("not-a-cursor", 0).await;
    assert_eq!(r.status, 400);
}

/// Invariant 1: keys and key-derived data never reach the data directory or
/// the logs, even at trace level.
#[tokio::test]
async fn viewing_keys_never_reach_disk_or_logs() {
    let logs = global_logs();

    let alice = Wallet::new(1);
    let mut s = scanning(60).await;
    s.chain.lock().unwrap().blocks[55].vtx = vec![tx(
        0xE1,
        vec![sapling_output(&alice.sapling, 1)],
        vec![],
        vec![],
    )];
    s.wake(&[], lease_json(&alice, 50, "instant")).await;
    eventually(|| s.page_len() == 1).await;
    let b = block(
        61,
        vec![tx(
            0xE2,
            vec![],
            vec![action(&alice.orchard, 6, false)],
            vec![],
        )],
    );
    lz_server::scanner::scan_block(&s.h.state, Arc::new(b)).await;
    assert_eq!(s.page_len(), 2, "the live block must match");
    s.h.state.store.flush_if_dirty();

    let text = alice.uivk_main();
    let needles: Vec<Vec<u8>> = vec![
        text.as_bytes()[8..40].to_vec(),
        alice.orchard_ivk[..16].to_vec(),
        alice.sapling_ivk[..16].to_vec(),
    ];
    let log_text = logs.snapshot();
    assert!(
        String::from_utf8_lossy(&log_text).contains("lease matches"),
        "logs not captured:\n{}",
        String::from_utf8_lossy(&log_text)
    );
    for n in &needles {
        assert!(
            !log_text.windows(n.len()).any(|w| w == &n[..]),
            "key material in logs"
        );
    }
    for entry in std::fs::read_dir(&s.h.state.config.data_dir).unwrap() {
        let path = entry.unwrap().path();
        let bytes = std::fs::read(&path).unwrap();
        for n in &needles {
            assert!(
                !bytes.windows(n.len()).any(|w| w == &n[..]),
                "key material in {}",
                path.display()
            );
        }
    }
}

#[tokio::test]
async fn mempool_payment_alerts_at_once_then_mines_without_a_second_push() {
    use zcash_protocol::consensus::BranchId;
    let alice = Wallet::new(1);
    let mut s = scanning(10).await;
    s.wake(&[], lease_json(&alice, 10, "instant")).await;

    let raw = wallet::full_tx(&alice, false, true);
    let tx = lz_server::mempool::to_compact(&raw, BranchId::Nu6_3).unwrap();
    lz_server::mempool::scan_tx(&s.h.state, tx.clone()).await;
    let r = s.wake(&[], lease_json(&alice, 10, "instant")).await;
    let e = &r.json["events"][0];
    assert_eq!(
        (e["status"].as_str(), e["height"].as_u64()),
        (Some("mempool"), None)
    );
    assert!(e["compact_tx"].is_string());
    assert_eq!(r.json["hints"], json!([]), "no hint before it is mined");
    let id = e["id"].as_str().unwrap().to_owned();
    eventually(|| !s.pushes.0.lock().unwrap().is_empty()).await;
    assert_eq!(s.pushes.0.lock().unwrap().len(), 1);

    // Seeing it again in the mempool changes nothing.
    lz_server::mempool::scan_tx(&s.h.state, tx.clone()).await;
    // Mined: same id, now `mined` with a hint, and no second push.
    let mut mined = tx.clone();
    mined.index = 3;
    lz_server::scanner::scan_block(&s.h.state, Arc::new(block(11, vec![mined]))).await;
    let r = s.wake(&[], lease_json(&alice, 10, "instant")).await;
    let events = r.json["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["id"], id.as_str());
    assert_eq!(events[0]["status"], "mined");
    assert_eq!(events[0]["rev"], 2);
    assert_eq!(r.json["hints"], json!([{ "start": 11, "end": 12 }]));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        s.pushes.0.lock().unwrap().len(),
        1,
        "only the first sighting pushes"
    );

    // A reorg sends it back to `mined` → `reorged`; the mempool brings it
    // back to `mempool`.
    s.h.state.scanner.on_disconnect(11);
    lz_server::mempool::scan_tx(&s.h.state, tx).await;
    let r = s.wake(&[], lease_json(&alice, 10, "instant")).await;
    assert_eq!(r.json["events"][0]["status"], "mempool");
}

#[tokio::test]
async fn mempool_stream_is_followed_and_new_leases_see_what_is_pending() {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let mut s = scanning(10).await;
    s.chain.lock().unwrap().mempool = vec![
        wallet::full_tx(&bob, true, false),
        wallet::full_tx(&alice, true, false),
    ];
    // The stream runs before any lease exists, so nothing matches yet...
    tokio::spawn(lz_server::mempool::run(s.h.state.clone()));
    eventually(|| s.h.state.scanner.mempool_snapshot().len() == 2).await;
    assert_eq!(s.page_len(), 0);
    // ...but a new lease is checked against the pending transactions.
    s.wake(&[], lease_json(&alice, 10, "instant")).await;
    eventually(|| s.page_len() == 1).await;
    let r = s.wake(&[], lease_json(&alice, 10, "instant")).await;
    assert_eq!(r.json["events"][0]["status"], "mempool");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        s.pushes.0.lock().unwrap().is_empty(),
        "catch-up matches don't push"
    );
}

#[tokio::test]
async fn one_push_per_transaction_and_at_most_two_a_minute() {
    use zcash_protocol::consensus::BranchId;
    let alice = Wallet::new(1);
    let mut s = scanning(10).await;
    s.wake(&[], lease_json(&alice, 10, "instant")).await;

    // One transaction paying two of Alice's outputs: two events, one push.
    let two = tx(
        0xF1,
        vec![
            sapling_output(&alice.sapling, 1),
            sapling_output(&alice.sapling, 2),
        ],
        vec![],
        vec![],
    );
    // One clock for the whole burst so the per-minute push cap is deterministic.
    let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
    lz_server::scanner::scan_block_at(&s.h.state, Arc::new(block(11, vec![two])), now).await;
    assert_eq!(s.page_len(), 2);
    eventually(|| s.pushes.0.lock().unwrap().len() == 1).await;

    // Three more payments in the same minute: only one more push, but all
    // of them reach the wallet.
    for i in 0..3u8 {
        let raw = wallet::full_tx(&alice, true, false);
        let mut t = lz_server::mempool::to_compact(&raw, BranchId::Nu6_3).unwrap();
        t.txid = vec![0xF2 + i; 32];
        lz_server::mempool::scan_tx_at(&s.h.state, t, now).await;
    }
    assert_eq!(s.page_len(), 5);
    eventually(|| s.pushes.0.lock().unwrap().len() == 2).await;

    // The mempool snapshot keeps one copy per txid.
    let raw = wallet::full_tx(&alice, true, false);
    let t = lz_server::mempool::to_compact(&raw, BranchId::Nu6_3).unwrap();
    let before = s.h.state.scanner.mempool_snapshot().len();
    lz_server::mempool::scan_tx(&s.h.state, t.clone()).await;
    lz_server::mempool::scan_tx(&s.h.state, t).await;
    assert_eq!(s.h.state.scanner.mempool_snapshot().len(), before + 1);
}

#[tokio::test]
async fn an_unknown_branch_id_does_not_stop_mempool_scanning() {
    let alice = Wallet::new(1);
    let mut s = scanning(10).await;
    {
        let mut c = s.chain.lock().unwrap();
        c.branch_id = Some("not-hex".into());
        c.mempool = vec![wallet::full_tx(&alice, false, true)];
    }
    s.wake(&[], lease_json(&alice, 10, "instant")).await;
    tokio::spawn(lz_server::mempool::run(s.h.state.clone()));
    eventually(|| s.page_len() == 1).await;
}
