//! Runs against a real Zebra and Zaino on regtest. Ignored by default; see
//! `deploy/regtest/README.md` for how to start them:
//!
//! ```sh
//! cargo test -p lz-server --test regtest -- --ignored --nocapture --test-threads 1
//! ```
//!
//! Zebra's `miner_address` must be the test wallet's Sapling address
//! (`print_regtest_addresses` prints it), so block rewards are payments the
//! scanner should find.

// These tests report what the real Zaino sends; printing it is the point.
#![allow(clippy::print_stdout)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::wallet::Wallet;
use lz_proto::lease::{AlertMode, LeaseRequest, Network, ViewingKey};
use lz_server::chain::{ChainEvent, Follower, Lightwalletd, Step};
use lz_server::config::{ChainConfig, Config, LimitsConfig, PushConfig};
use lz_server::viewkey::ScanKeys;
use lz_server::{AppState, scanner};
use serde_json::{Value, json};
use zcash_protocol::consensus::NetworkType;

fn lwd_url() -> String {
    std::env::var("LZ_REGTEST_LWD").unwrap_or_else(|_| "http://127.0.0.1:8137".into())
}

fn zebra_url() -> String {
    std::env::var("LZ_REGTEST_ZEBRA").unwrap_or_else(|_| "http://127.0.0.1:18232".into())
}

async fn zebra(method: &str, params: Value) -> Value {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let resp = reqwest::Client::new()
        .post(zebra_url())
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .expect("Zebra RPC reachable");
    let v: Value = serde_json::from_slice(&resp.bytes().await.unwrap()).unwrap();
    assert!(v["error"].is_null(), "{method}: {}", v["error"]);
    v["result"].clone()
}

async fn mine(n: u32) -> u64 {
    zebra("generate", json!([n])).await;
    zebra("getblockcount", json!([])).await.as_u64().unwrap()
}

/// Waits up to 60 s for Zaino to serve `height`.
async fn zaino_at(source: &Lightwalletd, height: u64) {
    for _ in 0..120 {
        if source.latest_height().await.unwrap_or(0) >= height {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("Zaino didn't reach {height}");
}

/// Prints the test wallet's regtest addresses, for Zebra's `miner_address`.
#[test]
#[ignore]
fn print_regtest_addresses() {
    let w = Wallet::new(1);
    println!("SAPLING_UA={}", w.sapling_ua(NetworkType::Regtest));
    println!(
        "UIVK={}",
        w.uivk(NetworkType::Regtest, zcash_address::unified::Revision::R0)
    );
}

/// What Zaino actually sends, compared with what our client assumes.
#[tokio::test]
#[ignore]
async fn zaino_matches_our_assumptions() {
    let source = Lightwalletd::new(&lwd_url()).unwrap();
    let tip = mine(1).await;
    zaino_at(&source, tip).await;

    // Network name: our check expects "regtest".
    println!("lightd info: {:?}", source.info().await.unwrap());
    let net = source.check_network(Network::Regtest).await;
    println!("check_network(Regtest): {net:?}");
    // Branch id: hex, parsed into a known upgrade.
    println!(
        "consensus_branch_id: {:?}",
        source.consensus_branch_id().await
    );

    // Byte order: compact block hashes vs Zebra's display hex.
    let block = source.blocks(tip, tip).await.unwrap().pop().unwrap();
    let display = zebra("getbestblockhash", json!([])).await;
    let display = display.as_str().unwrap();
    let mut reversed = block.hash.clone();
    reversed.reverse();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    println!(
        "CompactBlock.hash is {} order",
        if hex(&reversed) == display {
            "internal (reversed display)"
        } else if hex(&block.hash) == display {
            "display"
        } else {
            "UNKNOWN"
        }
    );
    let prev = source
        .blocks(tip - 1, tip - 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        block.prev_hash, prev.hash,
        "prev_hash links to the parent's hash"
    );
    assert_eq!(block.vtx.len(), 1, "a coinbase-only block");
    assert!(
        !block.vtx[0].outputs.is_empty(),
        "the coinbase pays a Sapling output"
    );
    net.unwrap();
}

/// The follower tracks Zebra's tip through Zaino.
#[tokio::test]
#[ignore]
async fn follower_tracks_the_real_tip() {
    let source = Lightwalletd::new(&lwd_url()).unwrap();
    let chain = Arc::new(lz_server::chain::Chain::default());
    let mut events = chain.subscribe();
    let mut f = Follower::new(chain.clone(), source.clone());
    let start = mine(1).await;
    zaino_at(&source, start).await;
    while f.step().await.unwrap() != Step::CaughtUp {}
    assert_eq!(chain.tip(), start);
    assert!(matches!(events.recv().await.unwrap(), ChainEvent::Reset(_)));

    let tip = mine(3).await;
    zaino_at(&source, tip).await;
    while f.step().await.unwrap() != Step::CaughtUp {}
    assert_eq!(chain.tip(), tip);
    for h in start + 1..=tip {
        match events.recv().await.unwrap() {
            ChainEvent::Connected(b) => assert_eq!(b.height, h),
            other => panic!("expected block {h}, got {other:?}"),
        }
    }
}

fn state() -> Arc<AppState> {
    let mut raw = [0u8; 8];
    rand::fill(&mut raw);
    let name: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let dir = std::env::temp_dir().join(format!("lz-regtest-{name}"));
    AppState::new(Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        public_host: "lz.test".into(),
        base_path: String::new(),
        network: Network::Regtest,
        data_dir: dir,
        vapid_contact: "mailto:ops@lz.test".into(),
        direct_api: false,
        chain: Some(ChainConfig {
            lightwalletd: lwd_url(),
            poll_secs: 1,
        }),
        push: PushConfig::default(),
        limits: LimitsConfig::default(),
        hardening: Default::default(),
        accounts: Default::default(),
    })
    .unwrap()
}

/// Backfill finds the block rewards already paid to the test wallet, and
/// live scanning finds new ones as they're mined.
#[tokio::test]
#[ignore]
async fn scanner_finds_real_block_rewards() {
    let state = state();
    let source = state.chain_source.clone().unwrap();
    let tip = mine(2).await;
    zaino_at(&source, tip).await;

    tokio::spawn(lz_server::chain::run(
        state.chain.clone(),
        source.clone(),
        Network::Regtest,
        Duration::from_secs(1),
    ));
    tokio::spawn(scanner::run(state.clone()));
    for _ in 0..60 {
        if state.chain.tip() >= tip {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(state.chain.tip(), tip, "follower caught up");

    let w = Wallet::new(1);
    let uivk = w.uivk(NetworkType::Regtest, zcash_address::unified::Revision::R0);
    let req = LeaseRequest {
        keys: vec![ViewingKey::new(uivk)],
        from_height: tip - 4,
        duration_secs: 604_800,
        spend_alerts: false,
        alert_mode: AlertMode::Private,
    };
    let keys = ScanKeys::decode(&req.keys, Network::Regtest).unwrap();
    let account = [9u8; 16];
    let bf = state
        .scanner
        .set_lease(
            account,
            keys,
            &req,
            Duration::from_secs(604_800),
            tip,
            std::time::SystemTime::now(),
        )
        .unwrap();
    scanner::backfill(state.clone(), bf).await;
    let page = state.scanner.page(account, None, 3500);
    let heights: Vec<_> = page.events.iter().filter_map(|e| e.height).collect();
    println!("backfill found rewards at {heights:?}");
    assert_eq!(page.events.len(), 5, "one reward per block in [tip-4, tip]");

    // Live: the next two blocks' rewards appear as they are mined.
    let new_tip = mine(2).await;
    for _ in 0..60 {
        if state.scanner.page(account, None, 3500).events.len() >= 7 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let mut heights: Vec<u64> = state
        .scanner
        .page(account, None, 3500)
        .events
        .iter()
        .filter_map(|e| e.height)
        .collect();
    heights.sort_unstable();
    println!("after mining to {new_tip}: {heights:?}");
    assert!(heights.contains(&new_tip) && heights.contains(&(new_tip - 1)));
    assert_eq!(
        state.scanner.hints(account).last().unwrap().end,
        new_tip + 1
    );
}

/// `GetMempoolStream` sends the mempool, then ends when a block is mined.
#[tokio::test]
#[ignore]
async fn mempool_stream_ends_at_the_next_block() {
    let source = Lightwalletd::new(&lwd_url()).unwrap();
    let tip = mine(1).await;
    zaino_at(&source, tip).await;
    let mut stream = source.mempool_stream().await.unwrap();
    let ended = tokio::spawn(async move {
        let mut n = 0;
        while let Ok(Some(_)) = stream.message().await {
            n += 1;
        }
        n
    });
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(
        !ended.is_finished(),
        "an empty mempool keeps the stream open"
    );
    mine(1).await;
    let n = tokio::time::timeout(Duration::from_secs(60), ended)
        .await
        .expect("stream ended after a block")
        .unwrap();
    println!("mempool stream sent {n} transactions, then ended");
}

/// NU7 activates at height 10 on the regtest kit (3,543,405 on mainnet).
/// Zaino must follow across it, report the NU7 branch id, and the scanner
/// must find payments on both sides of the boundary.
#[tokio::test]
#[ignore]
async fn crosses_the_nu7_boundary() {
    if std::env::var("LZ_REGTEST_NU7").is_err() {
        println!(
            "skipped: start the kit with ZEBRA_CONFIG=zebrad-nu7.toml and set LZ_REGTEST_NU7=1"
        );
        return;
    }
    let state = state();
    let source = state.chain_source.clone().unwrap();
    let mut tip = zebra("getblockcount", json!([])).await.as_u64().unwrap();
    if tip < 15 {
        tip = mine((15 - tip) as u32).await;
    }
    zaino_at(&source, tip).await;
    assert_eq!(
        source.consensus_branch_id().await.unwrap(),
        zcash_protocol::consensus::BranchId::Nu7
    );
    let info = source.info().await.unwrap();
    println!(
        "after NU7: upgrade {} at {}",
        info.upgrade_name, info.upgrade_height
    );

    // Every block from 5 to the tip pays the test wallet; all are found.
    tokio::spawn(lz_server::chain::run(
        state.chain.clone(),
        source.clone(),
        Network::Regtest,
        Duration::from_secs(1),
    ));
    for _ in 0..60 {
        if state.chain.tip() >= tip {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let w = Wallet::new(1);
    let req = LeaseRequest {
        keys: vec![ViewingKey::new(
            w.uivk(NetworkType::Regtest, zcash_address::unified::Revision::R0),
        )],
        from_height: 5,
        duration_secs: 604_800,
        spend_alerts: false,
        alert_mode: AlertMode::Private,
    };
    let keys = ScanKeys::decode(&req.keys, Network::Regtest).unwrap();
    let account = [7u8; 16];
    let bf = state
        .scanner
        .set_lease(
            account,
            keys,
            &req,
            Duration::from_secs(604_800),
            tip,
            std::time::SystemTime::now(),
        )
        .unwrap();
    scanner::backfill(state.clone(), bf).await;
    let mut found: Vec<u64> = Vec::new();
    let mut after = None;
    loop {
        let page = state.scanner.page(account, after, 3500);
        found.extend(page.events.iter().filter_map(|e| e.height));
        if !page.more {
            break;
        }
        after = Some(page.cursor);
    }
    found.sort_unstable();
    assert_eq!(
        found,
        (5..=tip).collect::<Vec<_>>(),
        "a reward in every block, before and after NU7"
    );
}
