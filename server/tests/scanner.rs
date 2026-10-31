//! The scanner without HTTP: key decoding, trial decryption in all three
//! pools, the event lifecycle, leases, paging, and the memory-only rules
//! (invariants 1–3).

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::wallet::{Wallet, action, block, sapling_output, tx};
use lz_proto::api::EventStatus;
use lz_proto::event_id::Pool;
use lz_proto::lease::{AlertMode, LeaseRequest, Network, ViewingKey};
use lz_server::scanner::{
    EVENT_TTL, FINALITY_DEPTH, MAX_BACKFILL_BLOCKS, MAX_EVENTS_PER_ACCOUNT, Match, Scanner,
    trial_decrypt,
};
use lz_server::viewkey::{KeyError, ScanKeys};
use zcash_address::unified::Revision;
use zcash_protocol::consensus::NetworkType;
use zeroize::Zeroizing;

const A: [u8; 16] = [1; 16];
const B: [u8; 16] = [2; 16];
const WEEK: Duration = Duration::from_secs(604_800);

fn keys(w: &Wallet) -> ScanKeys {
    ScanKeys::decode(&[ViewingKey::new(w.uivk_main())], Network::Main).unwrap()
}

fn lease_req(w: &Wallet, from_height: u64, alert_mode: AlertMode) -> LeaseRequest {
    LeaseRequest {
        keys: vec![ViewingKey::new(w.uivk_main())],
        from_height,
        duration_secs: WEEK.as_secs(),
        spend_alerts: false,
        alert_mode,
    }
}

fn scanner() -> Scanner {
    Scanner::new(Zeroizing::new([7; 32]))
}

fn t0() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_800_000_000)
}

#[test]
fn decodes_revision_0_and_2_in_either_case() {
    let w = Wallet::new(1);
    for text in [
        w.uivk(NetworkType::Main, Revision::R0),
        w.uivk(NetworkType::Main, Revision::R2),
        w.uivk(NetworkType::Main, Revision::R0).to_ascii_uppercase(),
    ] {
        let k = ScanKeys::decode(&[ViewingKey::new(text)], Network::Main).unwrap();
        assert_eq!((k.sapling.len(), k.orchard.len()), (1, 1));
    }
    let test = w.uivk(NetworkType::Test, Revision::R0);
    assert_eq!(
        ScanKeys::decode(&[ViewingKey::new(test)], Network::Main).unwrap_err(),
        KeyError::WrongNetwork(0)
    );
    assert_eq!(
        ScanKeys::decode(&[ViewingKey::new("uivk1qqqqqq".into())], Network::Main).unwrap_err(),
        KeyError::Invalid(0)
    );
}

#[test]
fn key_types_never_print_key_material() {
    let w = Wallet::new(1);
    let text = w.uivk_main();
    let k = ScanKeys::decode(&[ViewingKey::new(text.clone())], Network::Main).unwrap();
    assert_eq!(format!("{k:?}"), "ScanKeys(<redacted>)");
    assert!(!format!("{:?}", ViewingKey::new(text.clone())).contains(&text[5..20]));
    assert!(!format!("{:?}", lease_req(&w, 1, AlertMode::Instant)).contains(&text[5..20]));
    // Errors name the key's position, never its content.
    let err = ScanKeys::decode(&[ViewingKey::new(text.replace('q', "p"))], Network::Main)
        .unwrap_err()
        .to_string();
    assert!(!err.contains(&text[5..20]), "{err}");
}

#[test]
fn finds_payments_in_sapling_orchard_and_ironwood_only_for_their_owner() {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let b = block(
        100,
        vec![
            tx(
                0xA1,
                vec![
                    sapling_output(&bob.sapling, 1),
                    sapling_output(&alice.sapling, 2),
                ],
                vec![
                    action(&bob.orchard, 1, false),
                    action(&alice.orchard, 2, false),
                ],
                vec![],
            ),
            tx(0xA2, vec![], vec![], vec![action(&alice.orchard, 3, true)]),
        ],
    );
    let leases = vec![(A, Arc::new(keys(&alice)))];
    let mut found = trial_decrypt(&b, &leases);
    found.sort_by_key(|m| (m.tx, m.pool.code(), m.index));
    let m = |tx, pool, index| Match {
        account: A,
        tx,
        pool,
        index,
    };
    assert_eq!(
        found,
        [
            m(0, Pool::Sapling, 1),
            m(0, Pool::Orchard, 1),
            m(1, Pool::Ironwood, 0)
        ]
    );
    // Garbage outputs are skipped, not fatal.
    let mut junk = b.clone();
    junk.vtx[0].actions[0].cmx = vec![0xFF; 32];
    junk.vtx[0].outputs[0].ciphertext.truncate(10);
    assert_eq!(trial_decrypt(&junk, &leases).len(), 3);
}

#[test]
fn a_sapling_only_key_finds_only_sapling() {
    let w = Wallet::new(3);
    let k = ScanKeys::decode(&[ViewingKey::new(w.sapling_only_uivk())], Network::Main).unwrap();
    let b = block(
        5,
        vec![tx(
            1,
            vec![sapling_output(&w.sapling, 1)],
            vec![action(&w.orchard, 1, false)],
            vec![],
        )],
    );
    let found = trial_decrypt(&b, &[(A, Arc::new(k))]);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].pool, Pool::Sapling);
}

/// Records a block paying `w` with one Orchard action, as the live scanner
/// does.
fn pay(s: &Scanner, w: &Wallet, height: u64, txid: u8, tip: u64, now: SystemTime) -> usize {
    let b = block(
        height,
        vec![tx(
            txid,
            vec![],
            vec![action(&w.orchard, txid, false)],
            vec![],
        )],
    );
    let leases = s.active_keys(now);
    let matches = trial_decrypt(&b, &leases);
    s.record(&b, &matches, tip, now).len()
}

#[test]
fn event_lifecycle_confirmations_reorg_ack() {
    let w = Wallet::new(1);
    let s = scanner();
    let now = t0();
    assert!(
        s.set_lease(
            A,
            keys(&w),
            &lease_req(&w, 90, AlertMode::Instant),
            WEEK,
            100,
            now
        )
        .is_some()
    );

    assert_eq!(pay(&s, &w, 101, 0xA1, 101, now), 1);
    let page = s.page(A, None, 3500);
    assert_eq!(page.events.len(), 1);
    let e = &page.events[0];
    assert_eq!(
        (e.status, e.height, e.confirmations, e.rev),
        (EventStatus::Mined, Some(101), 1, 1)
    );
    assert!(e.compact_tx.is_some());
    assert_eq!(
        s.hints(A),
        [lz_proto::api::Hint {
            start: 101,
            end: 102
        }]
    );
    let id = e.id.clone();
    let cursor = page.cursor;
    assert!(!s.has_after(A, cursor));

    // The same payment seen again changes nothing (deterministic ids).
    assert_eq!(pay(&s, &w, 101, 0xA1, 101, now), 0);
    assert!(!s.has_after(A, cursor));

    // Confirmations count up to the finality depth, then stop.
    for tip in 102..120 {
        s.on_tip(tip);
    }
    let e = &s.page(A, None, 3500).events[0];
    assert_eq!(e.confirmations, FINALITY_DEPTH);
    assert_eq!(e.rev, FINALITY_DEPTH);
    assert!(s.has_after(A, cursor));

    // A reorg marks it, and seeing it again at a new height re-mines it.
    s.on_disconnect(101);
    let e = &s.page(A, None, 3500).events[0];
    assert_eq!(
        (e.status, e.height, e.confirmations),
        (EventStatus::Reorged, None, 0)
    );
    assert!(s.hints(A).is_empty());
    assert_eq!(
        pay(&s, &w, 103, 0xA1, 103, now),
        0,
        "same id, not a new event"
    );
    let e = &s.page(A, None, 3500).events[0];
    assert_eq!(
        (e.status, e.height, e.id.as_str()),
        (EventStatus::Mined, Some(103), id.as_str())
    );

    // An ack deletes the event and its hint.
    s.ack(A, std::slice::from_ref(&id));
    assert!(s.page(A, None, 3500).events.is_empty());
    assert!(s.hints(A).is_empty());
}

#[test]
fn leases_renew_replace_end_and_expire() {
    let alice = Wallet::new(1);
    let other = Wallet::new(2);
    let s = scanner();
    let now = t0();

    // First lease: backfill from `from_height`, clamped to the window.
    let bf = s
        .set_lease(
            A,
            keys(&alice),
            &lease_req(&alice, 1, AlertMode::Instant),
            WEEK,
            50_000,
            now,
        )
        .unwrap();
    assert_eq!((bf.from, bf.to), (50_000 - MAX_BACKFILL_BLOCKS, 50_000));
    // Same keys again: a renewal, no backfill, later expiry.
    let later = now + Duration::from_secs(3600);
    assert!(
        s.set_lease(
            A,
            keys(&alice),
            &lease_req(&alice, 49_990, AlertMode::Private),
            WEEK,
            50_000,
            later
        )
        .is_none()
    );
    let status = s.lease_status(A, later);
    assert!(status.active);
    // New keys: a new lease and backfill.
    let bf2 = s
        .set_lease(
            A,
            keys(&other),
            &lease_req(&other, 49_990, AlertMode::Instant),
            WEEK,
            50_000,
            later,
        )
        .unwrap();
    assert_ne!(bf.generation, bf2.generation);
    assert_eq!(bf2.from, 49_990);
    // Without a known tip, nothing to backfill yet; the first renewal once
    // the tip is known starts it.
    assert!(
        s.set_lease(
            B,
            keys(&alice),
            &lease_req(&alice, 1, AlertMode::Instant),
            WEEK,
            0,
            now
        )
        .is_none()
    );
    let late = s
        .set_lease(
            B,
            keys(&alice),
            &lease_req(&alice, 5, AlertMode::Instant),
            WEEK,
            20,
            now,
        )
        .unwrap();
    assert_eq!((late.from, late.to), (5, 20));
    assert!(
        s.set_lease(
            B,
            keys(&alice),
            &lease_req(&alice, 5, AlertMode::Instant),
            WEEK,
            21,
            now
        )
        .is_none()
    );

    // Opt-out drops keys and events at once (invariants 2 and 3).
    assert_eq!(pay(&s, &alice, 10, 1, 10, now), 1, "B's lease matches");
    s.end_lease(B);
    assert!(!s.has_lease(B));
    assert!(s.page(B, None, 3500).events.is_empty());

    // Expiry: the lease stops matching at once, and keys leave memory.
    let expired = later + WEEK + Duration::from_secs(1);
    assert!(!s.lease_status(A, expired).active);
    assert!(s.active_keys(expired).is_empty());
    assert_eq!(pay(&s, &other, 11, 2, 11, expired), 0);
    assert!(!s.has_lease(A));
}

#[test]
fn events_expire_after_seven_days() {
    let w = Wallet::new(1);
    let s = scanner();
    let now = t0();
    s.set_lease(
        A,
        keys(&w),
        &lease_req(&w, 1, AlertMode::Instant),
        WEEK,
        10,
        now,
    );
    pay(&s, &w, 10, 1, 10, now);
    s.sweep(now + EVENT_TTL - Duration::from_secs(1));
    assert_eq!(s.page(A, None, 3500).events.len(), 1);
    s.sweep(now + EVENT_TTL);
    assert!(s.page(A, None, 3500).events.is_empty());
}

#[test]
fn pages_split_by_size_and_oversized_events_drop_compact_tx() {
    let w = Wallet::new(1);
    let s = scanner();
    let now = t0();
    s.set_lease(
        A,
        keys(&w),
        &lease_req(&w, 1, AlertMode::Instant),
        WEEK,
        10,
        now,
    );
    for i in 0..12 {
        pay(&s, &w, 10 + u64::from(i), i + 1, 30, now);
    }
    let p1 = s.page(A, None, 3500);
    assert!(p1.more && !p1.events.is_empty() && p1.events.len() < 12);
    let p2 = s.page(A, Some(p1.cursor), 3500);
    let p3 = s.page(A, Some(p2.cursor), 3500);
    let total = p1.events.len() + p2.events.len() + p3.events.len();
    assert_eq!(
        total,
        12,
        "pages: {} {} {}",
        p1.events.len(),
        p2.events.len(),
        p3.events.len()
    );
    assert!(!p3.more);

    // A transaction too big for any page is sent without compact_tx.
    let big = block(
        50,
        vec![tx(
            0xEE,
            (0..40).map(|i| sapling_output(&w.sapling, i)).collect(),
            vec![],
            vec![],
        )],
    );
    let m = trial_decrypt(&big, &s.active_keys(now));
    assert_eq!(m.len(), 40);
    s.record(&big, &m[..1], 50, now);
    let last = s.page(A, Some(p3.cursor), 3500);
    assert_eq!(last.events.len(), 1);
    assert!(last.events[0].compact_tx.is_none());
}

#[test]
fn private_mode_pings_carry_up_to_four_events() {
    let w = Wallet::new(1);
    let s = scanner();
    let now = t0();
    s.set_lease(
        A,
        keys(&w),
        &lease_req(&w, 1, AlertMode::Instant),
        WEEK,
        10,
        now,
    );
    for i in 0..6 {
        pay(&s, &w, 10, i + 1, 10, now);
    }
    assert!(
        s.ping_events(A, now).is_empty(),
        "instant mode: empty pings"
    );
    s.set_lease(
        A,
        keys(&w),
        &lease_req(&w, 1, AlertMode::Private),
        WEEK,
        10,
        now,
    );
    let events = s.ping_events(A, now);
    assert_eq!(events.len(), 4);
    assert!(events.iter().all(|e| e.compact_tx.is_none()));
}

#[test]
fn caps_stored_events_per_account() {
    let w = Wallet::new(1);
    let s = scanner();
    let now = t0();
    s.set_lease(
        A,
        keys(&w),
        &lease_req(&w, 1, AlertMode::Instant),
        WEEK,
        10,
        now,
    );
    let mut recorded = 0usize;
    let mut height = 10u64;
    let mut txid = 0u8;
    while recorded <= MAX_EVENTS_PER_ACCOUNT {
        let batch = (MAX_EVENTS_PER_ACCOUNT + 1 - recorded).min(10);
        let actions: Vec<_> = (0..batch)
            .map(|j| action(&w.orchard, j as u8, false))
            .collect();
        let b = block(height, vec![tx(txid, vec![], actions, vec![])]);
        let leases = s.active_keys(now);
        let matches = trial_decrypt(&b, &leases);
        recorded += s.record(&b, &matches, 30, now).len();
        height += 1;
        txid = txid.wrapping_add(1);
    }
    let mut total = 0usize;
    let mut cursor = None;
    loop {
        let page = s.page(A, cursor, 10_000_000);
        total += page.events.len();
        if !page.more {
            break;
        }
        cursor = Some(page.cursor);
    }
    assert_eq!(total, MAX_EVENTS_PER_ACCOUNT);
}

#[test]
fn releases_wake_waiting_polls() {
    let s = scanner();
    let rx = s.subscribe_release();
    assert!(!rx.has_changed().unwrap());
    s.release();
    assert!(rx.has_changed().unwrap());
}

#[test]
fn mempool_transactions_parse_to_compact_and_match() {
    use zcash_protocol::consensus::BranchId;
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let raw = common::wallet::full_tx(&alice, true, true);
    let tx = lz_server::mempool::to_compact(&raw, BranchId::Nu6_3).unwrap();
    assert_eq!(tx.txid.len(), 32);
    assert!(!tx.outputs.is_empty() && !tx.ironwood_actions.is_empty());
    let found = lz_server::scanner::trial_decrypt_txs(
        std::slice::from_ref(&tx),
        &[(A, Arc::new(keys(&alice)))],
    );
    let mut pools: Vec<u8> = found.iter().map(|m| m.pool.code()).collect();
    pools.sort();
    assert_eq!(pools, [0, 2], "one hit each in Sapling and Ironwood");
    assert!(
        lz_server::scanner::trial_decrypt_txs(
            std::slice::from_ref(&tx),
            &[(B, Arc::new(keys(&bob)))]
        )
        .is_empty()
    );
    assert!(lz_server::mempool::to_compact(&raw[..raw.len() - 1], BranchId::Nu6_3).is_none());
    assert!(lz_server::mempool::to_compact(b"junk", BranchId::Nu6_3).is_none());
}
