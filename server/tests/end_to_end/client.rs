//! The wallet client core (`lz-client`) against the real server, through
//! the real OHTTP gateway, the way a wallet SDK drives it. The test plays
//! the app's networking and the relay.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use lz_client::{
    Client, ClientState, Error, HttpRequest, HttpResponse, KeyConfig, PushReceiver, Transport,
};
use lz_proto::api::{DeviceRegistration, EventStatus, Hint, PingType};
use lz_proto::lease::{AlertMode, LeaseRequest, Network, ViewingKey};
use lz_proto::token::TokenHash;
use lz_proto::url::ConnectionUrl;
use lz_server::config::LimitsConfig;
use lz_server::gateway::GATEWAY_PATH;

use super::harness::{BASE, HOST, Harness, harness, harness_full, receiver};
use super::scanning::{eventually, sync_tip};
use crate::common::fake_lwd;
use crate::common::wallet::{Wallet, action, block, tx};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Plays the relay: forwards the encapsulated request to the gateway.
async fn relay(h: &Harness, req: &HttpRequest) -> (u16, Vec<u8>) {
    assert_eq!(req.url, format!("https://{HOST}{GATEWAY_PATH}"));
    let mut b = Request::post(GATEWAY_PATH);
    for (name, value) in &req.headers {
        b = b.header(*name, value.as_str());
    }
    let resp = h.outer(b.body(Body::from(req.body.clone())).unwrap()).await;
    let status = resp.status().as_u16();
    let body = axum::body::to_bytes(resp.into_body(), 1 << 16)
        .await
        .unwrap()
        .to_vec();
    (status, body)
}

fn reply(r: &(u16, Vec<u8>)) -> HttpResponse<'_> {
    HttpResponse {
        status: r.0,
        retry_after: None,
        body: &r.1,
    }
}

fn connection(h: &Harness) -> ConnectionUrl {
    ConnectionUrl::parse(&format!("lanternzero://{HOST}{BASE}#{}", h.token)).unwrap()
}

#[tokio::test]
async fn a_wallet_session_through_the_client_core() {
    let chain = fake_lwd::genesis();
    chain.lock().unwrap().build(1, 100, 1);
    let url = fake_lwd::serve(chain.clone()).await;
    let h = harness_full(true, LimitsConfig::default(), Some(url));
    sync_tip(&h).await;
    let mut sizes = Vec::new();

    // The key configuration, as fetched through two relays.
    let config = KeyConfig::from_two_relays(&h.key_config().await, &h.key_config().await).unwrap();
    let mut c = Client::new(
        connection(&h),
        Network::Main,
        Transport::Ohttp(config.clone()),
        ClientState::default(),
    )
    .unwrap();

    let p = c.info(now_ms()).unwrap();
    sizes.push(p.request().body.len());
    let r = relay(&h, p.request()).await;
    let info = c.finish_info(p, reply(&r)).unwrap();
    assert_eq!(
        info.info.vapid_public_key,
        h.state.vapid.current().public_b64
    );
    assert!(!info.vapid_key_changed);

    // Register with an endpoint from the vendor's gateway, then remove it.
    let device = PushReceiver::generate().unwrap();
    let p = c
        .register(
            now_ms(),
            "https://push.example-wallet.app/wp/abc",
            device.push_keys(),
        )
        .unwrap();
    sizes.push(p.request().body.len());
    let r = relay(&h, p.request()).await;
    let removed = c.finish_register(p, reply(&r)).unwrap();
    let p = c.unregister(now_ms()).unwrap();
    let r = relay(&h, p.request()).await;
    c.finish_unregister(p, reply(&r)).unwrap();
    assert_eq!(c.state().device_id, None);

    // Another copy of the app still holding that device id is told so.
    let mut stale = Client::new(
        connection(&h),
        Network::Main,
        Transport::Ohttp(config.clone()),
        ClientState {
            device_id: Some(removed),
            ..ClientState::default()
        },
    )
    .unwrap();
    let p = stale.wake(now_ms(), None).unwrap();
    let r = relay(&h, p.request()).await;
    assert_eq!(stale.finish_wake(p, reply(&r)), Err(Error::UnknownDevice));
    assert_eq!(stale.state().device_id, None);

    // A device whose pushes reach a local receiver. Registration over the
    // API needs an https endpoint, so it goes into the store directly.
    let (endpoint, pushes) = receiver(StatusCode::CREATED).await;
    let account = h
        .state
        .store
        .authenticate(&TokenHash::of_text(&h.token))
        .unwrap();
    let device_id = h
        .state
        .store
        .register_device(
            account,
            &DeviceRegistration {
                seq: 1,
                endpoint,
                keys: device.push_keys(),
                vapid_public_key: None,
            },
            10,
        )
        .unwrap();
    let mut state = c.state().clone();
    state.device_id = Some(device_id);
    let mut c = Client::new(
        connection(&h),
        Network::Main,
        Transport::Ohttp(config),
        state,
    )
    .unwrap();

    // The scheduled ping, opened on the device.
    lz_server::push::wake_round(&h.state, Duration::ZERO).await;
    eventually(|| !pushes.0.lock().unwrap().is_empty()).await;
    let (_, body) = pushes.0.lock().unwrap().pop().unwrap();
    let ping = device.open_ping(&body).unwrap();
    assert_eq!(ping.t, PingType::Wake);
    assert!(ping.events.is_empty());

    // Opt in: a lease on the wake.
    let alice = Wallet::new(1);
    let lease = || LeaseRequest {
        keys: vec![ViewingKey::new(alice.uivk_main())],
        from_height: 95,
        duration_secs: 604_800,
        spend_alerts: false,
        alert_mode: AlertMode::Instant,
    };
    let p = c.wake(now_ms(), None).unwrap();
    sizes.push(p.request().body.len());
    let p = c.wake(now_ms(), Some(lease())).unwrap();
    sizes.push(p.request().body.len());
    let r = relay(&h, p.request()).await;
    let w = c.finish_wake(p, reply(&r)).unwrap();
    assert_eq!(w.tip, 100);
    assert!(w.lease.active);
    assert!(w.events.is_empty());

    // The long-poll is held until a payment lands in a new block.
    let p = c.poll(now_ms()).unwrap();
    sizes.push(p.request().body.len());
    let held = {
        let h = h.fork();
        let req = p.request().clone();
        tokio::spawn(async move { relay(&h, &req).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!held.is_finished(), "a poll returned without a release");
    let b = block(
        101,
        vec![tx(
            0xA1,
            vec![],
            vec![action(&alice.orchard, 7, false)],
            vec![],
        )],
    );
    lz_server::scanner::scan_block(&h.state, Arc::new(b)).await;
    let r = held.await.unwrap();
    let out = c.finish_poll(p, reply(&r)).unwrap();
    assert_eq!(out.events.len(), 1);
    let event = out.events[0].clone();
    assert_eq!(event.status, EventStatus::Mined);
    assert_eq!(event.height, Some(101));
    assert!(event.compact_tx.is_some());

    // The instant payment push, opened on the device.
    eventually(|| !pushes.0.lock().unwrap().is_empty()).await;
    let (_, body) = pushes.0.lock().unwrap().pop().unwrap();
    let ping = device.open_ping(&body).unwrap();
    assert_eq!(ping.t, PingType::Payment);
    assert_eq!(ping.events[0].id, event.id);

    // The next wake repeats the event (not reported again) with its hint;
    // the acknowledgement rides on the one after and clears both.
    let p = c.wake(now_ms(), Some(lease())).unwrap();
    let r = relay(&h, p.request()).await;
    let w = c.finish_wake(p, reply(&r)).unwrap();
    assert!(w.events.is_empty());
    assert_eq!(
        w.hints,
        [Hint {
            start: 101,
            end: 102
        }]
    );
    assert!(c.ack(&event));
    let p = c.wake(now_ms(), Some(lease())).unwrap();
    let r = relay(&h, p.request()).await;
    let w = c.finish_wake(p, reply(&r)).unwrap();
    assert!(w.hints.is_empty());
    assert_eq!(c.pending_acks(), 0);

    // Invariant 4: every request looked the same to the relay.
    assert!(sizes.iter().all(|&s| s == sizes[0]), "{sizes:?}");
}

#[tokio::test]
async fn token_rotation_and_account_deletion_through_the_client_core() {
    use lz_proto::token::AccountToken;
    let chain = fake_lwd::genesis();
    chain.lock().unwrap().build(1, 100, 1);
    let url = fake_lwd::serve(chain.clone()).await;
    let h = harness_full(true, LimitsConfig::default(), Some(url));
    sync_tip(&h).await;
    let config = KeyConfig::from_two_relays(&h.key_config().await, &h.key_config().await).unwrap();
    let account = h
        .state
        .store
        .authenticate(&TokenHash::of_text(&h.token))
        .unwrap();
    let client = |url: &str, state: ClientState| {
        Client::new(
            ConnectionUrl::parse(url).unwrap(),
            Network::Main,
            Transport::Ohttp(config.clone()),
            state,
        )
        .unwrap()
    };
    let old_url = connection(&h).to_url().to_string();
    let mut c = client(&old_url, ClientState::default());
    let mut sizes = Vec::new();

    let p = c
        .register(
            now_ms(),
            "https://push.example-wallet.app/wp/abc",
            PushReceiver::generate().unwrap().push_keys(),
        )
        .unwrap();
    let r = relay(&h, p.request()).await;
    c.finish_register(p, reply(&r)).unwrap();
    let alice = Wallet::new(1);
    let lease = || LeaseRequest {
        keys: vec![ViewingKey::new(alice.uivk_main())],
        from_height: 95,
        duration_secs: 604_800,
        spend_alerts: false,
        alert_mode: AlertMode::Instant,
    };
    let p = c.wake(now_ms(), Some(lease())).unwrap();
    sizes.push(p.request().body.len());
    let r = relay(&h, p.request()).await;
    assert!(c.finish_wake(p, reply(&r)).unwrap().lease.active);

    // Rotate. Another copy of the app still has the old token.
    let mut old = client(&old_url, c.state().clone());
    let p = c
        .rotate_token(now_ms(), &AccountToken::generate().unwrap())
        .unwrap();
    sizes.push(p.request().body.len());
    let new_url = p.new_connection_url().to_string();
    let r = relay(&h, p.request()).await;
    assert_eq!(*c.finish_rotate(p, reply(&r)).unwrap(), new_url);
    assert_ne!(new_url, old_url);

    // The old token works until the new one is first used, then stops.
    let p = old.wake(now_ms(), Some(lease())).unwrap();
    let r = relay(&h, p.request()).await;
    assert!(old.finish_wake(p, reply(&r)).is_ok());
    let p = c.wake(now_ms(), Some(lease())).unwrap();
    let r = relay(&h, p.request()).await;
    let w = c.finish_wake(p, reply(&r)).unwrap();
    assert!(
        w.lease.active,
        "the account, its device, and its lease carried over"
    );
    let p = old.wake(now_ms(), Some(lease())).unwrap();
    let r = relay(&h, p.request()).await;
    assert_eq!(old.finish_wake(p, reply(&r)), Err(Error::Unauthorized));

    // Delete the account: everything goes at once, and the token stops.
    assert!(h.state.scanner.has_lease(account));
    let p = c.delete_account(now_ms()).unwrap();
    sizes.push(p.request().body.len());
    let r = relay(&h, p.request()).await;
    c.finish_delete_account(p, reply(&r)).unwrap();
    assert!(!h.state.scanner.has_lease(account));
    assert!(h.state.store.devices().is_empty());
    assert!(!h.state.store.has_account(account));
    let mut after = client(&new_url, ClientState::default());
    let p = after
        .register(
            now_ms(),
            "https://push.example-wallet.app/wp/def",
            PushReceiver::generate().unwrap().push_keys(),
        )
        .unwrap();
    let r = relay(&h, p.request()).await;
    assert_eq!(
        after.finish_register(p, reply(&r)),
        Err(Error::Unauthorized)
    );
    let accounts = std::fs::read_to_string(
        h.state
            .config
            .data_dir
            .join(lz_server::store::ACCOUNTS_FILE),
    )
    .unwrap();
    assert!(accounts.trim().is_empty(), "{accounts}");

    // Invariant 4: account actions look like every other request.
    assert!(sizes.iter().all(|&s| s == sizes[0]), "{sizes:?}");
}

#[tokio::test]
async fn vapid_rotation_keeps_devices_on_their_key_until_they_move() {
    let h = harness(true);
    let dir = h.state.config.data_dir.clone();
    let k1 = h.state.vapid.current().public_b64.clone();
    let account = h
        .state
        .store
        .authenticate(&TokenHash::of_text(&h.token))
        .unwrap();

    // A device record from before keys rotated, with no key recorded.
    let (endpoint, pushes) = receiver(StatusCode::CREATED).await;
    let device = PushReceiver::generate().unwrap();
    let legacy = h
        .state
        .store
        .register_device(
            account,
            &DeviceRegistration {
                seq: 1,
                endpoint,
                keys: device.push_keys(),
                vapid_public_key: None,
            },
            10,
        )
        .unwrap();
    let config = KeyConfig::from_two_relays(&h.key_config().await, &h.key_config().await).unwrap();
    let mut c = Client::new(
        connection(&h),
        Network::Main,
        Transport::Ohttp(config.clone()),
        ClientState::default(),
    )
    .unwrap();
    let p = c.info(now_ms()).unwrap();
    let r = relay(&h, p.request()).await;
    assert_eq!(
        c.finish_info(p, reply(&r)).unwrap().info.vapid_public_key,
        k1
    );

    // A wallet that never read `info` registers without naming a key: it
    // gets the current one.
    let mut unnamed = Client::new(
        connection(&h),
        Network::Main,
        Transport::Ohttp(config.clone()),
        ClientState {
            last_seq: c.state().last_seq,
            ..ClientState::default()
        },
    )
    .unwrap();
    let pre = "https://push.example-wallet.app/wp/pre";
    let p = unnamed.register(now_ms(), pre, device.push_keys()).unwrap();
    let r = relay(&h, p.request()).await;
    unnamed.finish_register(p, reply(&r)).unwrap();

    // Stop, rotate, start.
    let mut k2 = String::new();
    let h = h.restart_with(|dir| k2 = lz_server::rotate_vapid(dir, false).unwrap());
    assert_ne!(k2, k1);
    assert_eq!(h.state.vapid.current().public_b64, k2);
    assert_eq!(h.state.vapid.retired().collect::<Vec<_>>(), [k1.as_str()]);
    let vapid_of = |h: &Harness, id: &str| {
        h.state
            .store
            .devices()
            .into_iter()
            .find(|(d, _)| d == id)
            .and_then(|(_, d)| d.vapid)
    };
    assert_eq!(vapid_of(&h, &legacy).as_deref(), Some(k1.as_str()));

    // The old device is still signed for with the key its subscription is
    // bound to.
    lz_server::push::wake_round(&h.state, Duration::ZERO).await;
    eventually(|| !pushes.0.lock().unwrap().is_empty()).await;
    let (headers, body) = pushes.0.lock().unwrap().pop().unwrap();
    let auth = headers["authorization"].to_str().unwrap();
    assert!(auth.ends_with(&format!("k={k1}")), "{auth}");
    assert_eq!(device.open_ping(&body).unwrap().t, PingType::Wake);

    // Registering that same endpoint again without naming a key keeps the
    // key it was bound to: a subscription's key never changes.
    let p = unnamed.register(now_ms(), pre, device.push_keys()).unwrap();
    let r = relay(&h, p.request()).await;
    let again = unnamed.finish_register(p, reply(&r)).unwrap();
    assert_eq!(vapid_of(&h, &again).as_deref(), Some(k1.as_str()));
    h.state.store.remove_device(&again);

    // The wallet sees the new key and registers a subscription bound to it.
    let p = c.info(now_ms()).unwrap();
    let r = relay(&h, p.request()).await;
    let info = c.finish_info(p, reply(&r)).unwrap();
    assert!(info.vapid_key_changed);
    assert_eq!(info.info.vapid_public_key, k2);
    let p = c
        .register(
            now_ms(),
            "https://push.example-wallet.app/wp/new",
            device.push_keys(),
        )
        .unwrap();
    let r = relay(&h, p.request()).await;
    let moved = c.finish_register(p, reply(&r)).unwrap();
    assert_eq!(vapid_of(&h, &moved).as_deref(), Some(k2.as_str()));
    // Then it deletes its old device record by id.
    let p = c.unregister_device(now_ms(), &legacy).unwrap();
    let r = relay(&h, p.request()).await;
    c.finish_unregister(p, reply(&r)).unwrap();
    assert!(vapid_of(&h, &legacy).is_none());
    assert_eq!(c.state().device_id.as_deref(), Some(moved.as_str()));

    // A wallet that read `info` just before the rotation names the old key,
    // and gets it; a key the server doesn't hold is refused.
    let stale_state = |key: &str| ClientState {
        vapid_public_key: Some(key.to_owned()),
        last_seq: c.state().last_seq,
        ..ClientState::default()
    };
    let mut late = Client::new(
        connection(&h),
        Network::Main,
        Transport::Ohttp(config.clone()),
        stale_state(&k1),
    )
    .unwrap();
    let p = late
        .register(
            now_ms(),
            "https://push.example-wallet.app/wp/late",
            device.push_keys(),
        )
        .unwrap();
    let r = relay(&h, p.request()).await;
    let late_id = late.finish_register(p, reply(&r)).unwrap();
    assert_eq!(vapid_of(&h, &late_id).as_deref(), Some(k1.as_str()));
    let unknown = PushReceiver::generate().unwrap().push_keys().p256dh;
    let mut lost = Client::new(
        connection(&h),
        Network::Main,
        Transport::Ohttp(config.clone()),
        stale_state(&unknown),
    )
    .unwrap();
    let p = lost
        .register(
            now_ms(),
            "https://push.example-wallet.app/wp/lost",
            device.push_keys(),
        )
        .unwrap();
    let r = relay(&h, p.request()).await;
    assert_eq!(
        lost.finish_register(p, reply(&r)),
        Err(Error::UnknownVapidKey)
    );

    // Once no device is bound to the old key, the next start deletes it.
    h.state.store.remove_device(&late_id);
    let h = h.restart();
    assert_eq!(h.state.vapid.retired().count(), 0);
    let retired_dir = dir.join(lz_server::keys::VAPID_RETIRED_DIR);
    assert_eq!(std::fs::read_dir(&retired_dir).unwrap().count(), 0);
    assert!(h.state.vapid.get(&k1).is_none());

    // After a suspected leak, the old key goes at once, with its devices.
    let mut k3 = String::new();
    let h = h.restart_with(|dir| k3 = lz_server::rotate_vapid(dir, true).unwrap());
    assert_eq!(h.state.vapid.current().public_b64, k3);
    assert_eq!(h.state.vapid.retired().count(), 0);
    assert!(
        h.state.store.devices().is_empty(),
        "devices bound to k2 dropped"
    );
}

#[tokio::test]
async fn ohttp_key_rotation_through_the_client_core() {
    let h = harness(true);
    let dir = h.state.config.data_dir.clone();
    let fetch = |h: &Harness| {
        let h = h.fork();
        async move { KeyConfig::from_two_relays(&h.key_config().await, &h.key_config().await) }
    };
    let old = fetch(&h).await.unwrap();
    let mut c = Client::new(
        connection(&h),
        Network::Main,
        Transport::Ohttp(old.clone()),
        ClientState::default(),
    )
    .unwrap();
    let p = c.info(now_ms()).unwrap();
    let r = relay(&h, p.request()).await;
    c.finish_info(p, reply(&r)).unwrap();
    let device = PushReceiver::generate().unwrap();
    let endpoint = "https://push.example-wallet.app/wp/rotation";
    let p = c.register(now_ms(), endpoint, device.push_keys()).unwrap();
    let r = relay(&h, p.request()).await;
    c.finish_register(p, reply(&r)).unwrap();

    // Rotate; the running server picks it up (spec §3.2). Only the new
    // configuration is served, but a wallet that cached the old one keeps
    // working, and `info` tells it to move.
    assert_eq!(lz_server::rotate_ohttp(&dir, false).unwrap(), 2);
    let now_secs = now_ms() / 1000;
    assert_eq!(h.state.ohttp.reload(&dir, now_secs).unwrap(), Some(2));
    let new = fetch(&h).await.unwrap();
    assert_ne!(new.sha256_hex(), old.sha256_hex());
    let p = c.wake(now_ms(), None).unwrap();
    let r = relay(&h, p.request()).await;
    c.finish_wake(p, reply(&r)).unwrap();
    let p = c.info(now_ms()).unwrap();
    let r = relay(&h, p.request()).await;
    assert_eq!(
        c.finish_info(p, reply(&r)).unwrap_err(),
        Error::KeyConfigChanged
    );
    c.set_key_config(new.clone());
    let p = c.info(now_ms()).unwrap();
    let r = relay(&h, p.request()).await;
    c.finish_info(p, reply(&r)).unwrap();

    // A suspected leak, here picked up by a restart: old keys are dropped
    // at once. A wallet still on one gets the RFC 9458 `ohttp-key` problem, fetches the configuration
    // again, and carries on.
    assert_eq!(lz_server::rotate_ohttp(&dir, true).unwrap(), 3);
    let h = h.restart();
    let p = c.wake(now_ms(), None).unwrap();
    let r = relay(&h, p.request()).await;
    assert_eq!(r.0, 400);
    assert_eq!(
        c.finish_wake(p, reply(&r)).unwrap_err(),
        Error::KeyConfigRejected
    );
    c.set_key_config(fetch(&h).await.unwrap());
    let p = c.wake(now_ms(), None).unwrap();
    let r = relay(&h, p.request()).await;
    c.finish_wake(p, reply(&r)).unwrap();
}
