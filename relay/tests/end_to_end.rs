//! A wallet session through the relay: the real client core and the real
//! server's OHTTP gateway, over real sockets. The test plays the wallet
//! app's networking, sending each request to the relay.

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use common::Relay;
use lz_client::{
    Client, ClientState, HttpRequest, HttpResponse, KeyConfig, PushReceiver, Transport,
};
use lz_proto::lease::Network;
use lz_proto::token::AccountToken;
use lz_proto::url::ConnectionUrl;

const HOST: &str = "lz.test";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn temp_dir() -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let d = std::env::temp_dir().join(format!("lz-relay-e2e-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A server on a loopback port, with one account. Returns its origin and
/// the account token.
async fn server() -> (String, AccountToken) {
    let dir = temp_dir();
    let token = AccountToken::generate().unwrap();
    lz_server::store::Store::add_account_to_file(&dir, &token.hash()).unwrap();
    let state = lz_server::AppState::new(lz_server::config::Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        public_host: HOST.into(),
        base_path: String::new(),
        network: Network::Main,
        data_dir: dir,
        vapid_contact: "mailto:ops@lz.test".into(),
        direct_api: false,
        chain: None,
        push: Default::default(),
        limits: Default::default(),
        hardening: Default::default(),
        accounts: Default::default(),
    })
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let app = lz_server::gateway::router(state);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (origin, token)
}

/// What the wallet app does with each request: POST it to the relay,
/// naming the server's gateway.
async fn send(relay: &Relay, gateway: &str, req: &HttpRequest) -> (u16, Vec<u8>) {
    assert_eq!(req.url, format!("https://{HOST}/.well-known/ohttp-gateway"));
    let mut b = relay.client.post(relay.url(gateway));
    for (name, value) in &req.headers {
        b = b.header(*name, value.as_str());
    }
    let resp = b.body(req.body.clone()).send().await.unwrap();
    (resp.status().as_u16(), resp.bytes().await.unwrap().to_vec())
}

fn reply(r: &(u16, Vec<u8>)) -> HttpResponse<'_> {
    HttpResponse {
        status: r.0,
        retry_after: None,
        date: None,
        body: &r.1,
    }
}

#[tokio::test]
async fn a_wallet_session_through_the_relay() {
    let (gateway, token) = server().await;
    let relay = Relay::start("").await;

    // The key configuration, through the relay (spec §3.2). Both copies
    // come from the relay's cache, so they match.
    let first = relay.get(&gateway).await;
    assert_eq!(first.status(), 200);
    let first = first.bytes().await.unwrap();
    let second = relay.get(&gateway).await.bytes().await.unwrap();
    let config = KeyConfig::from_two_sources(&first, &second).unwrap();

    let url = ConnectionUrl::parse(&format!("lanternzero://{HOST}#{}", &*token.encode())).unwrap();
    let mut c = Client::new(
        url,
        Network::Main,
        Transport::Ohttp(config),
        ClientState::default(),
    )
    .unwrap();

    let p = c.info(now_ms()).unwrap();
    let r = send(&relay, &gateway, p.request()).await;
    assert_eq!(r.0, 200);
    let info = c.finish_info(p, reply(&r)).unwrap();
    assert!(!info.info.vapid_public_key.is_empty());

    let device = PushReceiver::generate().unwrap();
    let p = c
        .register(
            now_ms(),
            "https://push.example-wallet.app/wp/abc",
            device.push_keys(),
        )
        .unwrap();
    let r = send(&relay, &gateway, p.request()).await;
    c.finish_register(p, reply(&r)).unwrap();
    assert!(c.state().device_id.is_some());

    let p = c.wake(now_ms(), None).unwrap();
    let r = send(&relay, &gateway, p.request()).await;
    let w = c.finish_wake(p, reply(&r)).unwrap();
    assert!(!w.lease.active);

    let p = c.unregister(now_ms()).unwrap();
    let r = send(&relay, &gateway, p.request()).await;
    c.finish_unregister(p, reply(&r)).unwrap();
    assert_eq!(c.state().device_id, None);

    let [forwarded, key_configs, refused, limited, failed] = relay.state.totals.take();
    assert_eq!((forwarded, key_configs), (4, 2));
    assert_eq!((refused, limited, failed), (0, 0, 0));
}
