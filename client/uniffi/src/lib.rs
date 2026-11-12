//! UniFFI bindings for the Lantern Zero client core (`lz-client`), for
//! apps without a Rust core of their own: Swift and Kotlin directly, and
//! React Native through a native module over those.
//!
//! The surface follows `lz-client`: every call builds an [`HttpRequest`]
//! for the app to send with its own HTTP stack (URLSession, OkHttp), and a
//! [`Pending`] value that the matching `finish_*` call opens the
//! [`HttpResponse`] with. Only the phone side is exposed; merchant
//! backends (webhooks, clients without a device) use `lz-client` from Rust.
//!
//! **Secrets across the boundary.** The account token (inside the
//! connection URL), viewing keys, and push secrets cross into Swift or
//! Kotlin as strings or bytes, which those languages can't wipe. Keep them
//! in the native layer and the keychain. A React Native module MUST NOT
//! pass them into JavaScript, where debuggers, error reporters, and logs
//! can see them: JavaScript gets events and outcomes, not keys.

use std::sync::{Mutex, MutexGuard};

use lz_client::lz_proto;
use lz_proto::api as proto;
use lz_proto::lease as plz;
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

// ---------------------------------------------------------------- errors

/// Why a call failed. Messages never include tokens, keys, or bodies. The
/// variants follow `lz_client::Error`; its docs say what to do for each.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum LzError {
    #[error("request too large for the fixed size")]
    TooLarge,
    /// No encapsulated response. If the key configuration is more than an
    /// hour old, fetch it again as for `KeyConfigRejected` (spec §3.2).
    #[error("relay answered {status}")]
    Relay { status: u16 },
    /// Fetch the key configuration again from both sources,
    /// `check_key_config`, and build the request again.
    #[error("the server no longer accepts this OHTTP key configuration")]
    KeyConfigRejected,
    #[error("malformed or unauthentic response")]
    Transport,
    #[error("unexpected response from the server")]
    Malformed,
    /// Build the same request again and send it once more.
    #[error("stale seq; send the request again")]
    StaleSeq,
    /// Corrected: persist the state, build the request again, send it once more.
    #[error("device clock was off; corrected, send the request again")]
    ClockCorrected,
    /// Register again.
    #[error("unknown device; register again")]
    UnknownDevice,
    #[error("no device registered")]
    NotRegistered,
    #[error("no cursor yet; send a wake first")]
    NoCursor,
    #[error("rate limited")]
    RateLimited { retry_after_secs: Option<u64> },
    #[error("account token not accepted")]
    Unauthorized,
    #[error("this server does not offer scanning")]
    ScanningUnavailable,
    /// Send no lease from now on, and tell the user.
    #[error("scanning is not part of this account")]
    ScanningNotIncluded,
    #[error("this server does not offer spend alerts")]
    SpendAlertsUnavailable,
    #[error("the account has the maximum number of devices")]
    TooManyDevices,
    /// Read `info` again, subscribe with the key it reports, register.
    #[error("the server doesn't hold this VAPID key; read info again")]
    UnknownVapidKey,
    #[error("server is on a different network")]
    WrongNetwork,
    #[error("server does not speak protocol v0")]
    UnsupportedVersion,
    /// Fetch the key configuration again from both sources and
    /// `check_key_config`.
    #[error("server's OHTTP key configuration changed")]
    KeyConfigChanged,
    /// The key-configuration sources disagreed for good (spec §3.2): no
    /// request is built until a check finds them in agreement. Tell the user.
    #[error("key configuration sources disagree; not using this server")]
    KeyConfigInconsistent,
    #[error("Tor transport needs a .onion server")]
    OnionOnly,
    /// The lease breaks a rule of spec §4.2 (`reason` says which).
    #[error("invalid lease: {reason}")]
    Lease { reason: String },
    /// The device registration breaks a rule of spec §4.1.
    #[error("invalid registration: {reason}")]
    Registration { reason: String },
    #[error("server error {status} ({problem})")]
    Server { status: u16, problem: String },

    /// The two key-configuration copies differ (spec §3.2).
    #[error("the key configuration sources disagree")]
    KeyConfigMismatch,
    #[error("not a valid OHTTP key configuration")]
    KeyConfigInvalid,
    #[error("not an OHTTP client")]
    NotOhttp,

    #[error("no randomness available")]
    Random,
    #[error("invalid push key")]
    PushKey,
    /// Altered, truncated, for another device, or not a Lantern Zero ping.
    #[error("cannot decrypt this push")]
    PushDecrypt,
    #[error("not a valid ping")]
    Ping,

    #[error("not a valid connection URL")]
    InvalidUrl,
    #[error("not a valid account token")]
    InvalidToken,
    #[error("saved client state is not valid")]
    InvalidState,
    /// A `Pending` was finished twice, or with the wrong `finish_*` call.
    #[error("this pending request was already finished, or belongs to another call")]
    WrongPending,
}

impl From<lz_client::Error> for LzError {
    fn from(e: lz_client::Error) -> Self {
        use lz_client::Error as E;
        match e {
            E::TooLarge => Self::TooLarge,
            E::Relay(status) => Self::Relay { status },
            E::KeyConfigRejected => Self::KeyConfigRejected,
            E::Transport => Self::Transport,
            E::Malformed => Self::Malformed,
            E::StaleSeq => Self::StaleSeq,
            E::ClockCorrected => Self::ClockCorrected,
            E::UnknownDevice => Self::UnknownDevice,
            E::NotRegistered => Self::NotRegistered,
            E::NoCursor => Self::NoCursor,
            E::RateLimited { retry_after_secs } => Self::RateLimited { retry_after_secs },
            E::Unauthorized => Self::Unauthorized,
            E::ScanningUnavailable => Self::ScanningUnavailable,
            E::ScanningNotIncluded => Self::ScanningNotIncluded,
            E::SpendAlertsUnavailable => Self::SpendAlertsUnavailable,
            E::TooManyDevices => Self::TooManyDevices,
            E::UnknownVapidKey => Self::UnknownVapidKey,
            E::WrongNetwork => Self::WrongNetwork,
            E::UnsupportedVersion => Self::UnsupportedVersion,
            E::KeyConfigChanged => Self::KeyConfigChanged,
            E::KeyConfigInconsistent => Self::KeyConfigInconsistent,
            E::OnionOnly => Self::OnionOnly,
            E::Lease(l) => Self::Lease {
                reason: l.to_string(),
            },
            E::Registration(r) => Self::Registration {
                reason: r.to_string(),
            },
            E::Server { status, problem } => Self::Server { status, problem },
        }
    }
}

impl From<lz_client::KeyConfigError> for LzError {
    fn from(e: lz_client::KeyConfigError) -> Self {
        use lz_client::KeyConfigError as K;
        match e {
            K::Mismatch => Self::KeyConfigMismatch,
            K::Invalid => Self::KeyConfigInvalid,
            K::NotOhttp => Self::NotOhttp,
        }
    }
}

impl From<lz_client::PushError> for LzError {
    fn from(e: lz_client::PushError) -> Self {
        use lz_client::PushError as P;
        match e {
            P::Random => Self::Random,
            P::Key => Self::PushKey,
            P::Decrypt => Self::PushDecrypt,
            P::Ping => Self::Ping,
        }
    }
}

// ----------------------------------------------------------------- types

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Network {
    Main,
    Test,
    Regtest,
}

impl From<Network> for plz::Network {
    fn from(n: Network) -> Self {
        match n {
            Network::Main => Self::Main,
            Network::Test => Self::Test,
            Network::Regtest => Self::Regtest,
        }
    }
}

impl From<plz::Network> for Network {
    fn from(n: plz::Network) -> Self {
        match n {
            plz::Network::Main => Self::Main,
            plz::Network::Test => Self::Test,
            plz::Network::Regtest => Self::Regtest,
        }
    }
}

/// One request header.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// A request for the app to send. Over OHTTP, POST `body` to one of the
/// vendor's relays, which forwards it to `url` (the server's gateway);
/// rotate among relays (spec §1.1). Over Tor, send it to `url` as is.
///
/// Over Tor the headers carry the account token, and bodies may carry
/// viewing keys: don't log any of it.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

impl std::fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// What came back, as the app received it.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct HttpResponse {
    pub status: u16,
    /// The `Retry-After` header. Only used over Tor.
    pub retry_after: Option<String>,
    /// The `Date` header. Only used over Tor.
    pub date: Option<String>,
    pub body: Vec<u8>,
}

impl std::fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

impl HttpResponse {
    fn core(&self) -> lz_client::HttpResponse<'_> {
        lz_client::HttpResponse {
            status: self.status,
            retry_after: self.retry_after.as_deref(),
            date: self.date.as_deref(),
            body: &self.body,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AlertMode {
    /// An extra push as soon as a payment is seen; Apple or Google see when.
    Instant,
    /// Alerts ride inside the next scheduled ping (spec §5.2).
    Private,
}

/// The `lease` of a `wake` (spec §4.2). Only with the user's consent
/// (spec §6.3). Send it again on every wake while scanning.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct Lease {
    /// 1 to 4 unified incoming viewing keys (`uivk…`), all for one account.
    /// Full viewing keys only with `spend_alerts`.
    pub keys: Vec<String>,
    pub from_height: u64,
    pub duration_secs: u64,
    pub spend_alerts: bool,
    pub alert_mode: AlertMode,
}

impl std::fmt::Debug for Lease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lease")
            .field("keys", &self.keys.len())
            .field("from_height", &self.from_height)
            .finish_non_exhaustive()
    }
}

impl From<Lease> for plz::LeaseRequest {
    fn from(l: Lease) -> Self {
        Self {
            keys: l.keys.into_iter().map(plz::ViewingKey::new).collect(),
            from_height: l.from_height,
            duration_secs: l.duration_secs,
            spend_alerts: l.spend_alerts,
            alert_mode: match l.alert_mode {
                AlertMode::Instant => plz::AlertMode::Instant,
                AlertMode::Private => plz::AlertMode::Private,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum EventKind {
    Received,
    Spent,
    /// Added by a later version.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum EventStatus {
    Mempool,
    Mined,
    Reorged,
    /// Added by a later version.
    Unknown,
}

/// A matched transaction (spec §4.3). It is a claim by the server: show
/// it as incoming and unconfirmed until the user's own wallet finds it in
/// a block (spec §6.3).
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct Event {
    pub id: String,
    pub rev: u32,
    pub kind: EventKind,
    pub status: EventStatus,
    pub height: Option<u64>,
    pub confirmations: u32,
    /// `CompactTx` protobuf bytes, base64url, to trial-decrypt on the
    /// device. Absent in pings.
    pub compact_tx: Option<String>,
}

impl std::fmt::Debug for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Event")
            .field("rev", &self.rev)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl From<proto::Event> for Event {
    fn from(e: proto::Event) -> Self {
        Self {
            id: e.id,
            rev: e.rev,
            kind: match e.kind {
                proto::EventKind::Received => EventKind::Received,
                proto::EventKind::Spent => EventKind::Spent,
                proto::EventKind::Unknown => EventKind::Unknown,
            },
            status: match e.status {
                proto::EventStatus::Mempool => EventStatus::Mempool,
                proto::EventStatus::Mined => EventStatus::Mined,
                proto::EventStatus::Reorged => EventStatus::Reorged,
                proto::EventStatus::Unknown => EventStatus::Unknown,
            },
            height: e.height,
            confirmations: e.confirmations,
            compact_tx: e.compact_tx,
        }
    }
}

/// A half-open height range `[start, end)`. Use it only to reorder the
/// normal sync (spec §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct Hint {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct InfoOutcome {
    pub network: Network,
    pub wake_interval_secs: u32,
    pub finality_depth: u32,
    pub vapid_public_key: String,
    /// Days without a request before the server may delete the account.
    pub idle_account_days: Option<u32>,
    /// The server rotated its VAPID key: subscribe at the gateway with
    /// `vapid_public_key`, register, then `unregister_device` the old one.
    pub vapid_key_changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WakeOutcome {
    /// The server's chain tip, or 0 while it has none.
    pub tip: u64,
    pub lease_active: bool,
    /// RFC 3339, UTC, while a lease is active.
    pub lease_expires_at: Option<String>,
    pub hints: Vec<Hint>,
    /// New or changed since this client last saw them.
    pub events: Vec<Event>,
    /// More events are waiting: the next `poll` fetches them at once.
    pub more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PollOutcome {
    pub events: Vec<Event>,
    pub more: bool,
}

/// What `check_key_config` decided (see `lz_client::KeyCheck`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum KeyCheck {
    /// Both sources agree, and that configuration is now in use.
    /// `changed`: it replaced another; cache the bytes you passed in, for
    /// `Client::new_ohttp` next launch. `recovered`: tell the user it has
    /// cleared.
    Agreed { changed: bool, recovered: bool },
    /// They differ, but one matches the configuration in use. Fetch both
    /// again by `check_again_at_ms`.
    Kept { check_again_at_ms: u64 },
}

/// The `keys` of a device registration (spec §4.1).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PushKeys {
    pub p256dh: String,
    pub auth: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PingType {
    /// A scheduled wake: send one `wake`.
    Wake,
    /// An instant payment alert. Show a local alert and send nothing
    /// (spec §3.3); details come at the next scheduled wake.
    Payment,
    /// Added by a later version: ignore it.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Ping {
    pub ping_type: PingType,
    /// Empty except under `private` alerts and in payment pushes.
    pub events: Vec<Event>,
}

impl From<proto::Ping> for Ping {
    fn from(p: proto::Ping) -> Self {
        Self {
            ping_type: match p.t {
                proto::PingType::Wake => PingType::Wake,
                proto::PingType::Payment => PingType::Payment,
                proto::PingType::Unknown => PingType::Unknown,
            },
            events: p.events.into_iter().map(Event::from).collect(),
        }
    }
}

/// A parsed connection URL, for checking a pasted one and showing it
/// masked (spec §2). Never shows the token.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ConnectionInfo {
    pub base_url: String,
    pub host: String,
    /// `.onion` servers are reached over Tor, not OHTTP.
    pub onion: bool,
    /// The URL with all but the last four characters of the token hidden.
    pub masked: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ViewingKeyKind {
    /// `uivk…`: incoming payments only.
    Incoming,
    /// `uview…`: spends too. Only for spend alerts.
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct ViewingKeyInfo {
    pub kind: ViewingKeyKind,
    pub network: Network,
}

/// A new account token for in-app sign-up (spec §2.3): send only
/// `hash_hex` to the issuer, through OHTTP or Tor; keep `token` on the
/// device and build the connection URL with `connection_url`.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct NewToken {
    pub token: String,
    pub hash_hex: String,
}

impl std::fmt::Debug for NewToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NewToken(<redacted>)")
    }
}

// --------------------------------------------------------- free functions

/// Checks a connection URL (spec §2) without connecting.
#[uniffi::export]
pub fn parse_connection_url(url: String) -> Result<ConnectionInfo, LzError> {
    let url = Zeroizing::new(url);
    let parsed = lz_proto::url::ConnectionUrl::parse(&url).map_err(|_| LzError::InvalidUrl)?;
    Ok(ConnectionInfo {
        masked: parsed.masked(),
        base_url: parsed.base_url,
        host: parsed.host,
        onion: parsed.onion,
    })
}

/// The kind and network of a unified viewing key, from its prefix only.
/// `None` if it isn't one. A client that isn't a wallet keeps only
/// incoming viewing keys (spec §6.3).
#[uniffi::export]
pub fn classify_viewing_key(key: String) -> Option<ViewingKeyInfo> {
    let key = plz::ViewingKey::new(key);
    key.classify().map(|(kind, network)| ViewingKeyInfo {
        kind: match kind {
            plz::KeyKind::Incoming => ViewingKeyKind::Incoming,
            plz::KeyKind::Full => ViewingKeyKind::Full,
        },
        network: network.into(),
    })
}

/// A fresh account token, generated on the device (spec §2.3).
#[uniffi::export]
pub fn generate_account_token() -> Result<NewToken, LzError> {
    let token = lz_proto::token::AccountToken::generate().map_err(|_| LzError::Random)?;
    Ok(NewToken {
        hash_hex: token.hash().to_hex(),
        token: token.encode().to_string(),
    })
}

/// The connection URL for `token` on the server at `base_url` (an `https`
/// URL, or `http` for a `.onion` host).
#[uniffi::export]
pub fn connection_url(base_url: String, token: String) -> Result<String, LzError> {
    let token = Zeroizing::new(token);
    lz_proto::token::AccountToken::parse(&token).map_err(|_| LzError::InvalidToken)?;
    let rest = base_url
        .strip_prefix("https://")
        .or_else(|| base_url.strip_prefix("http://"))
        .ok_or(LzError::InvalidUrl)?;
    let url = Zeroizing::new(format!(
        "lanternzero://{}#{}",
        rest.trim_end_matches('/'),
        &*token
    ));
    let parsed = lz_proto::url::ConnectionUrl::parse(&url).map_err(|_| LzError::InvalidUrl)?;
    // `.onion` hosts take `http://`; others only `https://`.
    if parsed.onion != base_url.starts_with("http://") {
        return Err(LzError::InvalidUrl);
    }
    Ok(url.to_string())
}

// ------------------------------------------------------------ push keys

/// The device's RFC 8291 key pair and auth secret (spec §4.1, §5). Keep
/// `secret_bytes` and `auth_bytes` in the keychain, shared with the
/// notification extension that opens pings.
#[derive(uniffi::Object)]
pub struct PushReceiver(lz_client::PushReceiver);

impl std::fmt::Debug for PushReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PushReceiver(<redacted>)")
    }
}

#[uniffi::export]
impl PushReceiver {
    #[uniffi::constructor]
    pub fn generate() -> Result<Self, LzError> {
        Ok(Self(lz_client::PushReceiver::generate()?))
    }

    /// Restores a receiver from the 32-byte secret and 16-byte auth secret.
    #[uniffi::constructor]
    pub fn from_bytes(secret: Vec<u8>, auth: Vec<u8>) -> Result<Self, LzError> {
        let secret = Zeroizing::new(secret);
        let auth = Zeroizing::new(auth);
        let s: &[u8; 32] = secret.as_slice().try_into().map_err(|_| LzError::PushKey)?;
        let a: &[u8; 16] = auth.as_slice().try_into().map_err(|_| LzError::PushKey)?;
        Ok(Self(lz_client::PushReceiver::from_bytes(s, a)?))
    }

    pub fn secret_bytes(&self) -> Vec<u8> {
        self.0.secret_bytes().to_vec()
    }

    pub fn auth_bytes(&self) -> Vec<u8> {
        self.0.auth_bytes().to_vec()
    }

    pub fn push_keys(&self) -> PushKeys {
        let k = self.0.push_keys();
        PushKeys {
            p256dh: k.p256dh,
            auth: k.auth,
        }
    }

    /// Opens a ping: the raw `aes128gcm` message.
    pub fn open_ping(&self, message: Vec<u8>) -> Result<Ping, LzError> {
        Ok(self.0.open_ping(&message)?.into())
    }

    /// Opens a ping from the base64url `lz` field of the platform payload
    /// (as the reference gateway sends it).
    pub fn open_ping_b64(&self, lz: String) -> Result<Ping, LzError> {
        Ok(self.0.open_ping_b64(&lz)?.into())
    }
}

// ---------------------------------------------------------------- client

enum Inner {
    Info(lz_client::PendingInfo),
    Register(lz_client::PendingRegister),
    Unregister(lz_client::PendingUnregister),
    Wake(lz_client::PendingWake),
    Poll(lz_client::PendingEvents),
    Rotate(lz_client::PendingRotate),
    DeleteAccount(lz_client::PendingDeleteAccount),
}

impl Inner {
    fn request(&self) -> &lz_client::HttpRequest {
        match self {
            Self::Info(p) => p.request(),
            Self::Register(p) => p.request(),
            Self::Unregister(p) => p.request(),
            Self::Wake(p) => p.request(),
            Self::Poll(p) => p.request(),
            Self::Rotate(p) => p.request(),
            Self::DeleteAccount(p) => p.request(),
        }
    }
}

/// A request in flight. Send `request()`, then pass the response to the
/// matching `finish_*` call, once. The request is held only inside the
/// core, which wipes it when the `Pending` is finished or dropped.
#[derive(uniffi::Object)]
pub struct Pending(Mutex<Option<Inner>>);

impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pending(..)")
    }
}

impl Pending {
    fn new(inner: Inner) -> Self {
        Self(Mutex::new(Some(inner)))
    }
}

#[uniffi::export]
impl Pending {
    /// What the app sends: a fresh copy each call, so the app can drop it
    /// once sent. `WrongPending` once the `Pending` is finished.
    pub fn request(&self) -> Result<HttpRequest, LzError> {
        let guard = lock(&self.0);
        let r = guard.as_ref().ok_or(LzError::WrongPending)?.request();
        Ok(HttpRequest {
            method: r.method.to_owned(),
            url: r.url.clone(),
            headers: r
                .headers
                .iter()
                .map(|(n, v)| Header {
                    name: (*n).to_owned(),
                    value: v.clone(),
                })
                .collect(),
            body: r.body.clone(),
        })
    }

    /// For a token rotation: the connection URL with the new token. Store
    /// it in the keychain before sending (spec §4.6).
    pub fn new_connection_url(&self) -> Option<String> {
        match &*lock(&self.0) {
            Some(Inner::Rotate(p)) => Some(p.new_connection_url().to_string()),
            _ => None,
        }
    }
}

/// A poisoned lock means an earlier call panicked, which UniFFI reports to
/// the app as an error. Keep serving rather than failing every later call:
/// the worst case is a stale cursor or `seq`, which the protocol recovers
/// from (spec §3.4, §4.3).
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// One server connection (`lz_client::Client`). Persist `state()` after
/// every call; keep the connection URL in the keychain.
#[derive(uniffi::Object)]
pub struct Client(Mutex<lz_client::Client>);

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Client(..)")
    }
}

fn restore(state: Option<String>) -> Result<lz_client::ClientState, LzError> {
    match state {
        None => Ok(lz_client::ClientState::default()),
        Some(s) => serde_json::from_str(&s).map_err(|_| LzError::InvalidState),
    }
}

fn parse_url(url: String) -> Result<lz_proto::url::ConnectionUrl, LzError> {
    let url = Zeroizing::new(url);
    lz_proto::url::ConnectionUrl::parse(&url).map_err(|_| LzError::InvalidUrl)
}

/// Takes the `Pending` if it is the right kind; the wrong `finish_*`
/// call leaves it as it was.
macro_rules! finish {
    ($self:ident, $pending:ident, $response:ident, $variant:ident, $method:ident) => {{
        let p = {
            let mut slot = lock(&$pending.0);
            match slot.take() {
                Some(Inner::$variant(p)) => p,
                other => {
                    *slot = other;
                    return Err(LzError::WrongPending);
                }
            }
        };
        lock(&$self.0).$method(p, $response.core())?
    }};
}

#[uniffi::export]
impl Client {
    /// A client that reaches the server through OHTTP relays. `key_config`
    /// is the `application/ohttp-keys` configuration, checked against a
    /// second source (spec §3.2) or from the app's cache. `state` is the
    /// JSON from `state()`, or `None` the first time.
    #[uniffi::constructor]
    pub fn new_ohttp(
        connection_url: String,
        network: Network,
        key_config: Vec<u8>,
        state: Option<String>,
    ) -> Result<Self, LzError> {
        let config = lz_client::KeyConfig::from_cache(&key_config)?;
        let client = lz_client::Client::new(
            parse_url(connection_url)?,
            network.into(),
            lz_client::Transport::Ohttp(config),
            restore(state)?,
        )?;
        Ok(Self(Mutex::new(client)))
    }

    /// A client for a self-hosted `.onion` server, reached over Tor.
    #[uniffi::constructor]
    pub fn new_onion(
        connection_url: String,
        network: Network,
        state: Option<String>,
    ) -> Result<Self, LzError> {
        let client = lz_client::Client::new(
            parse_url(connection_url)?,
            network.into(),
            lz_client::Transport::Onion,
            restore(state)?,
        )?;
        Ok(Self(Mutex::new(client)))
    }

    /// What to persist after every call (no secrets), as JSON.
    pub fn state(&self) -> String {
        // Plain strings, numbers, and booleans: serializing can't fail.
        serde_json::to_string(lock(&self.0).state()).expect("ClientState serializes")
    }

    /// The connection, for showing it masked.
    pub fn connection(&self) -> ConnectionInfo {
        let c = lock(&self.0);
        let url = c.connection();
        ConnectionInfo {
            base_url: url.base_url.clone(),
            host: url.host.clone(),
            onion: url.onion,
            masked: url.masked(),
        }
    }

    /// This device's id at the server, once registered.
    pub fn device_id(&self) -> Option<String> {
        lock(&self.0).state().device_id.clone()
    }

    /// Checks the key configuration as fetched again from two sources
    /// that hide the device's IP address (spec §3.2). Call at least daily,
    /// on `KeyConfigChanged`, and on `KeyConfigRejected`.
    pub fn check_key_config(
        &self,
        now_unix_ms: u64,
        first: Vec<u8>,
        second: Vec<u8>,
    ) -> Result<KeyCheck, LzError> {
        Ok(
            match lock(&self.0).check_key_config(now_unix_ms, &first, &second)? {
                lz_client::KeyCheck::Agreed { changed, recovered } => {
                    KeyCheck::Agreed { changed, recovered }
                }
                lz_client::KeyCheck::Kept { check_again_at_ms } => {
                    KeyCheck::Kept { check_again_at_ms }
                }
            },
        )
    }

    /// Queues an acknowledgement for the next `wake` or `poll`. Only
    /// `Mined` events are acknowledged; returns whether it was queued.
    pub fn ack(&self, event: Event) -> bool {
        let e = proto::Event {
            id: event.id,
            rev: event.rev,
            kind: match event.kind {
                EventKind::Received => proto::EventKind::Received,
                EventKind::Spent => proto::EventKind::Spent,
                EventKind::Unknown => proto::EventKind::Unknown,
            },
            status: match event.status {
                EventStatus::Mempool => proto::EventStatus::Mempool,
                EventStatus::Mined => proto::EventStatus::Mined,
                EventStatus::Reorged => proto::EventStatus::Reorged,
                EventStatus::Unknown => proto::EventStatus::Unknown,
            },
            height: event.height,
            confirmations: event.confirmations,
            compact_tx: None,
        };
        lock(&self.0).ack(&e)
    }

    /// `POST /v0/info` (spec §4.7).
    pub fn info(&self, now_unix_ms: u64) -> Result<Pending, LzError> {
        let p = lock(&self.0).info(now_unix_ms)?;
        Ok(Pending::new(Inner::Info(p)))
    }

    pub fn finish_info(
        &self,
        pending: &Pending,
        response: HttpResponse,
    ) -> Result<InfoOutcome, LzError> {
        let out = finish!(self, pending, response, Info, finish_info);
        Ok(InfoOutcome {
            network: out.info.network.into(),
            wake_interval_secs: out.info.wake_interval_secs,
            finality_depth: out.info.finality_depth,
            vapid_public_key: out.info.vapid_public_key,
            idle_account_days: out.info.idle_account_days,
            vapid_key_changed: out.vapid_key_changed,
        })
    }

    /// `POST /v0/devices` (spec §4.1) with an endpoint from the vendor's
    /// gateway, bound to the VAPID key `info` last reported. Call `info`
    /// first.
    pub fn register(
        &self,
        now_unix_ms: u64,
        endpoint: String,
        keys: PushKeys,
    ) -> Result<Pending, LzError> {
        let keys = proto::PushKeys {
            p256dh: keys.p256dh,
            auth: keys.auth,
        };
        let p = lock(&self.0).register(now_unix_ms, &endpoint, keys)?;
        Ok(Pending::new(Inner::Register(p)))
    }

    /// Returns the new device id.
    pub fn finish_register(
        &self,
        pending: &Pending,
        response: HttpResponse,
    ) -> Result<String, LzError> {
        Ok(finish!(self, pending, response, Register, finish_register))
    }

    /// Deletes this device's record (spec §4.1). When the user removes the
    /// server, also revoke the gateway subscription.
    pub fn unregister(&self, now_unix_ms: u64) -> Result<Pending, LzError> {
        let p = lock(&self.0).unregister(now_unix_ms)?;
        Ok(Pending::new(Inner::Unregister(p)))
    }

    /// Deletes another device record of this account, such as the old one
    /// after a VAPID key rotation (spec §5.3).
    pub fn unregister_device(
        &self,
        now_unix_ms: u64,
        device_id: String,
    ) -> Result<Pending, LzError> {
        let p = lock(&self.0).unregister_device(now_unix_ms, &device_id)?;
        Ok(Pending::new(Inner::Unregister(p)))
    }

    pub fn finish_unregister(
        &self,
        pending: &Pending,
        response: HttpResponse,
    ) -> Result<(), LzError> {
        finish!(self, pending, response, Unregister, finish_unregister);
        Ok(())
    }

    /// `POST /v0/wake` (spec §4.2): exactly one per scheduled wake, never
    /// because of a payment push (spec §3.3). `lease: None` is default mode.
    pub fn wake(&self, now_unix_ms: u64, lease: Option<Lease>) -> Result<Pending, LzError> {
        let p = lock(&self.0).wake(now_unix_ms, lease.map(Into::into))?;
        Ok(Pending::new(Inner::Wake(p)))
    }

    pub fn finish_wake(
        &self,
        pending: &Pending,
        response: HttpResponse,
    ) -> Result<WakeOutcome, LzError> {
        let out = finish!(self, pending, response, Wake, finish_wake);
        Ok(WakeOutcome {
            tip: out.tip,
            lease_active: out.lease.active,
            lease_expires_at: out.lease.expires_at,
            hints: out
                .hints
                .into_iter()
                .map(|h| Hint {
                    start: h.start,
                    end: h.end,
                })
                .collect(),
            events: out.events.into_iter().map(Event::from).collect(),
            more: out.more,
        })
    }

    /// `POST /v0/events` (spec §4.3): call in a loop while the app is in
    /// the foreground, in both modes. The HTTP timeout must exceed
    /// `long_poll_wait_secs()` plus a few seconds.
    pub fn poll(&self, now_unix_ms: u64) -> Result<Pending, LzError> {
        let p = lock(&self.0).poll(now_unix_ms)?;
        Ok(Pending::new(Inner::Poll(p)))
    }

    pub fn finish_poll(
        &self,
        pending: &Pending,
        response: HttpResponse,
    ) -> Result<PollOutcome, LzError> {
        let out = finish!(self, pending, response, Poll, finish_poll);
        Ok(PollOutcome {
            events: out.events.into_iter().map(Event::from).collect(),
            more: out.more,
        })
    }

    /// `POST /v0/token/rotate` (spec §4.6) to `new_token`, from
    /// `generate_account_token`. Store `Pending::new_connection_url` in the
    /// keychain before sending. After a lost response or an error such as
    /// `StaleSeq`, call this again with the same token: the old one keeps
    /// working until the new one is first used, or for 24 hours.
    pub fn rotate_token(&self, now_unix_ms: u64, new_token: String) -> Result<Pending, LzError> {
        let text = Zeroizing::new(new_token);
        let token =
            lz_proto::token::AccountToken::parse(&text).map_err(|_| LzError::InvalidToken)?;
        let p = lock(&self.0).rotate_token(now_unix_ms, &token)?;
        Ok(Pending::new(Inner::Rotate(p)))
    }

    /// Switches to the new token and returns the new connection URL.
    pub fn finish_rotate(
        &self,
        pending: &Pending,
        response: HttpResponse,
    ) -> Result<String, LzError> {
        Ok(finish!(self, pending, response, Rotate, finish_rotate).to_string())
    }

    /// `DELETE /v0/account` (spec §4.6).
    pub fn delete_account(&self, now_unix_ms: u64) -> Result<Pending, LzError> {
        let p = lock(&self.0).delete_account(now_unix_ms)?;
        Ok(Pending::new(Inner::DeleteAccount(p)))
    }

    /// Clears the client. The app deletes the connection URL and revokes
    /// its gateway subscription.
    pub fn finish_delete_account(
        &self,
        pending: &Pending,
        response: HttpResponse,
    ) -> Result<(), LzError> {
        finish!(
            self,
            pending,
            response,
            DeleteAccount,
            finish_delete_account
        );
        Ok(())
    }
}

/// The long-poll's `wait`, in seconds (spec §4.3). The app's HTTP timeout
/// for `poll` must be longer than this plus a few seconds.
#[uniffi::export]
pub fn long_poll_wait_secs() -> u32 {
    lz_client::LONG_POLL_WAIT_SECS
}
