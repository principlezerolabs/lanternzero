//! The v0 API calls (spec §4) as build/finish pairs.

use std::collections::HashMap;

use lz_proto::api::{
    DeviceRegistered, DeviceRegistration, Event, EventStatus, EventsRequest, EventsResponse, Hint,
    Info, LeaseStatus, PushKeys, SeqOnly, TokenRotate, WakeRequest, WakeResponse,
};
use lz_proto::lease::{LeaseRequest, Network};
use lz_proto::replay::next_seq;
use lz_proto::token::AccountToken;
use lz_proto::url::ConnectionUrl;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::Error;
use crate::transport::{self, HttpRequest, HttpResponse, Inner, KeyConfig, Opener, Transport};

/// The `wait` of a regular long-poll (spec §4.3: the server clamps to
/// 25–30 s). The app's HTTP timeout must be longer than this plus the
/// server's 2 s release jitter.
pub const LONG_POLL_WAIT_SECS: u32 = 25;
/// Acknowledgements queued at most; the server keeps at most 1024
/// unacknowledged events per account (spec §6.1).
const MAX_ACKS: usize = 1024;
/// Event states remembered for reporting only changes.
const MAX_SEEN: usize = 4096;
const PROBLEM_PREFIX: &str = "https://lanternzero.com/problems/";

/// What the app persists between launches. Holds no secrets: the token
/// stays in the connection URL, which belongs in the keychain.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientState {
    /// This device's id at the server, once registered.
    pub device_id: Option<String>,
    /// Where the long-poll resumes.
    pub cursor: Option<String>,
    /// The server's VAPID key, as last seen in `info`. The gateway
    /// subscription is bound to it (spec §4.1, §5.3).
    pub vapid_public_key: Option<String>,
    /// The last `seq` sent (spec §3.4).
    pub last_seq: Option<u64>,
}

/// One server connection.
pub struct Client {
    url: ConnectionUrl,
    network: Network,
    transport: Transport,
    state: ClientState,
    /// The last response said more events are waiting (`next`).
    more: bool,
    acks: Vec<String>,
    seen: HashMap<String, (u32, EventStatus, Option<u64>, u32)>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("base_url", &self.url.base_url)
            .field("network", &self.network)
            .field("registered", &self.state.device_id.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct Exchange {
    request: HttpRequest,
    opener: Opener,
}

macro_rules! pending {
    ($(#[$doc:meta])* $name:ident $({ $($field:ident: $ty:ty),* })?) => {
        $(#[$doc])*
        #[derive(Debug)]
        pub struct $name {
            ex: Exchange,
            $($($field: $ty),*)?
        }

        impl $name {
            /// What the app sends.
            pub fn request(&self) -> &HttpRequest {
                &self.ex.request
            }
        }
    };
}

pending!(
    /// An `info` request in flight.
    PendingInfo
);
pending!(
    /// A device registration in flight.
    PendingRegister
);
pending!(
    /// A device deletion in flight.
    PendingUnregister { device_id: String }
);
pending!(
    /// A token rotation in flight.
    PendingRotate { new_url: ConnectionUrl }
);
pending!(
    /// An account deletion in flight.
    PendingDeleteAccount
);
pending!(
    /// A `wake` in flight.
    PendingWake { acks: Vec<String> }
);
pending!(
    /// An `events` long-poll (or `next` page fetch) in flight.
    PendingEvents { acks: Vec<String> }
);

impl PendingRotate {
    /// The connection URL with the new token. Spec §4.6: store it (in the
    /// keychain) before sending, so a crash after the server accepts the
    /// rotation can't lose it.
    pub fn new_connection_url(&self) -> Zeroizing<String> {
        self.new_url.to_url()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoOutcome {
    pub info: Info,
    /// The server rotated its VAPID key: create a new gateway subscription
    /// bound to `info.vapid_public_key`, register it, then unregister the
    /// old device (spec §5.3).
    pub vapid_key_changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeOutcome {
    /// The server's chain tip, or 0 while it has none yet.
    pub tip: u64,
    pub lease: LeaseStatus,
    /// Heights to scan first, within the normal sync only (spec §6.3).
    pub hints: Vec<Hint>,
    /// Events that are new or changed since this client last saw them.
    pub events: Vec<Event>,
    /// More events are waiting: the next [`Client::poll`] fetches them at
    /// once.
    pub more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollOutcome {
    /// Events that are new or changed since this client last saw them.
    pub events: Vec<Event>,
    pub more: bool,
}

impl Client {
    /// `network` is the wallet's own; `info` must match it (spec §4.7).
    pub fn new(
        url: ConnectionUrl,
        network: Network,
        transport: Transport,
        state: ClientState,
    ) -> Result<Self, Error> {
        if matches!(transport, Transport::Onion) && !url.onion {
            return Err(Error::OnionOnly);
        }
        Ok(Self {
            url,
            network,
            transport,
            state,
            more: false,
            acks: Vec::new(),
            seen: HashMap::new(),
        })
    }

    /// What to persist after each call.
    pub fn state(&self) -> &ClientState {
        &self.state
    }

    /// The connection, for showing it masked (spec §2).
    pub fn connection(&self) -> &ConnectionUrl {
        &self.url
    }

    /// Replaces the key configuration after a new two-relay check.
    pub fn set_key_config(&mut self, config: KeyConfig) {
        if let Transport::Ohttp(c) = &mut self.transport {
            *c = config;
        }
    }

    /// Queues an acknowledgement for the next `wake` or poll. Only `mined`
    /// events are acknowledged (spec §4.4: one acknowledged in the mempool
    /// comes back when it is mined); returns whether it was queued.
    pub fn ack(&mut self, event: &Event) -> bool {
        if event.status != EventStatus::Mined {
            return false;
        }
        if !self.acks.contains(&event.id) {
            if self.acks.len() >= MAX_ACKS {
                return false;
            }
            self.acks.push(event.id.clone());
        }
        true
    }

    /// Acknowledgements not yet confirmed by a response.
    pub fn pending_acks(&self) -> usize {
        self.acks.len()
    }

    /// `POST /v0/info` (spec §4.7). No token.
    pub fn info(&mut self, now_unix_ms: u64) -> Result<PendingInfo, Error> {
        let ex = self.exchange("POST", "/v0/info", false, now_unix_ms, None)?;
        Ok(PendingInfo { ex })
    }

    /// Checks the network, the version, and the key configuration.
    pub fn finish_info(
        &mut self,
        pending: PendingInfo,
        response: HttpResponse<'_>,
    ) -> Result<InfoOutcome, Error> {
        let body = self.open(pending.ex, response, 200)?;
        let info: Info = serde_json::from_slice(&body).map_err(|_| Error::Malformed)?;
        if !info.versions.iter().any(|v| v == lz_proto::VERSION) {
            return Err(Error::UnsupportedVersion);
        }
        if info.network != self.network {
            return Err(Error::WrongNetwork);
        }
        if let Transport::Ohttp(config) = &self.transport
            && !info
                .ohttp_key_config_sha256
                .eq_ignore_ascii_case(config.sha256_hex())
        {
            return Err(Error::KeyConfigChanged);
        }
        let vapid_key_changed = self
            .state
            .vapid_public_key
            .as_ref()
            .is_some_and(|k| *k != info.vapid_public_key);
        self.state.vapid_public_key = Some(info.vapid_public_key.clone());
        Ok(InfoOutcome {
            info,
            vapid_key_changed,
        })
    }

    /// `POST /v0/devices` (spec §4.1) with an endpoint from the vendor's
    /// gateway, bound to this server's VAPID key as `info` last reported it
    /// ([`ClientState::vapid_public_key`]). The registration names that
    /// key, so a rotation in between can't strand the device; call
    /// [`info`](Self::info) first.
    pub fn register(
        &mut self,
        now_unix_ms: u64,
        endpoint: &str,
        keys: PushKeys,
    ) -> Result<PendingRegister, Error> {
        let reg = DeviceRegistration {
            seq: self.seq(now_unix_ms),
            endpoint: endpoint.to_owned(),
            keys,
            vapid_public_key: self.state.vapid_public_key.clone(),
        };
        reg.validate()?;
        let body = to_json(&reg)?;
        let ex = self.exchange("POST", "/v0/devices", true, now_unix_ms, Some(&body))?;
        Ok(PendingRegister { ex })
    }

    /// Returns the new device id, which [`ClientState`] now holds.
    pub fn finish_register(
        &mut self,
        pending: PendingRegister,
        response: HttpResponse<'_>,
    ) -> Result<String, Error> {
        let body = self.open(pending.ex, response, 201)?;
        let reg: DeviceRegistered = serde_json::from_slice(&body).map_err(|_| Error::Malformed)?;
        if !valid_device_id(&reg.device_id) {
            return Err(Error::Malformed);
        }
        self.forget_device();
        self.state.device_id = Some(reg.device_id.clone());
        Ok(reg.device_id)
    }

    /// `DELETE /v0/devices/{device_id}` (spec §4.1) for this device. When
    /// the user removes the server, the app also revokes the gateway
    /// subscription.
    pub fn unregister(&mut self, now_unix_ms: u64) -> Result<PendingUnregister, Error> {
        let device_id = self.device_id()?.to_owned();
        self.unregister_device(now_unix_ms, &device_id)
    }

    /// Deletes another device record of this account: the old one after
    /// moving to a new subscription, for example when `info` reports a new
    /// VAPID key (spec §5.3). Register the new one first, keeping the old
    /// [`ClientState::device_id`], then delete the old one with this.
    pub fn unregister_device(
        &mut self,
        now_unix_ms: u64,
        device_id: &str,
    ) -> Result<PendingUnregister, Error> {
        if !valid_device_id(device_id) {
            return Err(Error::NotRegistered);
        }
        let body = to_json(&SeqOnly {
            seq: self.seq(now_unix_ms),
        })?;
        let path = format!("/v0/devices/{device_id}");
        let ex = self.exchange("DELETE", &path, true, now_unix_ms, Some(&body))?;
        Ok(PendingUnregister {
            ex,
            device_id: device_id.to_owned(),
        })
    }

    /// Forgets this device if it was the one deleted.
    pub fn finish_unregister(
        &mut self,
        pending: PendingUnregister,
        response: HttpResponse<'_>,
    ) -> Result<(), Error> {
        self.open(pending.ex, response, 204)?;
        if self.state.device_id.as_deref() == Some(pending.device_id.as_str()) {
            self.forget_device();
        }
        Ok(())
    }

    /// `POST /v0/wake` (spec §4.2): exactly one per wake, in both modes.
    /// `lease: None` is default mode (and ends any lease). With a lease,
    /// the app has the user's consent (spec §6.3) and sends the keys again
    /// on every wake.
    pub fn wake(
        &mut self,
        now_unix_ms: u64,
        lease: Option<LeaseRequest>,
    ) -> Result<PendingWake, Error> {
        if let Some(l) = &lease {
            l.validate(self.network)?;
        }
        let mut req = WakeRequest {
            device_id: self.device_id()?.to_owned(),
            seq: self.seq(now_unix_ms),
            ack: self.acks.clone(),
            lease,
        };
        loop {
            let body = to_json(&req)?;
            match self.exchange("POST", "/v0/wake", true, now_unix_ms, Some(&body)) {
                Ok(ex) => {
                    return Ok(PendingWake {
                        ex,
                        acks: std::mem::take(&mut req.ack),
                    });
                }
                // The rest wait for the next request.
                Err(Error::TooLarge) if !req.ack.is_empty() => {
                    req.ack.truncate(req.ack.len() / 2);
                }
                Err(e) => return Err(e),
            }
        }
    }

    pub fn finish_wake(
        &mut self,
        pending: PendingWake,
        response: HttpResponse<'_>,
    ) -> Result<WakeOutcome, Error> {
        let body = self.open(pending.ex, response, 200)?;
        let resp: WakeResponse = serde_json::from_slice(&body).map_err(|_| Error::Malformed)?;
        self.acked(&pending.acks);
        self.state.cursor = Some(resp.cursor);
        self.more = resp.next.is_some();
        Ok(WakeOutcome {
            tip: resp.tip,
            lease: resp.lease,
            hints: resp.hints,
            events: self.fresh(resp.events),
            more: self.more,
        })
    }

    /// `POST /v0/events` (spec §4.3). A long-poll of
    /// [`LONG_POLL_WAIT_SECS`], or, when the last response said more events
    /// are waiting, a `wait: 0` fetch of that page. Call it in a loop while
    /// the app is in the foreground, in both modes.
    pub fn poll(&mut self, now_unix_ms: u64) -> Result<PendingEvents, Error> {
        let device_id = self.device_id()?.to_owned();
        let cursor = self.state.cursor.clone().ok_or(Error::NoCursor)?;
        let mut req = EventsRequest {
            device_id,
            seq: self.seq(now_unix_ms),
            cursor,
            wait: if self.more { 0 } else { LONG_POLL_WAIT_SECS },
            ack: self.acks.clone(),
        };
        loop {
            let body = to_json(&req)?;
            match self.exchange("POST", "/v0/events", true, now_unix_ms, Some(&body)) {
                Ok(ex) => {
                    return Ok(PendingEvents {
                        ex,
                        acks: std::mem::take(&mut req.ack),
                    });
                }
                Err(Error::TooLarge) if !req.ack.is_empty() => {
                    req.ack.truncate(req.ack.len() / 2);
                }
                Err(e) => return Err(e),
            }
        }
    }

    pub fn finish_poll(
        &mut self,
        pending: PendingEvents,
        response: HttpResponse<'_>,
    ) -> Result<PollOutcome, Error> {
        let body = self.open(pending.ex, response, 200)?;
        let resp: EventsResponse = serde_json::from_slice(&body).map_err(|_| Error::Malformed)?;
        self.acked(&pending.acks);
        self.state.cursor = Some(resp.cursor);
        self.more = resp.next.is_some();
        Ok(PollOutcome {
            events: self.fresh(resp.events),
            more: self.more,
        })
    }

    /// `POST /v0/token/rotate` (spec §4.6) to `new_token`, which the app
    /// generates with [`AccountToken::generate`] and stores first. After a
    /// lost response or an error such as [`Error::StaleSeq`], send again
    /// with the same token: the old one keeps working until the new one is
    /// first used, or for 24 hours.
    pub fn rotate_token(
        &mut self,
        now_unix_ms: u64,
        new_token: &AccountToken,
    ) -> Result<PendingRotate, Error> {
        // AccountToken isn't Clone; copy it through its text form.
        let new_token = AccountToken::parse(&new_token.encode()).map_err(|_| Error::Malformed)?;
        let body = to_json(&TokenRotate {
            seq: self.seq(now_unix_ms),
            new_token_hash: new_token.hash().to_hex(),
        })?;
        let ex = self.exchange("POST", "/v0/token/rotate", true, now_unix_ms, Some(&body))?;
        Ok(PendingRotate {
            ex,
            new_url: self.url.with_token(new_token),
        })
    }

    /// Switches to the new token and returns the new connection URL, to
    /// store and to show the user once.
    pub fn finish_rotate(
        &mut self,
        pending: PendingRotate,
        response: HttpResponse<'_>,
    ) -> Result<Zeroizing<String>, Error> {
        self.open(pending.ex, response, 204)?;
        let url = pending.new_url.to_url();
        self.url = pending.new_url;
        Ok(url)
    }

    /// `DELETE /v0/account` (spec §4.6): the server drops everything about
    /// the account at once.
    pub fn delete_account(&mut self, now_unix_ms: u64) -> Result<PendingDeleteAccount, Error> {
        let body = to_json(&SeqOnly {
            seq: self.seq(now_unix_ms),
        })?;
        let ex = self.exchange("DELETE", "/v0/account", true, now_unix_ms, Some(&body))?;
        Ok(PendingDeleteAccount { ex })
    }

    /// Clears this client's state; the token no longer works. The app
    /// deletes the connection URL and revokes its gateway subscription.
    pub fn finish_delete_account(
        &mut self,
        pending: PendingDeleteAccount,
        response: HttpResponse<'_>,
    ) -> Result<(), Error> {
        self.open(pending.ex, response, 204)?;
        self.state = ClientState {
            last_seq: self.state.last_seq,
            ..ClientState::default()
        };
        self.more = false;
        self.acks.clear();
        self.seen.clear();
        Ok(())
    }

    fn device_id(&self) -> Result<&str, Error> {
        self.state.device_id.as_deref().ok_or(Error::NotRegistered)
    }

    fn forget_device(&mut self) {
        self.state.device_id = None;
        self.state.cursor = None;
        self.more = false;
    }

    fn seq(&mut self, now_unix_ms: u64) -> u64 {
        let s = next_seq(self.state.last_seq, now_unix_ms);
        self.state.last_seq = Some(s);
        s
    }

    fn exchange(
        &self,
        method: &'static str,
        path: &str,
        auth: bool,
        now_unix_ms: u64,
        body: Option<&[u8]>,
    ) -> Result<Exchange, Error> {
        let (request, opener) = transport::build(
            &self.transport,
            &self.url.base_url,
            method,
            path,
            auth.then_some(&self.url.token),
            now_unix_ms,
            body,
        )?;
        Ok(Exchange { request, opener })
    }

    /// Opens the response; anything but `expect` becomes an [`Error`].
    fn open(
        &mut self,
        ex: Exchange,
        response: HttpResponse<'_>,
        expect: u16,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let inner = transport::open(ex.opener, response)?;
        if inner.status == expect {
            Ok(inner.body)
        } else {
            Err(self.problem(&inner))
        }
    }

    fn problem(&mut self, inner: &Inner) -> Error {
        #[derive(Deserialize)]
        struct Problem {
            #[serde(rename = "type", default)]
            kind: String,
            #[serde(default)]
            min_seq: Option<u64>,
        }
        let p: Option<Problem> = serde_json::from_slice(&inner.body).ok();
        let slug: String = p
            .as_ref()
            .and_then(|p| p.kind.strip_prefix(PROBLEM_PREFIX))
            .unwrap_or("")
            .chars()
            .take(64)
            .collect();
        match (inner.status, slug.as_str()) {
            (409, "stale-seq") => {
                // Move past the window, so the retry is accepted.
                if let Some(min) = p.and_then(|p| p.min_seq) {
                    let floor = min.saturating_sub(1);
                    let last = self.state.last_seq.map_or(floor, |l| l.max(floor));
                    self.state.last_seq = Some(last);
                }
                Error::StaleSeq
            }
            (404, "unknown-device") => {
                self.forget_device();
                Error::UnknownDevice
            }
            (409, "too-many-devices") => Error::TooManyDevices,
            (400, "unknown-vapid-key") => Error::UnknownVapidKey,
            (429, _) => Error::RateLimited {
                retry_after_secs: inner.retry_after,
            },
            (401, _) => Error::Unauthorized,
            (501, "scanning-unavailable") => Error::ScanningUnavailable,
            (403, "scanning-not-included") => Error::ScanningNotIncluded,
            (501, "spend-alerts-unavailable") => Error::SpendAlertsUnavailable,
            (status, _) => Error::Server {
                status,
                problem: slug,
            },
        }
    }

    /// The server deleted these events: forget them.
    fn acked(&mut self, sent: &[String]) {
        self.acks.retain(|a| !sent.contains(a));
        for id in sent {
            self.seen.remove(id);
        }
    }

    /// Only events that are new, or whose state changed. Every `wake`
    /// repeats the unacknowledged events; the app needn't see them twice.
    fn fresh(&mut self, events: Vec<Event>) -> Vec<Event> {
        events
            .into_iter()
            .filter(|e| {
                let state = (e.rev, e.status, e.height, e.confirmations);
                if self.seen.get(&e.id) == Some(&state) {
                    return false;
                }
                if self.seen.len() >= MAX_SEEN && !self.seen.contains_key(&e.id) {
                    self.seen.clear();
                }
                self.seen.insert(e.id.clone(), state);
                true
            })
            .collect()
    }
}

/// Device ids go into request paths: only short base64url-like text.
fn valid_device_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn to_json<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>, Error> {
    serde_json::to_vec(value)
        .map(Zeroizing::new)
        .map_err(|_| Error::Malformed)
}
