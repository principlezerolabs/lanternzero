//! Lantern Zero client core for wallets (spec v0).
//!
//! **No I/O.** Every call builds an [`HttpRequest`] for the app to send with
//! its own HTTP stack (URLSession, OkHttp), and a pending value that opens
//! the [`HttpResponse`] when it comes back:
//!
//! ```text
//! let pending = client.wake(now_ms, lease)?;   // build
//! let reply   = app_send(pending.request());   // the app's networking
//! let outcome = client.finish_wake(pending, reply)?;
//! ```
//!
//! Over OHTTP the app POSTs the request body to one of the vendor's relays
//! (rotating among them), which forwards it to the server's gateway at
//! `request.url`. Self-hosted `.onion` servers are reached over Tor
//! instead ([`Transport::Onion`]).
//!
//! What the core takes care of:
//! - padded, fixed-size requests, and refusing responses that aren't
//!   (invariant 4);
//! - the `Date` header and time-based `seq` values, with `stale-seq`
//!   recovery (spec §3.4);
//! - the long-poll cursor, `next` pages, and acknowledgements that ride on
//!   the next request (spec §4.2–4.4);
//! - only reporting events that are new or changed;
//! - the network, version, and key-configuration checks on `info`
//!   (spec §3.2, §4.7);
//! - decrypting pings on the device ([`PushReceiver`]).
//!
//! What stays with the app: storing the connection URL and the
//! [`PushReceiver`] secrets in the keychain, persisting [`ClientState`],
//! fetching the key configuration from sources that hide the device's IP
//! address (spec §3.2), scheduling (one
//! `wake` per wake; a long-poll while in the foreground), and consent
//! (spec §6.3).

mod client;
#[cfg(feature = "reqwest")]
pub mod http;
pub mod push;
pub mod transport;

pub use client::{
    Client, ClientState, InfoOutcome, LONG_POLL_WAIT_SECS, PendingDeleteAccount,
    PendingDeleteWebhook, PendingEvents, PendingInfo, PendingRegister, PendingRotate,
    PendingSetWebhook, PendingUnregister, PendingWake, PollOutcome, WakeOutcome,
};
pub use lz_proto;
pub use push::{PushError, PushReceiver};
pub use transport::{HttpRequest, HttpResponse, KeyConfig, KeyConfigError, Transport};

/// Why a request failed. Messages never include tokens, keys, or bodies.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// The request doesn't fit the fixed size (spec §3.3).
    #[error("request too large for the fixed size")]
    TooLarge,
    /// The relay, or the server's gateway, answered with this HTTP status
    /// without an encapsulated response. A relay may hide the reason
    /// (RFC 9458 §5.2), so if the key configuration was fetched more than
    /// an hour ago, fetch it again as for [`Error::KeyConfigRejected`]
    /// (spec §3.2).
    #[error("relay answered {0}")]
    Relay(u16),
    /// The server no longer accepts the OHTTP key configuration in use,
    /// for example a week after it rotated (spec §3.2). Fetch it again
    /// ([`KeyConfig::from_two_sources`]), [`Client::set_key_config`], and
    /// build the request again.
    #[error("the server no longer accepts this OHTTP key configuration")]
    KeyConfigRejected,
    /// The response couldn't be decrypted, wasn't the fixed size, or wasn't
    /// valid Binary HTTP.
    #[error("malformed or unauthentic response")]
    Transport,
    /// The response body wasn't what the API defines.
    #[error("unexpected response from the server")]
    Malformed,
    /// `seq` was already used or too old. The client has moved past
    /// `min_seq`: build the same request again and send it once more.
    #[error("stale seq; send the request again")]
    StaleSeq,
    /// The device's clock was more than 60 s off the server's (spec §3.4).
    /// The client has corrected for it from the server's answer: build the
    /// same request again and send it once more. Persist the
    /// [`ClientState`] so the correction survives a restart.
    #[error("device clock was off; corrected, send the request again")]
    ClockCorrected,
    /// The server no longer knows this device (for example, its gateway
    /// reported the subscription gone). Register again.
    #[error("unknown device; register again")]
    UnknownDevice,
    /// This call needs a registered device.
    #[error("no device registered")]
    NotRegistered,
    /// A long-poll needs the cursor from a `wake` first.
    #[error("no cursor yet; send a wake first")]
    NoCursor,
    #[error("rate limited")]
    RateLimited { retry_after_secs: Option<u64> },
    #[error("account token not accepted")]
    Unauthorized,
    #[error("this server does not offer scanning")]
    ScanningUnavailable,
    /// The server scans only for accounts with scanning time, and this one
    /// has none left (spec §4.2, §4.6). Send `lease: None` from now on and
    /// tell the user that scanning isn't part of their account.
    #[error("scanning is not part of this account")]
    ScanningNotIncluded,
    #[error("this server does not offer spend alerts")]
    SpendAlertsUnavailable,
    #[error("the account has the maximum number of devices")]
    TooManyDevices,
    /// The server no longer holds the VAPID key this registration named:
    /// read `info` again, subscribe at the gateway with the key it reports,
    /// and register that subscription (spec §4.1).
    #[error("the server doesn't hold this VAPID key; read info again")]
    UnknownVapidKey,
    /// The server is on a different network: refuse to connect (§4.7).
    #[error("server is on a different network")]
    WrongNetwork,
    #[error("server does not speak protocol v0")]
    UnsupportedVersion,
    /// `info` names a different OHTTP key configuration than the one in
    /// use: fetch it again ([`KeyConfig::from_two_sources`], spec §3.2).
    #[error("server's OHTTP key configuration changed")]
    KeyConfigChanged,
    /// [`Transport::Onion`] is only for `.onion` servers.
    #[error("Tor transport needs a .onion server")]
    OnionOnly,
    #[error(transparent)]
    Lease(#[from] lz_proto::lease::LeaseError),
    #[error(transparent)]
    Registration(#[from] lz_proto::api::RegistrationError),
    /// Any other problem response (spec §3.6).
    #[error("server error {status} ({problem})")]
    Server { status: u16, problem: String },
}
