//! The issuer interface (`server/ISSUER.md`): how whoever issues accounts
//! (a sign-up site, a wallet company, a self-hoster's script) creates
//! them and gives them scanning time (spec §2.3, §4.6).
//!
//! HTTP/1.1 over a Unix socket, `<data_dir>/issuer.sock`, mode 0600 in the
//! 0700 data directory: only processes running as the server's user can
//! reach it. It is never served over TCP or through the OHTTP gateway, and
//! it is not part of the wire protocol.
//!
//! Deliberately narrow: no call lists accounts, reads token hashes back,
//! or shows activity days. An issuer reaches only accounts it created or
//! whose token hash it already holds.
//!
//! Nothing here logs request bodies, token hashes, account ids, or keys.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use lz_proto::token::TokenHash;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::api::{Problem, unix_secs};
use crate::store::{
    AccountId, CreateError, GrantError, MAX_GRANT_KEY_LEN, MAX_GRANT_SECS, account_hex,
    parse_account,
};

/// The socket's file name in `data_dir`.
pub const SOCKET_FILE: &str = "issuer.sock";
/// Most deleted ids in one `deletions` answer.
pub const DELETIONS_PAGE: usize = 1000;

pub fn socket_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SOCKET_FILE)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenHashBody {
    /// Lowercase hex SHA-256 of the token's text form (spec §2.2).
    token_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountBody {
    account: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddScanTime {
    account: String,
    secs: u64,
    key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeletionsBody {
    #[serde(default)]
    after: u64,
}

#[derive(Serialize)]
struct AccountAnswer {
    account: Option<String>,
}

#[derive(Serialize)]
struct UntilAnswer {
    /// Unix seconds.
    until: Option<u64>,
}

#[derive(Serialize)]
struct DeletionsAnswer {
    accounts: Vec<String>,
    next: u64,
}

/// The issuer router, served on the socket from [`bind`].
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/create", post(create))
        .route("/resolve", post(resolve))
        .route("/scan_until", post(scan_until))
        .route("/add_scan_time", post(add_scan_time))
        .route("/deletions", post(deletions))
        .route("/delete", post(delete))
        .with_state(state)
}

/// Binds `<data_dir>/issuer.sock` with mode 0600, for `axum::serve` with
/// [`router`]. A socket left by an earlier run is replaced; any other file
/// at that path is an error.
#[cfg(unix)]
pub fn bind(data_dir: &Path) -> std::io::Result<tokio::net::UnixListener> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    let path = socket_path(data_dir);
    match std::fs::symlink_metadata(&path) {
        Ok(m) if m.file_type().is_socket() => std::fs::remove_file(&path)?,
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{SOCKET_FILE} exists in data_dir and is not a socket"),
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    // Bound inside a fresh 0700 directory and moved into place only once
    // it is 0600, so nobody else can connect in between, even if data_dir
    // itself were more open than it should be. The name is short because
    // socket paths are limited to about 100 bytes.
    let mut raw = [0u8; 4];
    rand::fill(&mut raw);
    let staging = data_dir.join(format!(
        ".i{}",
        raw.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    crate::keys::create_private_dir(&staging)?;
    let result = (|| {
        let staged = staging.join(SOCKET_FILE);
        let listener = tokio::net::UnixListener::bind(&staged)?;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&staged, &path)?;
        Ok(listener)
    })();
    let _ = std::fs::remove_dir_all(&staging);
    result
}

fn parse<T: DeserializeOwned>(body: &Bytes) -> Result<T, Problem> {
    serde_json::from_slice(body).map_err(|_| Problem::bad_request("malformed JSON body"))
}

fn json<T: Serialize>(status: StatusCode, value: &T) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(value).expect("response serializes"),
    )
        .into_response()
}

fn token_hash(s: &str) -> Result<TokenHash, Problem> {
    TokenHash::from_hex(s).ok_or_else(|| Problem::bad_request("invalid token_hash"))
}

fn unknown_account() -> Problem {
    Problem::new(StatusCode::NOT_FOUND, "unknown-account", "no such account")
}

/// Parses an account id and checks it still exists.
fn live_account(state: &AppState, s: &str, now: u64) -> Result<AccountId, Problem> {
    let account = parse_account(s).ok_or_else(|| Problem::bad_request("invalid account"))?;
    if state.store.has_account_at(account, now) {
        Ok(account)
    } else {
        Err(unknown_account())
    }
}

fn now() -> u64 {
    unix_secs(std::time::SystemTime::now())
}

/// `create {token_hash}`: a new account, live at once.
async fn create(State(state): State<Arc<AppState>>, body: Bytes) -> Result<Response, Problem> {
    let req: TokenHashBody = parse(&body)?;
    let hash = token_hash(&req.token_hash)?;
    match state.store.create_account(&hash, now()) {
        Ok(account) => Ok(json(
            StatusCode::CREATED,
            &AccountAnswer {
                account: Some(account_hex(&account)),
            },
        )),
        Err(CreateError::Taken) => Err(Problem::new(
            StatusCode::CONFLICT,
            "hash-taken",
            "token hash already in use",
        )),
        Err(CreateError::Io(e)) => {
            tracing::error!(error = %e, "issuer: cannot create an account");
            Err(Problem::internal())
        }
    }
}

/// `resolve {token_hash}`: the account, or `null`. Neither retires a
/// rotated token nor counts as activity.
async fn resolve(State(state): State<Arc<AppState>>, body: Bytes) -> Result<Response, Problem> {
    let req: TokenHashBody = parse(&body)?;
    let hash = token_hash(&req.token_hash)?;
    let account = state.store.resolve_at(&hash, now());
    Ok(json(
        StatusCode::OK,
        &AccountAnswer {
            account: account.map(|a| account_hex(&a)),
        },
    ))
}

/// `scan_until {account}`: the scanning end time, or `null` if none is left.
async fn scan_until(State(state): State<Arc<AppState>>, body: Bytes) -> Result<Response, Problem> {
    let req: AccountBody = parse(&body)?;
    let now = now();
    let account = live_account(&state, &req.account, now)?;
    Ok(json(
        StatusCode::OK,
        &UntilAnswer {
            until: state.store.scan_until(account, now),
        },
    ))
}

/// `add_scan_time {account, secs, key}`: idempotent by `key` for 30 days.
async fn add_scan_time(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, Problem> {
    let req: AddScanTime = parse(&body)?;
    if req.secs == 0 || req.secs > MAX_GRANT_SECS {
        return Err(Problem::bad_request("secs out of range"));
    }
    if req.key.is_empty() || req.key.len() > MAX_GRANT_KEY_LEN {
        return Err(Problem::bad_request("key must be 1 to 128 bytes"));
    }
    let now = now();
    let account = live_account(&state, &req.account, now)?;
    match state.store.add_scan_time(account, req.secs, &req.key, now) {
        Ok(until) => Ok(json(StatusCode::OK, &UntilAnswer { until: Some(until) })),
        Err(GrantError::UnknownAccount) => Err(unknown_account()),
        Err(GrantError::KeyReused) => Err(Problem::new(
            StatusCode::CONFLICT,
            "key-reused",
            "this key was already used for another account",
        )),
        Err(GrantError::Io(e)) => {
            tracing::error!(error = %e, "issuer: cannot record scanning time");
            Err(Problem::internal())
        }
    }
}

/// `deletions {after}`: deleted account ids, oldest first, kept 30 days.
async fn deletions(State(state): State<Arc<AppState>>, body: Bytes) -> Result<Response, Problem> {
    let req: DeletionsBody = parse(&body)?;
    let (ids, next) = state.store.deletions(req.after, DELETIONS_PAGE);
    Ok(json(
        StatusCode::OK,
        &DeletionsAnswer {
            accounts: ids.iter().map(account_hex).collect(),
            next,
        },
    ))
}

/// `delete {account}`: as `DELETE /v0/account` (spec §4.6), for abuse
/// handling or refunds.
async fn delete(State(state): State<Arc<AppState>>, body: Bytes) -> Result<Response, Problem> {
    let req: AccountBody = parse(&body)?;
    let account = live_account(&state, &req.account, now())?;
    if let Err(e) = state.delete_account(account) {
        tracing::error!(error = %e, "issuer: cannot delete an account");
        return Err(Problem::internal());
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}
