//! Problem types (RFC 9457) the server sends and wallets act on (spec §3.6).
//! Both ends use these constants, so a renamed type breaks the build
//! instead of a wallet's error handling.

/// The prefix of every Lantern Zero problem `type`.
pub const TYPE_PREFIX: &str = "https://lanternzero.com/problems/";

/// RFC 9458 §5.3's problem type for a key configuration the gateway
/// doesn't accept (spec §3.2). Sent unencapsulated.
pub const OHTTP_KEY_TYPE: &str = "https://iana.org/assignments/http-problem-types#ohttp-key";

pub const BAD_REQUEST: &str = "bad-request";
pub const BAD_DATE: &str = "bad-date";
pub const BAD_SIZE: &str = "bad-size";
pub const BAD_TARGET: &str = "bad-target";
pub const INTERNAL: &str = "internal";
pub const RATE_LIMITED: &str = "rate-limited";
pub const UNAUTHORIZED: &str = "unauthorized";
pub const UNKNOWN_DEVICE: &str = "unknown-device";
pub const TOO_MANY_DEVICES: &str = "too-many-devices";
pub const STALE_SEQ: &str = "stale-seq";
pub const UNKNOWN_VAPID_KEY: &str = "unknown-vapid-key";
pub const SCANNING_UNAVAILABLE: &str = "scanning-unavailable";
pub const SCANNING_NOT_INCLUDED: &str = "scanning-not-included";
pub const SPEND_ALERTS_UNAVAILABLE: &str = "spend-alerts-unavailable";

/// The full `type` URI for a slug.
pub fn type_uri(slug: &str) -> String {
    format!("{TYPE_PREFIX}{slug}")
}

/// The slug of a Lantern Zero problem `type`, if it is one.
pub fn slug(type_uri: &str) -> Option<&str> {
    type_uri.strip_prefix(TYPE_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_round_trip() {
        assert_eq!(
            type_uri(STALE_SEQ),
            "https://lanternzero.com/problems/stale-seq"
        );
        assert_eq!(slug(&type_uri(STALE_SEQ)), Some(STALE_SEQ));
        assert_eq!(slug(OHTTP_KEY_TYPE), None);
    }
}
