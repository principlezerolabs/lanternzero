//! Connection URLs (spec §2).
//!
//! `lanternzero://<host>[:<port>][/<base-path>]#<account-token>`, or the same
//! with `https://` (for universal links and app links).
//!
//! Schemes are matched case-insensitively (RFC 3986 §3.1), because phone
//! keyboards often capitalize the first letter of a pasted URL.

use crate::token::{AccountToken, TokenError};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UrlError {
    #[error("URL must start with lanternzero:// or https://")]
    Scheme,
    #[error("URL is malformed")]
    Malformed,
    #[error("URL has no account token after `#`")]
    MissingToken,
    #[error("URL must not contain a user name, password, or query")]
    Extra,
    #[error(transparent)]
    Token(#[from] TokenError),
}

/// A parsed connection URL. `Debug` never shows the token.
#[derive(Debug)]
pub struct ConnectionUrl {
    /// `https://host[:port][/base-path]` (or `http://` for `.onion` hosts),
    /// with no trailing slash and no token.
    pub base_url: String,
    /// The host, used for the OHTTP gateway at the origin root (spec §3.1).
    pub host: String,
    /// True for `.onion` hosts, which use Tor instead of OHTTP (self-hosted
    /// servers only).
    pub onion: bool,
    pub token: AccountToken,
}

impl ConnectionUrl {
    pub fn parse(input: &str) -> Result<Self, UrlError> {
        let input = input.trim();
        let rest = strip_prefix_ignore_case(input, "lanternzero://")
            .or_else(|| strip_prefix_ignore_case(input, "https://"))
            .ok_or(UrlError::Scheme)?;
        let (before, token_text) = rest.split_once('#').ok_or(UrlError::MissingToken)?;
        if token_text.is_empty() {
            return Err(UrlError::MissingToken);
        }
        let token = AccountToken::parse(token_text)?;

        let parsed =
            ::url::Url::parse(&format!("https://{before}")).map_err(|_| UrlError::Malformed)?;
        if !parsed.username().is_empty() || parsed.password().is_some() || parsed.query().is_some()
        {
            return Err(UrlError::Extra);
        }
        let host = parsed
            .host_str()
            .ok_or(UrlError::Malformed)?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if host.is_empty() {
            return Err(UrlError::Malformed);
        }
        let onion = host.ends_with(".onion");
        // Onion services are already encrypted and authenticated by Tor, and
        // rarely have TLS certificates (spec §2).
        let mut base_url = format!("{}://{host}", if onion { "http" } else { "https" });
        if let Some(port) = parsed.port() {
            base_url.push_str(&format!(":{port}"));
        }
        base_url.push_str(parsed.path().trim_end_matches('/'));
        Ok(Self {
            base_url,
            host,
            onion,
            token,
        })
    }

    /// The URL to show the user, as the scheme form, with the token masked to
    /// its last four characters (spec §2).
    pub fn masked(&self) -> String {
        let text = self.token.encode();
        let tail = &text[text.len() - 4..];
        let rest = self.base_url.split_once("://").map_or("", |(_, r)| r);
        format!("lanternzero://{rest}#lzt_…{tail}")
    }
}

fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok() -> String {
        AccountToken::from_bytes([9; 32]).encode().to_string()
    }

    #[test]
    fn parses_scheme_and_https_forms() {
        for prefix in ["lanternzero://", "https://"] {
            let u = ConnectionUrl::parse(&format!("{prefix}LZ.Example.org:8443/lz/#{}", tok()))
                .unwrap();
            assert_eq!(u.base_url, "https://lz.example.org:8443/lz");
            assert_eq!(u.host, "lz.example.org");
            assert!(!u.onion);
        }
    }

    #[test]
    fn rejects_bad_urls() {
        assert_eq!(
            ConnectionUrl::parse("http://x.org#a").unwrap_err(),
            UrlError::Scheme
        );
        assert_eq!(
            ConnectionUrl::parse("lanternzero://x.org").unwrap_err(),
            UrlError::MissingToken
        );
        assert_eq!(
            ConnectionUrl::parse(&format!("lanternzero://u:p@x.org#{}", tok())).unwrap_err(),
            UrlError::Extra
        );
        assert_eq!(
            ConnectionUrl::parse(&format!("lanternzero://x.org/?a=b#{}", tok())).unwrap_err(),
            UrlError::Extra
        );
    }

    #[test]
    fn accepts_capitalized_schemes() {
        for prefix in ["Lanternzero://", "LANTERNZERO://", "HTTPS://"] {
            let u = ConnectionUrl::parse(&format!("{prefix}x.org#{}", tok())).unwrap();
            assert_eq!(u.base_url, "https://x.org");
        }
    }

    #[test]
    fn rejects_empty_host() {
        assert!(ConnectionUrl::parse(&format!("lanternzero://#{}", tok())).is_err());
        assert!(ConnectionUrl::parse(&format!("lanternzero://./#{}", tok())).is_err());
    }

    #[test]
    fn detects_onion_and_masks_token() {
        let u = ConnectionUrl::parse(&format!("lanternzero://abc.onion.#{}", tok())).unwrap();
        assert!(u.onion);
        assert_eq!(u.base_url, "http://abc.onion");
        assert!(u.masked().starts_with("lanternzero://abc.onion#lzt_…"));
        let masked = u.masked();
        assert!(!masked.contains(&tok()[4..40]));
        assert!(masked.ends_with(&tok()[48..]));
        assert!(!format!("{u:?}").contains(&tok()[4..]));
    }
}
