//! Gateway origins, taken from the request path.
//!
//! Clients address a gateway the way payjoin-mailroom expects:
//! `/<scheme>://<host>[:<port>]`, or a bare `/<host>[:<port>]` for `https`.
//! An origin is a scheme, a host, and a port, nothing else: no userinfo,
//! path, query, or percent-escapes.
//!
//! Which gateway a client uses says which server holds its account, so
//! [`Origin`]'s `Debug` doesn't print it, and the relay never logs it.

use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scheme {
    Https,
    /// Tests only (`allow_private_targets`).
    Http,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Origin {
    scheme: Scheme,
    /// Lowercase; IPv6 literals keep their brackets.
    host: String,
    port: u16,
}

impl std::fmt::Debug for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Origin(<redacted>)")
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OriginError {
    #[error("not a gateway origin")]
    Invalid,
    #[error("plain http gateways are for tests only")]
    Http,
}

impl Origin {
    /// Parses the request path without its leading `/`. `allow_http` is
    /// for tests.
    pub fn parse(s: &str, allow_http: bool) -> Result<Self, OriginError> {
        let (scheme, rest) = if let Some(rest) = strip_prefix_ignore_case(s, "https://") {
            (Scheme::Https, rest)
        } else if let Some(rest) = strip_prefix_ignore_case(s, "http://") {
            if !allow_http {
                return Err(OriginError::Http);
            }
            (Scheme::Http, rest)
        } else {
            (Scheme::Https, s)
        };
        // One trailing slash is fine; any other path is not.
        let authority = rest.strip_suffix('/').unwrap_or(rest);
        if authority.is_empty()
            || !authority
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
        {
            return Err(OriginError::Invalid);
        }
        let (host, port) = split_host_port(authority)?;
        let default_port = match scheme {
            Scheme::Https => 443,
            Scheme::Http => 80,
        };
        let port = match port {
            None => default_port,
            Some(p) => p.parse::<u16>().map_err(|_| OriginError::Invalid)?,
        };
        if port == 0 {
            return Err(OriginError::Invalid);
        }
        Ok(Self {
            scheme,
            host: canonical_host(host)?,
            port,
        })
    }

    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The host in canonical form and without brackets, as the allow and
    /// deny lists hold it.
    pub fn host(&self) -> &str {
        self.host.trim_start_matches('[').trim_end_matches(']')
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The host as an IP address, if it is a literal one.
    pub fn ip(&self) -> Option<IpAddr> {
        self.host().parse().ok()
    }

    fn base(&self) -> String {
        let scheme = match self.scheme {
            Scheme::Https => "https",
            Scheme::Http => "http",
        };
        format!("{scheme}://{}:{}", self.host, self.port)
    }

    /// The gateway resource (RFC 9540).
    pub fn gateway_url(&self) -> String {
        format!("{}/.well-known/ohttp-gateway", self.base())
    }

    /// Where the gateway lists the purposes it accepts relayed requests for.
    pub fn purposes_url(&self) -> String {
        format!("{}/.well-known/ohttp-gateway?allowed_purposes", self.base())
    }
}

/// The host as the HTTP client will read it. URLs are parsed by WHATWG
/// rules, which read `2130706433`, `0x7f.1`, and `0177.0.0.1` as IPv4
/// addresses (all `127.0.0.1`), and the client connects to a literal
/// address without asking the resolver. So every check uses this form:
/// the literal-address check sees the address the client will connect to.
pub(crate) fn canonical_host(host: &str) -> Result<String, OriginError> {
    let url = reqwest::Url::parse(&format!("https://{host}/")).map_err(|_| OriginError::Invalid)?;
    match url.host() {
        Some(url::Host::Domain(d)) => Ok(d.to_owned()),
        Some(url::Host::Ipv4(ip)) => Ok(ip.to_string()),
        Some(url::Host::Ipv6(ip)) => Ok(format!("[{ip}]")),
        None => Err(OriginError::Invalid),
    }
}

fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

/// Splits `host[:port]` or `[v6][:port]`, checking the host's syntax.
fn split_host_port(authority: &str) -> Result<(&str, Option<&str>), OriginError> {
    if authority.starts_with('[') {
        let close = authority.find(']').ok_or(OriginError::Invalid)?;
        let host = &authority[..=close];
        host[1..close]
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| OriginError::Invalid)?;
        return match &authority[close + 1..] {
            "" => Ok((host, None)),
            rest => match rest.strip_prefix(':') {
                Some(port) => Ok((host, Some(port))),
                None => Err(OriginError::Invalid),
            },
        };
    }
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    // A DNS name or an IPv4 literal: labels of letters, digits, and inner
    // hyphens. Odd IPv4 spellings (`0x7f.1`, `2130706433`) pass here; the
    // resolver checks the address they resolve to.
    let ok = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if !ok {
        return Err(OriginError::Invalid);
    }
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Origin, OriginError> {
        Origin::parse(s, false)
    }

    #[test]
    fn parses_the_mailroom_forms() {
        let o = parse("https://LZ.Example.org").unwrap();
        assert_eq!(
            o.gateway_url(),
            "https://lz.example.org:443/.well-known/ohttp-gateway"
        );
        assert_eq!(
            o.purposes_url(),
            "https://lz.example.org:443/.well-known/ohttp-gateway?allowed_purposes"
        );
        assert_eq!(parse("lz.example.org").unwrap(), o);
        assert_eq!(parse("https://lz.example.org/").unwrap(), o);
        assert_eq!(parse("HTTPS://lz.example.org:443").unwrap(), o);
        let o = parse("https://lz.example.org:8443").unwrap();
        assert_eq!(o.port(), 8443);
        let o = parse("https://[2001:db8::1]:8443").unwrap();
        assert_eq!(o.host(), "2001:db8::1");
        assert_eq!(o.ip(), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(
            o.gateway_url(),
            "https://[2001:db8::1]:8443/.well-known/ohttp-gateway"
        );
    }

    #[test]
    fn rejects_anything_but_an_origin() {
        for bad in [
            "",
            "/",
            "https://",
            "https://user@lz.example.org",
            "https://user:pw@lz.example.org",
            "https://lz.example.org/path",
            "https://lz.example.org//",
            "https://lz.example.org?q",
            "https://lz.example.org#f",
            "https://lz%2eexample.org",
            "https://lz.example.org:0",
            "https://lz.example.org:65536",
            "https://lz.example.org:",
            "https://lz.example.org:x",
            "https://-lz.example.org",
            "https://lz..example.org",
            "https://[::1",
            "https://[not-v6]",
            "https://[::1]x",
            "ftp://lz.example.org",
            "https://lz.example.org:443:443",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn reads_odd_ipv4_spellings_as_the_http_client_does() {
        for spelling in [
            "2130706433",
            "0x7f.0.0.1",
            "127.1",
            "0177.0.0.1",
            "0x7F000001",
        ] {
            let o = parse(spelling).unwrap();
            assert_eq!(o.ip(), Some("127.0.0.1".parse().unwrap()), "{spelling}");
            assert_eq!(o.host(), "127.0.0.1");
        }
        // 169.254.169.254, the cloud metadata address.
        assert_eq!(
            parse("2852039166").unwrap().ip(),
            Some("169.254.169.254".parse().unwrap())
        );
        // IPv6 is written one way.
        assert_eq!(parse("[0:0::1]").unwrap().host(), "::1");
        assert_eq!(parse("[2001:DB8::1]").unwrap().host(), "2001:db8::1");
    }

    #[test]
    fn plain_http_only_when_allowed() {
        assert_eq!(parse("http://127.0.0.1:8080"), Err(OriginError::Http));
        let o = Origin::parse("http://127.0.0.1:8080", true).unwrap();
        assert_eq!(o.scheme(), Scheme::Http);
        assert_eq!(
            o.gateway_url(),
            "http://127.0.0.1:8080/.well-known/ohttp-gateway"
        );
    }

    #[test]
    fn debug_hides_the_origin() {
        let o = parse("https://secret-server.example").unwrap();
        assert!(!format!("{o:?}").contains("secret"));
    }
}
