//! Outbound connection rules for push endpoints (spec §4.1, §4.5).
//!
//! The server connects to URLs that clients registered, so a hostile client
//! could aim it at internal services. The HTTP client resolves names through
//! [`SafeResolver`], which drops disallowed addresses, so the check holds at
//! connect time and DNS rebinding can't get around it. Literal IP hosts skip
//! DNS, so [`check_url`] rejects disallowed ones before any request.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// True for addresses on the public internet.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(v4);
            }
            is_public_v6(v6)
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || a == 0 // "this network"
        || (a == 100 && (64..128).contains(&b)) // carrier-grade NAT
        || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
        || (a == 198 && (b == 18 || b == 19)) // benchmarking
        || a >= 240) // reserved
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let seg = ip.segments();
    let seg0 = seg[0];
    // IPv4-compatible (::a.b.c.d, deprecated), 6to4 (2002::/16), and Teredo
    // (2001::/32) embed IPv4 addresses; refuse them rather than decode them.
    if seg[..6] == [0; 6] || seg0 == 0x2002 || (seg0 == 0x2001 && seg[1] == 0) {
        return false;
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (seg0 & 0xfe00) == 0xfc00 // unique local
        || (seg0 & 0xffc0) == 0xfe80 // link local
        || (seg0 & 0xffc0) == 0xfec0 // site local (deprecated)
        || seg0 == 0x2001 && ip.segments()[1] == 0x0db8 // documentation
        || seg0 == 0x0064 && ip.segments()[1] == 0xff9b) // NAT64 to v4
}

/// A resolver that returns only public addresses, unless private targets
/// are allowed (self-hosting and tests).
#[derive(Debug, Clone)]
pub struct SafeResolver {
    pub allow_private: bool,
}

impl Resolve for SafeResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let allow_private = self.allow_private;
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|a| allow_private || is_public(a.ip()))
                .collect();
            if addrs.is_empty() {
                return Err("no allowed address for push endpoint host".into());
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TargetError {
    #[error("endpoint host is not on the gateway allow-list")]
    NotAllowListed,
    #[error("endpoint is a disallowed IP address")]
    PrivateAddress,
    #[error("endpoint is not a valid https URL")]
    Invalid,
}

/// Checks a push endpoint before storing or contacting it.
pub fn check_url(
    endpoint: &str,
    allow_private: bool,
    allowlist: &[String],
) -> Result<(), TargetError> {
    let url = url_host(endpoint, allow_private).ok_or(TargetError::Invalid)?;
    if !allowlist.is_empty() && !allowlist.iter().any(|h| h.eq_ignore_ascii_case(&url)) {
        return Err(TargetError::NotAllowListed);
    }
    let bare = url.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>()
        && !allow_private
        && !is_public(ip)
    {
        return Err(TargetError::PrivateAddress);
    }
    Ok(())
}

/// The lowercase host of an `https` URL (or `http`, for local tests only).
fn url_host(endpoint: &str, allow_http: bool) -> Option<String> {
    let uri: http::Uri = endpoint.parse().ok()?;
    match uri.scheme_str() {
        Some("https") => {}
        Some("http") if allow_http => {}
        _ => return None,
    }
    Some(uri.host()?.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_addresses() {
        for bad in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "198.18.0.1",
            "::1",
            "::",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "2001:db8::1",
            "::127.0.0.1",
            "::a9fe:a9fe",
            "2002:7f00:1::1",
            "2001:0:4136:e378::1",
        ] {
            assert!(!is_public(bad.parse().unwrap()), "{bad} should be blocked");
        }
        for good in [
            "1.1.1.1",
            "8.8.8.8",
            "2606:4700:4700::1111",
            "::ffff:1.1.1.1",
        ] {
            assert!(is_public(good.parse().unwrap()), "{good} should be allowed");
        }
    }

    #[test]
    fn checks_urls() {
        let none: &[String] = &[];
        assert_eq!(check_url("https://push.example.app/x", false, none), Ok(()));
        assert_eq!(
            check_url("https://169.254.169.254/latest", false, none),
            Err(TargetError::PrivateAddress)
        );
        assert_eq!(
            check_url("https://[::1]:8443/x", false, none),
            Err(TargetError::PrivateAddress)
        );
        assert_eq!(check_url("https://127.0.0.1/x", true, none), Ok(()));
        let list = vec!["push.example.app".to_owned()];
        assert_eq!(
            check_url("https://PUSH.example.app/x", false, &list),
            Ok(())
        );
        assert_eq!(
            check_url("https://evil.example/x", false, &list),
            Err(TargetError::NotAllowListed)
        );
        assert_eq!(
            check_url("ftp://x/", false, none),
            Err(TargetError::Invalid)
        );
        assert_eq!(
            check_url("http://push.example.app/", false, none),
            Err(TargetError::Invalid)
        );
    }
}
