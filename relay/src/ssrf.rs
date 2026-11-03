//! Outbound connection rules: the relay connects to gateways that clients
//! name, so a hostile client could aim it at internal services.
//!
//! The HTTP client resolves names through [`SafeResolver`], which drops
//! non-public addresses, so the check holds at connect time and DNS
//! rebinding can't get around it. Literal IP hosts skip DNS, so the relay
//! checks them with [`is_public`] before any request.
//!
//! Copied from `server/src/ssrf.rs` (keep the two in step) until a shared
//! server-side crate exists (CLAUDE.md, "No shared server/gateway crate
//! yet").

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
/// are allowed (tests).
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
                return Err("no public address for the gateway host".into());
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
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
}
