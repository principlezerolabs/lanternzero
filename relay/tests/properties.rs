//! Property tests for the input clients fully control: the gateway origin
//! in the request path.

use lz_relay::origin::{Origin, Scheme};
use proptest::prelude::*;

proptest! {
    /// Any path parses or is refused, without panicking; whatever parses
    /// is a bare https origin, so the gateway URLs built from it can only
    /// name `/.well-known/ohttp-gateway` on that host.
    #[test]
    fn any_path_is_an_origin_or_refused(s in "\\PC{0,80}") {
        if let Ok(o) = Origin::parse(&s, false) {
            prop_assert_eq!(o.scheme(), Scheme::Https);
            let url = o.gateway_url();
            let rest = url.strip_prefix("https://").unwrap();
            let (authority, path) = rest.split_once('/').unwrap();
            prop_assert_eq!(path, ".well-known/ohttp-gateway");
            prop_assert!(!authority.contains(['@', '?', '#', '%', '/', '\\']));
            prop_assert!(o.port() != 0);
        }
    }

    /// Paths built from URL-ish pieces, which reach the interesting
    /// branches far more often than random text.
    #[test]
    fn urlish_paths_never_smuggle_a_path_or_userinfo(
        scheme in prop::sample::select(vec!["", "https://", "HTTPS://", "http://", "ftp://"]),
        user in prop::option::of("[a-z:]{1,5}@"),
        host in "[a-z0-9.\\-\\[\\]:%]{1,20}",
        port in prop::option::of(0u32..70000),
        tail in prop::sample::select(vec!["", "/", "//", "/x", "?q", "#f", "/.well-known/ohttp-gateway"]),
    ) {
        let port = port.map(|p| format!(":{p}")).unwrap_or_default();
        let s = format!("{scheme}{}{host}{port}{tail}", user.clone().unwrap_or_default());
        if let Ok(o) = Origin::parse(&s, false) {
            prop_assert!(user.is_none(), "userinfo accepted: {s}");
            prop_assert!(matches!(tail, "" | "/"), "path accepted: {s}");
            prop_assert!(!host.contains('%'));
            prop_assert_eq!(o.scheme(), Scheme::Https);
            // Parsing the origin it names gives the same origin back.
            let again = o.gateway_url();
            let base = again.strip_suffix("/.well-known/ohttp-gateway").unwrap();
            prop_assert_eq!(Origin::parse(base, false).unwrap(), o);
        }
    }
}
