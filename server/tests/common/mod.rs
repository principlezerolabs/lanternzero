//! Shared test helpers. Each test binary uses a different subset.
#![allow(dead_code)]

pub mod fake_lwd;
pub mod wallet;

/// A fresh directory under the system temp dir, `lz-<tag>-<random>`. Left
/// in place: servers under test may still be using it when the test ends.
pub fn temp_dir(tag: &str) -> std::path::PathBuf {
    let mut raw = [0u8; 8];
    rand::fill(&mut raw);
    let d = std::env::temp_dir().join(format!("lz-{tag}-{}", lz_proto::hex::encode(&raw)));
    std::fs::create_dir_all(&d).unwrap();
    d
}
