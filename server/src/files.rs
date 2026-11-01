//! Owner-only files in `data_dir`: folders made mode 0700, files mode 0600,
//! and replacement through a temporary file and a rename, so a crash leaves
//! the old or the new contents.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

/// Creates `dir` (and parents) readable only by the owner.
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}

/// Open options for files only the owner may read (mode 0600 on Unix).
pub fn private_file() -> std::fs::OpenOptions {
    let mut opts = std::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts
}

/// Replaces `dir/name` with `bytes` (mode 0600) through a temporary file
/// and a rename, syncing the file and then the directory, so a crash
/// leaves the old or the new contents.
pub fn write_private_atomic(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    let mut f = private_file()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, dir.join(name))?;
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// Every file in `dir` and its contents, skipping the `.tmp` files
/// [`write_private_atomic`] leaves after a crash. A missing `dir` has none.
/// Contents are zeroed on drop, as these are often key files.
pub fn read_files(dir: &Path) -> std::io::Result<Vec<(PathBuf, Zeroizing<Vec<u8>>)>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if path.extension().is_some_and(|x| x == "tmp") {
            continue;
        }
        let bytes = Zeroizing::new(std::fs::read(&path)?);
        out.push((path, bytes));
    }
    Ok(out)
}

/// A fresh, owner-only temporary directory for a test, deleted on drop.
#[cfg(test)]
pub(crate) struct TestDir(PathBuf);

#[cfg(test)]
impl TestDir {
    pub(crate) fn new(tag: &str) -> Self {
        let mut raw = [0u8; 8];
        rand::fill(&mut raw);
        let name = lz_proto::hex::encode(&raw);
        let d = std::env::temp_dir().join(format!("lz-{tag}-{name}"));
        create_private_dir(&d).expect("create test dir");
        Self(d)
    }
}

#[cfg(test)]
impl std::ops::Deref for TestDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

#[cfg(test)]
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_writes_are_owner_only_and_listing_skips_tmp() {
        let dir = TestDir::new("files");
        write_private_atomic(&dir, "a", b"one").unwrap();
        write_private_atomic(&dir, "a", b"two").unwrap();
        std::fs::write(dir.join("b.tmp"), b"partial").unwrap();
        let files = read_files(&dir).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(&files[0].1[..], b"two");
        assert!(read_files(&dir.join("missing")).unwrap().is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir.join("a")), 0o600);
            assert_eq!(mode(&dir), 0o700);
        }
        let path = dir.to_path_buf();
        drop(dir);
        assert!(!path.exists());
    }
}
