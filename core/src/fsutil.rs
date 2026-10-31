// SPDX-License-Identifier: Apache-2.0
//! Small filesystem helpers shared by the stores.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

/// Writes `bytes` to `path` atomically: the data goes to `<path>.tmp`, is flushed to disk and
/// then renamed over `path`, so readers see either the old or the new content, never a mix.
///
/// Any leftover `<path>.tmp` is removed first and the new one is created exclusively, so a
/// stale or planted file (or symlink) is never reused; on failure the temp file is removed.
/// Creates missing parent directories. With `private` set, the file is created readable and
/// writable by the owner only (Unix mode 0600). On Windows there is no per-file mode: the
/// owner-only property holds only when the file lives under the user's profile directory,
/// whose ACL restricts access, so the daemon must keep its state there.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8], private: bool) -> io::Result<()> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(dir) = dir {
        fs::create_dir_all(dir)?;
    }
    let mut tmp_name = name.to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);

    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        if private {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
    }
    #[cfg(not(unix))]
    let _ = private;

    let mut file = options.open(&tmp)?;
    let result = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| {
            drop(file);
            fs::rename(&tmp, path)
        });
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    #[cfg(unix)]
    {
        if let Some(dir) = dir {
            if let Ok(d) = fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_leftover_tmp_file_does_not_break_the_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        fs::write(dir.path().join("state.json.tmp"), "junk from a crash").unwrap();
        write_atomic(&path, b"fresh", true).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"fresh");
        assert!(!dir.path().join("state.json.tmp").exists());
    }

    #[test]
    fn a_failed_rename_leaves_no_tmp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        fs::create_dir(&path).unwrap();
        assert!(write_atomic(&path, b"data", true).is_err());
        assert!(!dir.path().join("state.json.tmp").exists());
    }
}
