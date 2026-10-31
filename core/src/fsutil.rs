// SPDX-License-Identifier: Apache-2.0
//! Small filesystem helpers shared by the stores.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

/// Writes `bytes` to `path` atomically: the data goes to `<path>.tmp`, is flushed to disk and
/// then renamed over `path`, so readers see either the old or the new content, never a mix.
///
/// Creates missing parent directories. With `private` set, the file is created readable and
/// writable by the owner only (Unix mode 0600); on Windows the user-profile directory ACL
/// already restricts access, so the flag has no further effect there.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8], private: bool) -> io::Result<()> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(dir)?;
    }
    let mut tmp_name = name.to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);

    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
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
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)
}
