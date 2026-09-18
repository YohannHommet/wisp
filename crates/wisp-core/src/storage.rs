//! Receive into a private, randomly named file in the destination filesystem.
//! Publishing never overwrites an existing file, including a dangling symlink.
use anyhow::{bail, Context, Result};
use std::{
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;

#[derive(Debug)]
pub(crate) struct PublishedFile {
    pub path: PathBuf,
    pub sync_warning: Option<String>,
}

pub(crate) struct PendingFile {
    writer: BufWriter<NamedTempFile>,
    dir: PathBuf,
}

impl PendingFile {
    pub fn create(dir: &Path) -> Result<Self> {
        let file = tempfile::Builder::new()
            .prefix(".wisp-")
            .suffix(".part")
            .tempfile_in(dir)
            .context("cannot create a temporary file in the destination")?;
        Ok(Self {
            writer: BufWriter::with_capacity(256 * 1024, file),
            dir: dir.to_owned(),
        })
    }

    pub fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer
            .write_all(bytes)
            .context("writing received file (check free disk space)")
    }

    /// No await between verification and publication: cancellation cannot orphan a commit task.
    /// Synchronous bounded writes also ensure the file handle closes before its cleanup guard.
    pub fn commit(mut self, name: &str) -> Result<PublishedFile> {
        self.writer.flush().context("flushing received file")?;
        self.writer
            .get_ref()
            .as_file()
            .sync_all()
            .context("syncing received file")?;
        let mut temp = self.writer.into_inner().map_err(|e| e.into_error())?;
        let safe = sanitize(name);
        for index in 0..10_000 {
            let path = self.dir.join(collision_name(&safe, index));
            match temp.persist_noclobber(&path) {
                Ok(file) => {
                    drop(file);
                    let mut sync_warning = None;
                    #[cfg(unix)]
                    {
                        if let Ok(dir_file) = std::fs::File::open(&self.dir) {
                            if let Err(err) = dir_file.sync_all() {
                                sync_warning = Some(format!(
                                    "file saved at {}, but syncing its directory failed: {err}",
                                    path.display()
                                ));
                            }
                        } else {
                            sync_warning = Some(format!(
                                "file saved at {}, but opening its directory for sync failed",
                                path.display()
                            ));
                        }
                    }
                    return Ok(PublishedFile { path, sync_warning });
                }
                Err(err) if err.error.kind() == std::io::ErrorKind::AlreadyExists => {
                    temp = err.file
                }
                Err(err) => {
                    return Err(err.error).context("publishing received file without overwriting")
                }
            }
        }
        bail!("too many files named {safe}; choose another destination directory")
    }
}

fn collision_name(name: &str, index: usize) -> String {
    if index == 0 {
        return name.to_owned();
    }
    let path = Path::new(name);
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    let ext = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    format!("{stem} ({index}){ext}")
}

/// A portable single filename; removes traversal, control characters and device names.
pub fn sanitize(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or_default();
    let mut clean: String = base
        .chars()
        .map(|c| {
            if c.is_control()
                || matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|')
                || matches!(
                    c,
                    '\u{200e}'
                        | '\u{200f}'
                        | '\u{061c}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                )
            {
                '_'
            } else {
                c
            }
        })
        .collect();
    clean = clean.trim_matches([' ', '.']).to_owned();
    // Leave room for a collision suffix and keep UTF-8 boundaries intact.
    let mut limit = clean.len().min(180);
    while !clean.is_char_boundary(limit) {
        limit -= 1;
    }
    clean.truncate(limit);
    clean = clean.trim_end_matches([' ', '.']).to_owned();
    if clean.is_empty() {
        return "file".into();
    }
    // Windows recognizes device names even with multiple extensions.
    let stem = clean
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end()
        .to_ascii_uppercase();
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$"
    ) || ["COM", "LPT"].iter().any(|prefix| {
        stem.strip_prefix(prefix).is_some_and(|n| {
            matches!(
                n,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    }) {
        clean.insert(0, '_');
    }
    clean
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn portable_names() {
        for (raw, expected) in [
            ("../../file.txt", "file.txt"),
            ("C:\\temp\\file.txt", "file.txt"),
            ("NUL.txt", "_NUL.txt"),
            ("CLOCK$.txt", "_CLOCK$.txt"),
            ("\u{200e}file.txt", "_file.txt"),
            ("con.foo.bar", "_con.foo.bar"),
            ("LPT1", "_LPT1"),
            ("... ", "file"),
            ("a\x1b[31m.txt", "a_[31m.txt"),
            ("hello. ", "hello"),
            ("COM¹.txt", "_COM¹.txt"),
        ] {
            assert_eq!(sanitize(raw), expected);
        }
        assert!(sanitize(&"é".repeat(200)).len() <= 180);
    }
    #[test]
    fn collision_does_not_overwrite_and_drop_cleans_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("report.txt"), b"original").unwrap();
        let mut a = PendingFile::create(dir.path()).unwrap();
        let mut b = PendingFile::create(dir.path()).unwrap();
        a.write(b"first").unwrap();
        b.write(b"second").unwrap();
        assert!(a
            .commit("report.txt")
            .unwrap()
            .path
            .ends_with("report (1).txt"));
        assert!(b
            .commit("report.txt")
            .unwrap()
            .path
            .ends_with("report (2).txt"));
        assert_eq!(
            std::fs::read(dir.path().join("report.txt")).unwrap(),
            b"original"
        );
        {
            let mut pending = PendingFile::create(dir.path()).unwrap();
            pending.write(b"incomplete").unwrap();
        }
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 3);
    }
    #[cfg(unix)]
    #[test]
    fn private_permissions_and_dangling_symlink_are_preserved() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        symlink(dir.path().join("missing"), dir.path().join("file")).unwrap();
        let pending = PendingFile::create(dir.path()).unwrap();
        assert_eq!(
            pending
                .writer
                .get_ref()
                .as_file()
                .metadata()
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(pending.commit("file").unwrap().path.ends_with("file (1)"));
        assert!(dir.path().join("file").is_symlink());
    }
}
