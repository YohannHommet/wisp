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
                    #[cfg(unix)]
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
                    #[cfg(not(unix))]
                    let sync_warning = None;
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

pub(crate) struct PendingDirectory {
    temp_dir: Option<tempfile::TempDir>,
    dest_dir: PathBuf,
}

impl PendingDirectory {
    pub fn create(dest_dir: &Path) -> Result<Self> {
        let temp_dir = tempfile::Builder::new()
            .prefix(".wisp-dir-")
            .suffix(".part")
            .tempdir_in(dest_dir)
            .context("cannot create a temporary directory in the destination")?;
        Ok(Self {
            temp_dir: Some(temp_dir),
            dest_dir: dest_dir.to_owned(),
        })
    }

    pub fn path(&self) -> &Path {
        self.temp_dir.as_ref().expect("temp_dir present").path()
    }

    pub fn create_subdir(&self, rel_path: &Path) -> Result<()> {
        let root = self.path();
        let target = root.join(rel_path);
        if !target.starts_with(root) {
            bail!("directory traversal attempted");
        }
        std::fs::create_dir_all(&target).context("creating subdirectory in temporary directory")?;
        Ok(())
    }

    pub fn open_file(&self, rel_path: &Path, executable: bool) -> Result<std::fs::File> {
        let root = self.path();
        let target = root.join(rel_path);
        if !target.starts_with(root) {
            bail!("directory traversal attempted");
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .context("creating parent directory in temporary directory")?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mode = if executable { 0o700 } else { 0o600 };
            options.mode(mode);
        }
        let file = options
            .open(&target)
            .context("creating file in temporary directory")?;
        Ok(file)
    }

    pub fn commit(mut self, name: &str) -> Result<PublishedFile> {
        let temp = self.temp_dir.take().expect("temp_dir present");
        let staging_path = temp.path().to_owned();
        let _ = temp.keep();
        let safe = sanitize(name);
        for index in 0..10_000 {
            let candidate_name = collision_name(&safe, index);
            let target_path = self.dest_dir.join(&candidate_name);
            if target_path.symlink_metadata().is_ok() {
                continue;
            }
            #[cfg(unix)]
            {
                match std::fs::create_dir(&target_path) {
                    Ok(()) => {
                        if let Err(err) = std::fs::rename(&staging_path, &target_path) {
                            let _ = std::fs::remove_dir(&target_path);
                            let _ = std::fs::remove_dir_all(&staging_path);
                            return Err(err).context("publishing received directory");
                        }
                        let mut sync_warning = None;
                        if let Ok(dir_file) = std::fs::File::open(&self.dest_dir) {
                            if let Err(err) = dir_file.sync_all() {
                                sync_warning = Some(format!(
                                    "directory saved at {}, but syncing its parent directory failed: {err}",
                                    target_path.display()
                                ));
                            }
                        } else {
                            sync_warning = Some(format!(
                                "directory saved at {}, but opening its parent directory for sync failed",
                                target_path.display()
                            ));
                        }
                        return Ok(PublishedFile {
                            path: target_path,
                            sync_warning,
                        });
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(err) => {
                        let _ = std::fs::remove_dir_all(&staging_path);
                        return Err(err).context("reserving destination directory");
                    }
                }
            }
            #[cfg(not(unix))]
            {
                match std::fs::rename(&staging_path, &target_path) {
                    Ok(()) => {
                        return Ok(PublishedFile {
                            path: target_path,
                            sync_warning: None,
                        });
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(err) => {
                        let _ = std::fs::remove_dir_all(&staging_path);
                        return Err(err).context("publishing received directory");
                    }
                }
            }
        }
        let _ = std::fs::remove_dir_all(&staging_path);
        bail!("too many items named {safe}; choose another destination directory")
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

/// Validate and sanitize a relative path sent over the wire.
/// Rejects path traversal, backslashes, absolute paths, empty components,
/// Windows device names, and control characters.
pub fn sanitize_relative_path(wire_path: &str) -> Result<PathBuf> {
    if wire_path.is_empty() {
        bail!("empty relative path");
    }
    if wire_path.contains('\\') {
        bail!("relative path cannot contain backslashes");
    }
    if wire_path.starts_with('/') || wire_path.starts_with('~') || wire_path.contains(':') {
        bail!("relative path must be relative without drive letters or root markers");
    }
    let components: Vec<&str> = wire_path.split('/').collect();
    if components.is_empty() || components.len() > 32 {
        bail!("relative path nesting exceeds 32 levels or is empty");
    }
    let mut safe_path = PathBuf::new();
    for segment in components {
        if segment.is_empty() || segment == "." || segment == ".." {
            bail!("relative path component cannot be empty, '.' or '..'");
        }
        if segment.len() > 240 {
            bail!("relative path component exceeds 240 bytes");
        }
        if segment.ends_with([' ', '.']) {
            bail!("relative path component cannot end with a space or dot");
        }
        for c in segment.chars() {
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
                bail!("relative path contains invalid or bidirectional control character");
            }
        }
        let stem = segment
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
            bail!("relative path component matches Windows reserved device name: {stem}");
        }
        safe_path.push(segment);
    }
    Ok(safe_path)
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

    #[test]
    fn sanitize_relative_path_safety() {
        assert_eq!(
            sanitize_relative_path("src/main.rs").unwrap(),
            PathBuf::from("src/main.rs")
        );
        assert_eq!(
            sanitize_relative_path("docs/images/logo.png").unwrap(),
            PathBuf::from("docs/images/logo.png")
        );

        // Disallowed patterns
        assert!(sanitize_relative_path("").is_err());
        assert!(sanitize_relative_path("../secret").is_err());
        assert!(sanitize_relative_path("a/../b").is_err());
        assert!(sanitize_relative_path("/etc/passwd").is_err());
        assert!(sanitize_relative_path("C:\\Windows").is_err());
        assert!(sanitize_relative_path("a\\b").is_err());
        assert!(sanitize_relative_path("foo//bar").is_err());
        assert!(sanitize_relative_path("con/data.txt").is_err());
        assert!(sanitize_relative_path("nul").is_err());
        assert!(sanitize_relative_path("prn.txt").is_err());
        assert!(sanitize_relative_path("com1/file").is_err());
        assert!(sanitize_relative_path("foo./bar").is_err());
        assert!(sanitize_relative_path("foo /bar").is_err());
        assert!(sanitize_relative_path("foo/\u{202e}bar").is_err());
    }

    #[test]
    fn pending_directory_staging_and_commit() {
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("destination");
        std::fs::create_dir_all(&dest).unwrap();

        // 1. Rollback on drop
        {
            let pending = PendingDirectory::create(&dest).unwrap();
            pending.create_subdir(Path::new("sub")).unwrap();
            let mut f = pending.open_file(Path::new("sub/a.txt"), false).unwrap();
            use std::io::Write;
            f.write_all(b"hello").unwrap();
            drop(f);
            // pending dropped here without commit
        }
        // Staging dir should be gone
        assert_eq!(std::fs::read_dir(&dest).unwrap().count(), 0);

        // 2. Successful commit
        let pending = PendingDirectory::create(&dest).unwrap();
        pending.create_subdir(Path::new("sub")).unwrap();
        let mut f = pending.open_file(Path::new("sub/a.txt"), true).unwrap();
        use std::io::Write;
        f.write_all(b"world").unwrap();
        drop(f);
        let published = pending.commit("my-folder").unwrap();
        assert!(published.path.ends_with("my-folder"));
        assert!(published.path.join("sub/a.txt").is_file());
        assert_eq!(
            std::fs::read(published.path.join("sub/a.txt")).unwrap(),
            b"world"
        );

        // 3. Collision handling
        let pending2 = PendingDirectory::create(&dest).unwrap();
        let published2 = pending2.commit("my-folder").unwrap();
        assert!(published2.path.ends_with("my-folder (1)"));
    }
}
