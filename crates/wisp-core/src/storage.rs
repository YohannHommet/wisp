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

#[allow(dead_code)]
pub(crate) struct PendingFile {
    writer: BufWriter<NamedTempFile>,
    dir: PathBuf,
}

#[allow(dead_code)]
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub(crate) struct ResumeLedger {
    pub version: u32,
    pub file_hash: String,
    pub file_name: String,
    pub total_size: u64,
    pub checkpoint_offset: u64,
}

pub(crate) struct ResumableFile {
    file: Option<std::fs::File>,
    part_path: PathBuf,
    resume_path: PathBuf,
    dir: PathBuf,
    file_hash: String,
    file_name: String,
    total_size: u64,
    checkpoint_offset: u64,
    has_checkpoint: bool,
    committed: bool,
    resume_enabled: bool,
}

impl ResumableFile {
    pub fn open_or_resume(
        dir: &Path,
        name: &str,
        size: u64,
        hash: &str,
        resume_enabled: bool,
    ) -> Result<(Self, u64)> {
        let part_path = dir.join(format!(".wisp-{hash}.part"));
        let resume_path = dir.join(format!(".wisp-{hash}.resume"));

        if resume_enabled && resume_path.exists() && part_path.exists() {
            if let Ok(bytes) = std::fs::read(&resume_path) {
                if let Ok(ledger) = serde_json::from_slice::<ResumeLedger>(&bytes) {
                    if ledger.version == 1
                        && ledger.file_hash == hash
                        && ledger.total_size == size
                    {
                        if let Ok(metadata) = std::fs::metadata(&part_path) {
                            let disk_len = metadata.len();
                            let target_offset = ledger.checkpoint_offset;
                            if disk_len >= target_offset && target_offset <= size {
                                use std::io::Seek;
                                let mut file = std::fs::OpenOptions::new()
                                    .read(true)
                                    .write(true)
                                    .open(&part_path)
                                    .context("opening existing partial file")?;
                                file.set_len(target_offset)
                                    .context("truncating partial file to checkpoint")?;
                                file.seek(std::io::SeekFrom::Start(target_offset))
                                    .context("seeking partial file to checkpoint")?;
                                return Ok((
                                    Self {
                                        file: Some(file),
                                        part_path,
                                        resume_path,
                                        dir: dir.to_owned(),
                                        file_hash: hash.to_owned(),
                                        file_name: name.to_owned(),
                                        total_size: size,
                                        checkpoint_offset: target_offset,
                                        has_checkpoint: target_offset > 0,
                                        committed: false,
                                        resume_enabled,
                                    },
                                    target_offset,
                                ));
                            }
                        }
                    }
                }
            }
            // Ledger invalid or disk file corrupt/truncated: clean up invalid sidecar
            let _ = std::fs::remove_file(&resume_path);
        }

        if !resume_enabled {
            let _ = std::fs::remove_file(&resume_path);
        }

        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&part_path)
            .context("creating partial file in destination")?;

        Ok((
            Self {
                file: Some(file),
                part_path,
                resume_path,
                dir: dir.to_owned(),
                file_hash: hash.to_owned(),
                file_name: name.to_owned(),
                total_size: size,
                checkpoint_offset: 0,
                has_checkpoint: false,
                committed: false,
                resume_enabled,
            },
            0,
        ))
    }

    pub fn write(&mut self, bytes: &[u8]) -> Result<()> {
        use std::io::Write;
        let file = self.file.as_mut().context("file handle closed")?;
        file.write_all(bytes)
            .context("writing received file (check free disk space)")
    }

    pub fn checkpoint(&mut self, current_offset: u64) -> Result<()> {
        use std::io::Write;
        let file = self.file.as_mut().context("file handle closed")?;
        file.flush().context("flushing partial file")?;
        file.sync_data().context("syncing partial file data")?;
        let ledger = ResumeLedger {
            version: 1,
            file_hash: self.file_hash.clone(),
            file_name: self.file_name.clone(),
            total_size: self.total_size,
            checkpoint_offset: current_offset,
        };
        let tmp_resume = self.dir.join(format!(".wisp-{}.resume.tmp", self.file_hash));
        std::fs::write(&tmp_resume, serde_json::to_vec(&ledger)?)
            .context("writing temporary resume ledger")?;
        std::fs::rename(&tmp_resume, &self.resume_path)
            .context("committing resume ledger")?;
        self.checkpoint_offset = current_offset;
        self.has_checkpoint = true;
        Ok(())
    }

    pub fn commit(mut self, expected_hash: &str) -> Result<PublishedFile> {
        use std::io::{Read, Seek, SeekFrom, Write};
        let mut file = self.file.take().context("file handle closed")?;
        file.flush().context("flushing received file")?;
        file.sync_all().context("syncing received file")?;

        // Rewind to 0 and verify full BLAKE3 hash from disk
        file.seek(SeekFrom::Start(0))
            .context("rewinding file for hash verification")?;
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = file
                .read(&mut buf)
                .context("reading file for verification")?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let computed = hasher.finalize().to_hex().to_string();
        if computed != expected_hash {
            drop(file);
            let _ = std::fs::remove_file(&self.part_path);
            let _ = std::fs::remove_file(&self.resume_path);
            self.committed = true;
            bail!("file integrity check failed on disk; temporary file removed");
        }

        // Close file handle before rename
        drop(file);

        let safe = sanitize(&self.file_name);
        for index in 0..10_000 {
            let candidate_name = collision_name(&safe, index);
            let target_path = self.dir.join(&candidate_name);
            if target_path.symlink_metadata().is_ok() {
                continue;
            }

            #[cfg(unix)]
            {
                match std::fs::hard_link(&self.part_path, &target_path) {
                    Ok(()) => {
                        let _ = std::fs::remove_file(&self.part_path);
                        let _ = std::fs::remove_file(&self.resume_path);
                        self.committed = true;

                        let mut sync_warning = None;
                        if let Ok(dir_file) = std::fs::File::open(&self.dir) {
                            if let Err(err) = dir_file.sync_all() {
                                sync_warning = Some(format!(
                                    "file saved at {}, but syncing its directory failed: {err}",
                                    target_path.display()
                                ));
                            }
                        } else {
                            sync_warning = Some(format!(
                                "file saved at {}, but opening its directory for sync failed",
                                target_path.display()
                            ));
                        }
                        return Ok(PublishedFile {
                            path: target_path,
                            sync_warning,
                        });
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(_) => {
                        if std::fs::rename(&self.part_path, &target_path).is_ok() {
                            let _ = std::fs::remove_file(&self.resume_path);
                            self.committed = true;
                            return Ok(PublishedFile {
                                path: target_path,
                                sync_warning: None,
                            });
                        }
                    }
                }
            }

            #[cfg(not(unix))]
            {
                match std::fs::rename(&self.part_path, &target_path) {
                    Ok(()) => {
                        let _ = std::fs::remove_file(&self.resume_path);
                        self.committed = true;
                        return Ok(PublishedFile {
                            path: target_path,
                            sync_warning: None,
                        });
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(err) => {
                        return Err(err).context("publishing received file without overwriting");
                    }
                }
            }
        }
        bail!("too many files named {safe}; choose another destination directory")
    }
}

impl Drop for ResumableFile {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if self.resume_enabled && self.has_checkpoint {
            return;
        }
        drop(self.file.take());
        let _ = std::fs::remove_file(&self.part_path);
        let _ = std::fs::remove_file(&self.resume_path);
    }
}

/// Clean up abandoned `.wisp-*.part` and `.wisp-*.resume` files in the directory older than `max_age`.
pub fn clean_stale_partial_files(dir: &Path, max_age: std::time::Duration) -> Result<usize> {
    let mut cleaned = 0;
    let now = std::time::SystemTime::now();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if file_name.starts_with(".wisp-")
                    && (file_name.ends_with(".part") || file_name.ends_with(".resume"))
                {
                    if let Ok(meta) = entry.metadata() {
                        if let Ok(modified) = meta.modified() {
                            if let Ok(age) = now.duration_since(modified) {
                                if age >= max_age {
                                    if meta.is_dir() {
                                        if std::fs::remove_dir_all(&path).is_ok() {
                                            cleaned += 1;
                                        }
                                    } else if std::fs::remove_file(&path).is_ok() {
                                        cleaned += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(cleaned)
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
    use std::time::Duration;
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

    #[test]
    fn resumable_file_checkpoint_and_resume_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let payload = vec![0x42u8; 1000];
        let full_hash = blake3::hash(&payload).to_hex().to_string();

        // 1. Initial write of 500 bytes and checkpoint
        {
            let (mut f, offset) =
                ResumableFile::open_or_resume(dir.path(), "data.bin", 1000, &full_hash, true)
                    .unwrap();
            assert_eq!(offset, 0);
            f.write(&payload[..500]).unwrap();
            f.checkpoint(500).unwrap();
            // Drop without commit: because checkpoint exists, it should be kept
        }

        let part_path = dir.path().join(format!(".wisp-{full_hash}.part"));
        let resume_path = dir.path().join(format!(".wisp-{full_hash}.resume"));
        assert!(part_path.exists());
        assert!(resume_path.exists());

        // 2. Resume from checkpoint
        {
            let (mut f, offset) =
                ResumableFile::open_or_resume(dir.path(), "data.bin", 1000, &full_hash, true)
                    .unwrap();
            assert_eq!(offset, 500);
            // Write remaining 500 bytes
            f.write(&payload[500..]).unwrap();
            let published = f.commit(&full_hash).unwrap();
            assert!(published.path.ends_with("data.bin"));
            assert_eq!(std::fs::read(&published.path).unwrap(), payload);
        }

        // Sidecar and part file should be cleaned up on commit
        assert!(!part_path.exists());
        assert!(!resume_path.exists());
    }

    #[test]
    fn resumable_file_part_larger_than_checkpoint_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let payload = vec![0x55u8; 1000];
        let full_hash = blake3::hash(&payload).to_hex().to_string();

        {
            let (mut f, _) =
                ResumableFile::open_or_resume(dir.path(), "data.bin", 1000, &full_hash, true)
                    .unwrap();
            f.write(&payload[..400]).unwrap();
            f.checkpoint(400).unwrap();
            // Write extra uncheckpointed bytes
            f.write(&[0xff; 200]).unwrap();
            // Drop
        }

        let part_path = dir.path().join(format!(".wisp-{full_hash}.part"));
        assert_eq!(std::fs::metadata(&part_path).unwrap().len(), 600);

        // Resume should truncate back to 400 bytes
        let (f, offset) =
            ResumableFile::open_or_resume(dir.path(), "data.bin", 1000, &full_hash, true).unwrap();
        assert_eq!(offset, 400);
        drop(f);
        assert_eq!(std::fs::metadata(&part_path).unwrap().len(), 400);
    }

    #[test]
    fn resumable_file_corrupt_ledger_falls_back_to_zero() {
        let dir = tempfile::tempdir().unwrap();
        let full_hash = "11".repeat(32);
        let resume_path = dir.path().join(format!(".wisp-{full_hash}.resume"));
        let part_path = dir.path().join(format!(".wisp-{full_hash}.part"));
        std::fs::write(&resume_path, b"not valid json").unwrap();
        std::fs::write(&part_path, b"random bytes").unwrap();

        let (f, offset) =
            ResumableFile::open_or_resume(dir.path(), "data.bin", 500, &full_hash, true).unwrap();
        assert_eq!(offset, 0);
        drop(f);
    }

    #[test]
    fn clean_stale_partial_files_removes_old_files() {
        let dir = tempfile::tempdir().unwrap();
        let old_part = dir.path().join(".wisp-stale.part");
        let old_resume = dir.path().join(".wisp-stale.resume");
        let normal_file = dir.path().join("normal.txt");

        std::fs::write(&old_part, b"stale").unwrap();
        std::fs::write(&old_resume, b"stale").unwrap();
        std::fs::write(&normal_file, b"keep").unwrap();

        // 0-duration max_age cleans everything starting with .wisp-
        let cleaned = clean_stale_partial_files(dir.path(), Duration::from_secs(0)).unwrap();
        assert_eq!(cleaned, 2);
        assert!(!old_part.exists());
        assert!(!old_resume.exists());
        assert!(normal_file.exists());
    }
}

