// Copyright 2026. SPDX-License-Identifier: Apache-2.0
//! Re-export descriptors that the current VMM still owns after a Worker restart.

use crate::retained_fds;
use std::fs::{self, File, Metadata};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::{fs::MetadataExt, net::UnixStream};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Memory,
    BlockReader,
    BlockWriter,
}

type Identity = (u64, u64, u64);

fn matches(kind: Kind, wanted: Identity, metadata: &Metadata) -> bool {
    metadata.is_file()
        && metadata.dev() == wanted.0
        && metadata.ino() == wanted.1
        && (kind == Kind::BlockWriter || metadata.len() == wanted.2)
}

fn valid_access(kind: Kind, file: &File) -> bool {
    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || flags & libc::O_PATH != 0 {
        return false;
    }
    match kind {
        Kind::Memory => {
            let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
            let required = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
            seals >= 0 && seals & required == required
        }
        Kind::BlockReader => flags & libc::O_ACCMODE == libc::O_RDONLY,
        Kind::BlockWriter => {
            if flags & libc::O_ACCMODE != libc::O_RDWR {
                return false;
            }
            // A different open description conflicts with the recorded lock.
            // The Worker separately verifies that the lock still exists.
            let mut lock: libc::flock = unsafe { std::mem::zeroed() };
            lock.l_type = libc::F_WRLCK as _;
            lock.l_whence = libc::SEEK_SET as _;
            (unsafe { libc::fcntl(fd, libc::F_OFD_GETLK, &mut lock) }) == 0
                && lock.l_type == libc::F_UNLCK as libc::c_short
        }
    }
}

fn retained(kind: Kind, wanted: &[Identity]) -> io::Result<Option<Vec<File>>> {
    let mut matched: Vec<Option<File>> = (0..wanted.len()).map(|_| None).collect();
    for dirent in fs::read_dir("/proc/self/fd")? {
        let dirent = dirent?;
        let name = dirent.file_name();
        let Some(raw) = name.to_str().and_then(|name| name.parse::<i32>().ok()) else {
            continue;
        };
        let metadata = match fs::metadata(dirent.path()) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for (index, &identity) in wanted.iter().enumerate() {
            if matched[index].is_some() || !matches(kind, identity, &metadata) {
                continue;
            }
            // Duplication retains the original file description and its OFD lock.
            let duplicate = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3) };
            if duplicate < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EBADF) {
                    continue;
                }
                return Err(error);
            }
            let file = unsafe { File::from_raw_fd(duplicate) };
            if matches(kind, identity, &file.metadata()?) && valid_access(kind, &file) {
                matched[index] = Some(file);
            }
        }
    }
    Ok(matched.into_iter().collect())
}

pub fn send(mut stream: &UnixStream, arguments: &str) -> io::Result<()> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid recovery descriptor request",
        )
    };
    let (kind, body) = arguments.split_once(' ').ok_or_else(invalid)?;
    let kind = match kind {
        "ram" => Kind::Memory,
        "reader" => Kind::BlockReader,
        "writer" => Kind::BlockWriter,
        _ => return Err(invalid()),
    };
    let wanted: Vec<Identity> = serde_json::from_str(body).map_err(|_| invalid())?;
    if wanted.is_empty() || wanted.len() > 32 || wanted.iter().any(|identity| identity.1 == 0) {
        return Err(invalid());
    }
    let files = retained(kind, &wanted)?;
    let receipt = serde_json::json!({"protocol":"CaptureRecovery/1", "fd_count":files.as_ref().map_or(0, Vec::len)});
    writeln!(stream, "OK {receipt}")?;
    if let Some(files) = files {
        let deadline = Instant::now() + Duration::from_secs(2);
        for file in files {
            retained_fds::send_fd(stream, file.as_raw_fd(), deadline)?;
        }
    }
    Ok(())
}
