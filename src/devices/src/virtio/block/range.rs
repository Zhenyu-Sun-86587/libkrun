// Copyright 2026. SPDX-License-Identifier: Apache-2.0
//! Read-only storage over a capability socket bound to one immutable object.

use imago::Storage;
use imago::io_buffers::{IoVector, IoVectorMut};
use imago::storage::drivers::CommonStorageHelper;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MAGIC: &[u8; 8] = b"SMOLBR1\0";
const MAX_REQUEST: usize = 1 << 20;

#[derive(Clone, Debug)]
pub struct ManagedRange {
    size: u64,
    stream: Arc<Mutex<UnixStream>>,
}

impl ManagedRange {
    pub fn new(stream: UnixStream, size: u64) -> io::Result<Self> {
        if size == 0 || size > i64::MAX as u64 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        stream.peer_addr()?;
        let mut kind = 0;
        let mut size_of_kind = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut kind as *mut libc::c_int).cast(),
                &mut size_of_kind,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        if kind != libc::SOCK_STREAM {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        stream.set_read_timeout(Some(Duration::from_secs(35)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        Ok(Self {
            size,
            stream: Arc::new(Mutex::new(stream)),
        })
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    fn read_exact_at(&self, output: &mut [u8], mut offset: u64) -> io::Result<()> {
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| io::Error::other("managed range socket poisoned"))?;
        let result = (|| {
            for chunk in output.chunks_mut(MAX_REQUEST) {
                let count = chunk.len();
                let mut request = [0u8; 20];
                request[..8].copy_from_slice(MAGIC);
                request[8..16].copy_from_slice(&offset.to_be_bytes());
                request[16..].copy_from_slice(&(count as u32).to_be_bytes());
                stream.write_all(&request)?;

                let mut response = [0; 4];
                stream.read_exact(&mut response)?;
                match u32::from_be_bytes(response) {
                    u32::MAX => {
                        stream.read_exact(&mut response)?;
                        // This is a complete error response so a later request
                        // may retry the same immutable range on this socket.
                        let errno = i32::try_from(u32::from_be_bytes(response))
                            .ok()
                            .filter(|errno| (1..4096).contains(errno))
                            .ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "invalid managed range error",
                                )
                            })?;
                        return Ok(Some(io::Error::from_raw_os_error(errno)));
                    }
                    n if n as usize == count => (),
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unexpected managed range length",
                        ));
                    }
                }
                stream.read_exact(chunk)?;
                offset += count as u64;
            }
            Ok(None)
        })();
        match result {
            Ok(None) => Ok(()),
            Ok(Some(error)) => Err(error),
            Err(error) => {
                // A partial command or response can no longer be framed safely.
                let _ = stream.shutdown(Shutdown::Both);
                Err(error)
            }
        }
    }
}

#[derive(Debug)]
pub(super) struct RemoteStorage {
    source: ManagedRange,
    helper: CommonStorageHelper,
}

impl RemoteStorage {
    pub(super) fn new(source: ManagedRange) -> Self {
        Self {
            source,
            helper: CommonStorageHelper::default(),
        }
    }
}

impl Display for RemoteStorage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("managed immutable object range")
    }
}

impl Storage for RemoteStorage {
    fn size(&self) -> io::Result<u64> {
        Ok(self.source.size)
    }

    async unsafe fn pure_readv(&self, mut buf: IoVectorMut<'_>, offset: u64) -> io::Result<()> {
        let mut bytes = vec![0; buf.len() as usize];
        let length = self.source.size.saturating_sub(offset).min(buf.len()) as usize;
        if length != 0 {
            self.source.read_exact_at(&mut bytes[..length], offset)?;
        }
        buf.copy_from_slice(&bytes);
        Ok(())
    }

    async unsafe fn pure_writev(&self, _: IoVector<'_>, _: u64) -> io::Result<()> {
        Err(io::ErrorKind::PermissionDenied.into())
    }

    async fn flush(&self) -> io::Result<()> {
        Ok(())
    }

    async fn sync(&self) -> io::Result<()> {
        Ok(())
    }

    async unsafe fn invalidate_cache(&self) -> io::Result<()> {
        Ok(())
    }

    fn get_storage_helper(&self) -> &CommonStorageHelper {
        &self.helper
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn broker_retries_a_complete_error_and_checks_range_framing() {
        let (client, mut broker) = UnixStream::pair().unwrap();
        let range = ManagedRange::new(client, MAX_REQUEST as u64 + 9).unwrap();
        let thread = thread::spawn(move || {
            for result in [Err(libc::EAGAIN), Ok(b"ninebytes".as_slice())] {
                let mut request = [0; 20];
                broker.read_exact(&mut request).unwrap();
                assert_eq!(&request[..8], MAGIC);
                assert_eq!(&request[8..16], &(MAX_REQUEST as u64).to_be_bytes());
                assert_eq!(&request[16..], &9u32.to_be_bytes());
                match result {
                    Ok(data) => {
                        broker.write_all(&9u32.to_be_bytes()).unwrap();
                        broker.write_all(data).unwrap();
                    }
                    Err(errno) => {
                        broker.write_all(&u32::MAX.to_be_bytes()).unwrap();
                        broker.write_all(&(errno as u32).to_be_bytes()).unwrap();
                    }
                }
            }
        });
        let mut data = [0; 9];
        assert_eq!(
            range
                .read_exact_at(&mut data, MAX_REQUEST as u64)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EAGAIN)
        );
        range.read_exact_at(&mut data, MAX_REQUEST as u64).unwrap();
        assert_eq!(&data, b"ninebytes");
        thread.join().unwrap();
    }
}
