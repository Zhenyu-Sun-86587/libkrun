use libc::{
    IFF_DETACH_QUEUE, IFF_MULTI_QUEUE, IFF_NO_PI, IFF_TAP, IFF_TUN, IFF_VNET_HDR, TUN_F_CSUM,
    TUN_F_TSO4, TUN_F_TSO6, TUN_F_UFO, c_char, c_int, ifreq,
};
use nix::fcntl::{FcntlArg, OFlag, fcntl, open};
use nix::sys::stat::Mode;
use nix::unistd::{read, write};
use nix::{ioctl_read, ioctl_write_int, ioctl_write_ptr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::{io, mem, ptr};
use virtio_bindings::virtio_net::{
    VIRTIO_NET_F_GUEST_CSUM, VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_TSO6,
    VIRTIO_NET_F_GUEST_UFO,
};

use super::backend::{ConnectError, NetBackend, ReadError, WriteError};
use super::device::TapProfile;

ioctl_write_ptr!(tunsetiff, b'T', 202, c_int);
// TUNGETIFF uses the size of int in the request but writes an ifreq.
ioctl_read!(tungetiff, b'T', 210, c_int);
ioctl_write_int!(tunsetoffload, b'T', 208);
ioctl_read!(tungetvnethdrsz, b'T', 215, c_int);
ioctl_write_ptr!(tunsetvnethdrsz, b'T', 216, c_int);
ioctl_read!(tungetvnetbe, b'T', 223, c_int);

pub struct Tap {
    fd: Arc<OwnedFd>,
}

/// A prepared Worker TAP. The config keeps the descriptor alive across device
/// reset, while the worker borrows its own reference for packet I/O.
#[derive(Clone)]
pub struct TapFd {
    fd: Arc<OwnedFd>,
    pub profile: TapProfile,
    /// Identifies the current host attachment. A restore provides a new lease.
    pub attachment_digest: [u8; 32],
}

impl TapFd {
    pub fn duplicate(
        fd: RawFd,
        profile: TapProfile,
        attachment_digest: [u8; 32],
    ) -> io::Result<Self> {
        // SAFETY: fcntl validates all descriptor values. On success the
        // returned descriptor is a new descriptor owned by this call.
        let fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Self::validate(&fd, profile.vnet_header_size)?;
        Ok(Self {
            fd: Arc::new(fd),
            profile,
            attachment_digest,
        })
    }

    fn validate(fd: &OwnedFd, expected_header: u16) -> io::Result<()> {
        let flags = OFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFL)?);
        if !flags.contains(OFlag::O_NONBLOCK) || flags & OFlag::O_ACCMODE != OFlag::O_RDWR {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TAP fd must be read-write and nonblocking",
            ));
        }
        let mut req: ifreq = unsafe { mem::zeroed() };
        let mut header = 0;
        let mut big_endian = 0;
        // SAFETY: ioctl arguments are writable storage of the sizes Linux
        // expects, even though TUNGETIFF encodes sizeof(int).
        let flags = unsafe {
            tungetiff(fd.as_raw_fd(), (&mut req as *mut ifreq).cast())?;
            tungetvnethdrsz(fd.as_raw_fd(), &mut header)?;
            // EINVAL means this kernel does not support big-endian tun headers.
            match tungetvnetbe(fd.as_raw_fd(), &mut big_endian) {
                Ok(_) | Err(nix::errno::Errno::EINVAL) => {}
                Err(err) => return Err(err.into()),
            }
            req.ifr_ifru.ifru_flags as u16 as c_int
        };
        let required = IFF_TAP | IFF_NO_PI | IFF_VNET_HDR;
        let rejected = IFF_TUN | IFF_MULTI_QUEUE | IFF_DETACH_QUEUE;
        if flags & required != required
            || flags & rejected != 0
            || header != c_int::from(expected_header)
            || big_endian != 0
            || cfg!(target_endian = "big")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected an attached single-queue TAP with a 12-byte little-endian virtio header and no packet information",
            ));
        }
        Ok(())
    }
}

impl Tap {
    /// Create an endpoint using the file descriptor of a tap device
    pub fn new(tap_name: String, vnet_features: u64) -> Result<Self, ConnectError> {
        let fd = match open("/dev/net/tun", OFlag::O_RDWR, Mode::empty()) {
            Ok(fd) => fd,
            Err(err) => return Err(ConnectError::OpenNetTun(err)),
        };

        let mut req: ifreq = unsafe { mem::zeroed() };

        unsafe {
            ptr::copy_nonoverlapping(
                tap_name.as_ptr() as *const c_char,
                req.ifr_name.as_mut_ptr(),
                tap_name.len(),
            );
        }

        req.ifr_ifru.ifru_flags = IFF_TAP as i16 | IFF_NO_PI as i16 | IFF_VNET_HDR as i16;

        let mut offload_flags: u64 = 0;
        if (vnet_features & (1 << VIRTIO_NET_F_GUEST_CSUM)) != 0 {
            offload_flags |= TUN_F_CSUM as u64;
        }
        if (vnet_features & (1 << VIRTIO_NET_F_GUEST_TSO4)) != 0 {
            offload_flags |= TUN_F_TSO4 as u64;
        }
        if (vnet_features & (1 << VIRTIO_NET_F_GUEST_TSO6)) != 0 {
            offload_flags |= TUN_F_TSO6 as u64;
        }
        if (vnet_features & (1 << VIRTIO_NET_F_GUEST_UFO)) != 0 {
            offload_flags |= TUN_F_UFO as u64;
        }

        unsafe {
            if let Err(err) = tunsetiff(fd.as_raw_fd(), &mut req as *mut _ as *mut _) {
                return Err(ConnectError::TunSetIff(io::Error::from(err)));
            }

            // TODO(slp): replace hardcoded vnet size with cons
            if let Err(err) = tunsetvnethdrsz(fd.as_raw_fd(), &12) {
                return Err(ConnectError::TunSetVnetHdrSz(io::Error::from(err)));
            }

            if let Err(err) = tunsetoffload(fd.as_raw_fd(), offload_flags) {
                return Err(ConnectError::TunSetOffload(io::Error::from(err)));
            }
        }

        match fcntl(&fd, FcntlArg::F_GETFL) {
            Ok(flags) => {
                if let Err(e) = fcntl(
                    &fd,
                    FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK),
                ) {
                    warn!("error switching to non-blocking: id={fd:?}, err={e}");
                }
            }
            Err(e) => error!("couldn't obtain fd flags id={fd:?}, err={e}"),
        };

        Ok(Self { fd: Arc::new(fd) })
    }

    pub fn from_fd(binding: TapFd, vnet_features: u64) -> Result<Self, ConnectError> {
        // Recheck the shared file description at activation before any packet
        // I/O. The Worker must retain exclusive configuration authority.
        TapFd::validate(&binding.fd, binding.profile.vnet_header_size)
            .map_err(ConnectError::InvalidAddress)?;
        let offload = if vnet_features & (1 << VIRTIO_NET_F_GUEST_CSUM) != 0 {
            TUN_F_CSUM as u64
        } else {
            0
        };
        // SAFETY: the descriptor is an attached TAP and the mask only uses
        // guest checksum offload, the sole receive offload supported by v1.
        unsafe { tunsetoffload(binding.fd.as_raw_fd(), offload) }
            .map_err(|err| ConnectError::TunSetOffload(err.into()))?;
        Ok(Self { fd: binding.fd })
    }
}

impl NetBackend for Tap {
    /// Try to read a frame from the tap devie. If no bytes are available reports
    /// ReadError::NothingRead.
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        let frame_length = match read(self.fd.as_ref(), buf) {
            Ok(f) => f,
            #[allow(unreachable_patterns)]
            Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                return Err(ReadError::NothingRead);
            }
            Err(e) => {
                return Err(ReadError::Internal(e.into()));
            }
        };
        debug!("Read eth frame from tap: {frame_length} bytes");
        Ok(frame_length)
    }

    /// Try to write a frame to the tap device.
    fn write_frame(&mut self, _hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError> {
        match write(self.fd.as_ref(), buf) {
            Ok(length) if length == buf.len() => Ok(()),
            Ok(_) => Err(WriteError::Internal(io::Error::new(
                io::ErrorKind::WriteZero,
                "short TAP packet write",
            ))),
            Err(nix::errno::Errno::EAGAIN) => Err(WriteError::NothingWritten),
            Err(error) => Err(WriteError::Internal(error.into())),
        }
    }

    fn has_unfinished_write(&self) -> bool {
        false
    }

    fn try_finish_write(&mut self, _hdr_len: usize, _buf: &[u8]) -> Result<(), WriteError> {
        // The tap backend doesn't do partial writes.
        Ok(())
    }

    fn raw_socket_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
