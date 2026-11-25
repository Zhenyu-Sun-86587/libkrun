// SPDX-License-Identifier: Apache-2.0
//! Receive identity and activation decisions exclusively on the Worker endpoint.
use super::CTX_MAP;
use devices::virtio::guest_gate::TargetScope;
use std::io;
use std::mem::size_of_val;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixDatagram;
use std::sync::{Arc, Mutex};

fn socket_value(fd: i32, option: i32) -> io::Result<i32> {
    let mut value = 0i32;
    let mut size = size_of_val(&value) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut i32).cast(),
            &mut size,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if size != size_of_val(&value) as libc::socklen_t {
        return Err(io::Error::other("bad socket option size"));
    }
    Ok(value)
}

/// # Safety
/// Anchor and context are 16 and 32 readable bytes. The caller keeps its FD.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_set_guest_target_authority_v1(
    ctx_id: u32,
    fd: i32,
    anchor: *const u8,
    context: *const u8,
    epoch: u64,
) -> i32 {
    if anchor.is_null() || context.is_null() || epoch == 0 {
        return -libc::EINVAL;
    }
    let anchor: [u8; 16] = unsafe { std::slice::from_raw_parts(anchor, 16) }
        .try_into()
        .unwrap();
    let context: [u8; 32] = unsafe { std::slice::from_raw_parts(context, 32) }
        .try_into()
        .unwrap();
    if anchor == [0; 16] || context == [0; 32] {
        return -libc::EINVAL;
    }
    let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        return -io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EBADF);
    }
    let socket = UnixDatagram::from(unsafe { OwnedFd::from_raw_fd(dup) });
    if !matches!(socket_value(dup, libc::SO_DOMAIN), Ok(libc::AF_UNIX))
        || !matches!(socket_value(dup, libc::SO_TYPE), Ok(libc::SOCK_SEQPACKET))
        || socket.peer_addr().is_err()
    {
        return -libc::ENOTSOCK;
    }
    let mut contexts = CTX_MAP.lock().unwrap();
    let Some(ctx) = contexts.get_mut(&ctx_id) else {
        return -libc::ENOENT;
    };
    if ctx.target_authority.is_some() || ctx.vmr.guest_identity_helper.is_none() {
        return -libc::EINVAL;
    }
    ctx.vmr.guest_target = Some(TargetScope {
        anchor,
        context,
        epoch,
    });
    ctx.target_authority = Some(socket);
    0
}

pub fn serve(socket: UnixDatagram, vmm: Arc<Mutex<vmm::Vmm>>) -> io::Result<()> {
    std::thread::Builder::new()
        .name("krun identity".into())
        .spawn(move || {
            let mut packet = [0u8; 194];
            loop {
                let size = unsafe {
                    libc::recv(
                        socket.as_raw_fd(),
                        packet.as_mut_ptr().cast(),
                        packet.len(),
                        libc::MSG_TRUNC,
                    )
                };
                if size == 0 {
                    break;
                }
                if size < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    break;
                }
                let response = if size as usize > packet.len() {
                    "ERR oversized".to_owned()
                } else {
                    match vmm
                        .lock()
                        .unwrap()
                        .target_identity_request(&packet[..size as usize])
                    {
                        Ok(phase) => format!("OK {phase}"),
                        Err(e) => format!("ERR {e}"),
                    }
                };
                packet.fill(0);
                if socket.send(response.as_bytes()).is_err() {
                    break;
                }
            }
        })?;
    Ok(())
}
