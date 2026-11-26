// SPDX-License-Identifier: Apache-2.0
use super::{CTX_MAP, ContextConfig, clear_last_error, set_last_error, worker_pivot};
use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use vm_memory::GuestAddress;
use vmm::kernel_cow::{
    KernelCow, MAX_CHECKPOINT_BYTES, MAX_RAM_REGIONS, PreparedRam, RamLayout, import_for_worker,
};

pub(super) enum Boot {
    Source(KernelCow),
    Target {
        ram: PreparedRam,
        checkpoint: Vec<u8>,
    },
}

#[repr(C)]
pub struct KrunWorkerCowRangeV1 {
    guest_start: u64,
    size: u64,
}

fn set_io_error(error: io::Error) -> i32 {
    let code = error.raw_os_error().unwrap_or_else(|| match error.kind() {
        io::ErrorKind::Unsupported => libc::EOPNOTSUPP,
        io::ErrorKind::InvalidInput => libc::EINVAL,
        _ => libc::EIO,
    });
    set_last_error(format!("prepare Worker kernel CoW: {error}"));
    -code
}

#[unsafe(no_mangle)]
pub extern "C" fn krun_enable_worker_kernel_cow_v1(ctx_id: u32) -> i32 {
    clear_last_error();
    let mut contexts = CTX_MAP.lock().unwrap();
    let Some(ctx) = contexts.get_mut(&ctx_id) else {
        return -libc::ENOENT;
    };
    if ctx.worker_kernel_cow.is_some() {
        return -libc::EBUSY;
    }
    match KernelCow::probe() {
        Ok(kernel) => {
            ctx.worker_kernel_cow = Some(Boot::Source(kernel));
            0
        }
        Err(error) => set_io_error(error),
    }
}

/// Consume an authenticated source and prepare RAM before creating any VMM
/// threads. A later libkrun context start uses these exact mappings.
///
/// # Safety
///
/// The caller transfers an owned pidfd for the exact authorized donor held
/// through this call. The bounded input arrays must be readable throughout
/// the call. This must run in the final, single-threaded VMM process before
/// seccomp and other Guest setup. Any failure terminates that bootstrap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_import_worker_kernel_cow_v1(
    ctx_id: u32,
    donor_pidfd: i32,
    ranges: *const KrunWorkerCowRangeV1,
    range_count: usize,
    checkpoint: *const u8,
    checkpoint_len: usize,
    uid: u32,
    gid: u32,
    kvm_group: u32,
) -> i32 {
    clear_last_error();
    if donor_pidfd < 0 {
        return -libc::EINVAL;
    }
    // SAFETY: ownership transfers at entry, including when validation fails.
    let donor = unsafe { OwnedFd::from_raw_fd(donor_pidfd) };
    if ranges.is_null()
        || !ranges.is_aligned()
        || !(1..=MAX_RAM_REGIONS).contains(&range_count)
        || checkpoint.is_null()
        || !(1..=MAX_CHECKPOINT_BYTES).contains(&checkpoint_len)
    {
        return -libc::EINVAL;
    }
    let mut contexts = CTX_MAP.lock().unwrap();
    let Some(ctx) = contexts.get_mut(&ctx_id) else {
        return -libc::ENOENT;
    };
    if ctx.worker_kernel_cow.is_some() {
        return -libc::EBUSY;
    }
    // SAFETY: callers supply a valid array of the bounded size.
    let ranges = unsafe { std::slice::from_raw_parts(ranges, range_count) }
        .iter()
        .map(|range| (GuestAddress(range.guest_start), range.size as usize))
        .collect::<Vec<_>>();
    let layout = match RamLayout::new(&ranges) {
        Ok(layout) => layout,
        Err(error) => return set_io_error(error),
    };
    // SAFETY: the caller supplies the exact held donor and this is the
    // single-threaded Worker bootstrap for these target credentials.
    let ram = match unsafe {
        import_for_worker(
            donor,
            &layout,
            uid,
            gid,
            (kvm_group != 0).then_some(kvm_group),
        )
    } {
        Ok(ram) => ram,
        Err(error) => return set_io_error(error),
    };
    // SAFETY: per the contract the caller keeps this bounded buffer readable.
    // Interpret the checkpoint only after the verified drop.
    let checkpoint = unsafe { std::slice::from_raw_parts(checkpoint, checkpoint_len) }.to_vec();
    ctx.worker_kernel_cow = Some(Boot::Target { ram, checkpoint });
    0
}

pub(super) fn validate(ctx: &ContextConfig, parked_target: bool) -> Result<(), String> {
    let Some(boot) = &ctx.worker_kernel_cow else {
        return Ok(());
    };
    if ctx.snapshot_dir.is_some()
        || ctx.diskless_snapshot_ram.is_some()
        || ctx.snapshot_memory.is_some()
        || ctx.worker_statepoint.is_some()
        || ctx.vmm_gid.is_some()
        || ctx.vmm_uid.is_some()
    {
        return Err("Worker kernel CoW cannot accompany another RAM or credentials setup".into());
    }
    match boot {
        Boot::Source(_)
            if !parked_target && ctx.vmr.guest_gate && ctx.vmr.guest_identity_helper.is_some() =>
        {
            Ok(())
        }
        Boot::Source(_) => Err("Worker kernel CoW source requires its measured Guest gate".into()),
        Boot::Target { .. } if parked_target => Ok(()),
        _ => Err("Worker kernel CoW restore requires its parked target identity authority".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::IntoRawFd;

    #[test]
    fn invalid_input_consumes_descriptor_without_changing_process_credentials() {
        let (remote, local) = std::os::unix::net::UnixStream::pair().unwrap();
        let fd = remote.into_raw_fd();
        let status = unsafe {
            krun_import_worker_kernel_cow_v1(
                u32::MAX,
                fd,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                20102,
                20102,
                0,
            )
        };
        assert_eq!(status, -libc::EINVAL);
        let mut reader = io::BufReader::new(local);
        let mut data = Vec::new();
        use std::io::Read;
        reader
            .get_ref()
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        reader.read_to_end(&mut data).unwrap();
        assert!(data.is_empty());
    }
}

pub(super) fn verify_writers(
    boot: Option<&Boot>,
    resources: &mut vmm::resources::VmResources,
    pivot: Option<&worker_pivot::Config>,
    restore: Option<&worker_pivot::RestoreScope>,
) -> Result<(), String> {
    if let Some(Boot::Target { checkpoint, .. }) = boot {
        let checkpoint = vmm::VmCheckpoint::deserialize(checkpoint)?;
        resources.guest_target_writers_verified =
            worker_pivot::validate_parked_restore(pivot, restore, resources, &checkpoint, None)?;
    }
    Ok(())
}
