// SPDX-License-Identifier: Apache-2.0
use super::{CTX_MAP, ContextConfig, clear_last_error, set_last_error, worker_pivot};
use std::io;
use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd};
use std::slice;
use std::sync::Mutex;
use vm_memory::GuestAddress;
use vmm::kernel_cow::{
    KernelCow, MAX_CHECKPOINT_BYTES, MAX_RAM_REGIONS, PreparedRam, RamLayout, ReadOnlyAnchor,
    import_anchor_for_worker, import_for_worker,
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

static ANCHOR: Mutex<Option<ReadOnlyAnchor>> = Mutex::new(None);

fn set_io_error(error: io::Error) -> i32 {
    let code = error.raw_os_error().unwrap_or_else(|| match error.kind() {
        io::ErrorKind::Unsupported => libc::EOPNOTSUPP,
        io::ErrorKind::InvalidInput => libc::EINVAL,
        _ => libc::EIO,
    });
    set_last_error(format!("Worker kernel CoW: {error}"));
    -code
}

#[unsafe(no_mangle)]
pub extern "C" fn krun_probe_worker_kernel_cow_v1() -> i32 {
    clear_last_error();
    KernelCow::probe().map_or_else(set_io_error, |_| 0)
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
            if let Err(error) = kernel.prohibit_import() {
                return set_io_error(error);
            }
            ctx.worker_kernel_cow = Some(Boot::Source(kernel));
            0
        }
        Err(error) => set_io_error(error),
    }
}

/// The caller supplies a readable `range_count`-element array for this call.
unsafe fn worker_layout(
    ranges: *const KrunWorkerCowRangeV1,
    range_count: usize,
) -> Result<RamLayout, i32> {
    if ranges.is_null() || !ranges.is_aligned() || !(1..=MAX_RAM_REGIONS).contains(&range_count) {
        return Err(-libc::EINVAL);
    }
    // SAFETY: caller supplies the bounded input array.
    let ranges = unsafe { slice::from_raw_parts(ranges, range_count) }
        .iter()
        .map(|range| (GuestAddress(range.guest_start), range.size as usize))
        .collect::<Vec<_>>();
    RamLayout::new(&ranges).map_err(set_io_error)
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
    if checkpoint.is_null() || !(1..=MAX_CHECKPOINT_BYTES).contains(&checkpoint_len) {
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
    let layout = match unsafe { worker_layout(ranges, range_count) } {
        Ok(layout) => layout,
        Err(code) => return code,
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
    let checkpoint = unsafe { slice::from_raw_parts(checkpoint, checkpoint_len) }.to_vec();
    ctx.worker_kernel_cow = Some(Boot::Target { ram, checkpoint });
    0
}

/// Retain one read-only capture in the dedicated final anchor process.
///
/// # Safety
/// The Worker transfers an owned pidfd of its exact authenticated held donor.
/// The input array must be readable and refer to that cut. Call before starting
/// any threads or installing the sandbox, and terminate the bootstrap on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_import_worker_kernel_cow_anchor_v1(
    donor_pidfd: i32,
    ranges: *const KrunWorkerCowRangeV1,
    range_count: usize,
    uid: u32,
    gid: u32,
) -> i32 {
    clear_last_error();
    if donor_pidfd < 0 {
        return -libc::EINVAL;
    }
    // SAFETY: ownership transfers at entry, including on validation failure.
    let donor = unsafe { OwnedFd::from_raw_fd(donor_pidfd) };
    // SAFETY: the caller provides the bounded input array.
    let layout = match unsafe { worker_layout(ranges, range_count) } {
        Ok(layout) => layout,
        Err(code) => return code,
    };
    let mut retained = ANCHOR.lock().unwrap();
    if retained.is_some() {
        return -libc::EBUSY;
    }
    // SAFETY: the caller proves the exact held donor and bootstrap scope.
    match unsafe { import_anchor_for_worker(donor, &layout, uid, gid) } {
        Ok(anchor) => {
            *retained = Some(anchor);
            0
        }
        Err(error) => set_io_error(error),
    }
}

/// Stream the retained anchor in guest-region order.
///
/// # Safety
/// The caller supplies a live, writable output descriptor for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_write_worker_kernel_cow_anchor_v1(fd: i32) -> i32 {
    clear_last_error();
    if fd < 0 {
        return -libc::EINVAL;
    }
    let retained = ANCHOR.lock().unwrap();
    let Some(anchor) = retained.as_ref() else {
        return -libc::ENOENT;
    };
    // SAFETY: the output remains open and owned by the caller.
    let output = unsafe { BorrowedFd::borrow_raw(fd) };
    anchor.write_to(output).map_or_else(set_io_error, |_| 0)
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

    #[cfg(not(feature = "aws-nitro"))]
    #[test]
    fn block_root_api_marks_the_virtual_bootstrap_after_other_shares() {
        use crate::{
            krun_add_disk, krun_add_virtiofs, krun_create_ctx, krun_free_ctx,
            krun_set_root_disk_remount,
        };
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use utils::tempfile::TempFile;

        let disk = TempFile::new().unwrap();
        disk.as_file().set_len(4096).unwrap();
        let path = CString::new(disk.as_path().as_os_str().as_bytes()).unwrap();
        let id = u32::try_from(krun_create_ctx()).unwrap();
        // SAFETY: each argument is a C string valid throughout its call.
        unsafe {
            assert_eq!(
                krun_add_virtiofs(id, c"extra".as_ptr(), c"/tmp".as_ptr()),
                0
            );
            assert_eq!(krun_add_disk(id, c"root".as_ptr(), path.as_ptr(), false), 0);
            assert_eq!(
                krun_set_root_disk_remount(
                    id,
                    c"/dev/vda".as_ptr(),
                    c"ext4".as_ptr(),
                    c"rw".as_ptr()
                ),
                0
            );
        }
        {
            let contexts = CTX_MAP.lock().unwrap();
            let resources = &contexts[&id].vmr;
            assert_eq!(resources.block_bootstrap_fs, Some(1));
            assert!(resources.fs[0].shared_dir.is_some());
            assert_eq!(resources.fs[1].fs_id, "/dev/root");
            assert!(resources.fs[1].shared_dir.is_none());
        }
        assert_eq!(krun_free_ctx(id), 0);
    }

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
