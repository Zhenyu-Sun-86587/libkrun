// SPDX-License-Identifier: Apache-2.0

//! Anonymous 4 KiB RAM for the Linux/x86_64 Worker CoW ABI.
//!
//! This module owns only the RAM mapping. Callers must separately capture and
//! restore CPU, device and disk state, and hold all Guest RAM writers during
//! import. Eligibility here is not a product Fork capability.

use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;

use vm_memory::mmap::{GuestRegionMmap, MmapRegion};
use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

const ABI_MARKER: &str = "/sys/kernel/smolvm_cow/abi";
const ABI_ID: &str = "smolvm_cow_v1";
const LAYOUT_SHA256: &str = "03e38c51fd9ac381993e22a9e9116060a0d867f39da57de3b717a2c6fa3a37a2";
const QUERY: libc::c_uint = 0;
const IMPORT: libc::c_uint = 1;
const REQUIRED_FEATURES: u32 = 0b11; // Strict no copy and private anonymous 4 KiB memory.
const PAGE: usize = 4096;
const HOST_BASE: usize = 0x4000_0000_0000;
const HOST_LIMIT: usize = 0x4800_0000_0000;
pub const MAX_RAM_REGIONS: usize = 64;
pub const MAX_CHECKPOINT_BYTES: usize = 64 << 20;
const RAM_PROT: libc::c_int = libc::PROT_READ | libc::PROT_WRITE;
const RAM_FLAGS: libc::c_int = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;

#[repr(C)]
#[derive(Default)]
struct Query {
    version: u32,
    features: u32,
    import_size: u32,
    page_size: u32,
    reserved: [u64; 4],
}

#[repr(C)]
struct Import {
    source_pidfd: i32,
    flags: u32,
    address: u64,
    length: u64,
    reserved: [u64; 4],
}

const _: () = assert!(size_of::<Query>() == 48 && size_of::<Import>() == 56);

fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

/// One exact kernel build contract. The syscall number is discovered rather
/// than invoked on the basis of a Linux version or a caller-supplied number.
#[derive(Clone, Copy)]
pub struct KernelCow(libc::c_long);

impl KernelCow {
    pub fn probe() -> io::Result<Self> {
        let mut source = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(ABI_MARKER)
            .map_err(|err| {
                if err.kind() == io::ErrorKind::NotFound {
                    unsupported("the Worker does not expose smolvm_cow_v1")
                } else {
                    err
                }
            })?;
        let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: source is open and fs points to writable statfs storage.
        if unsafe { libc::fstatfs(source.as_raw_fd(), fs.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful fstatfs initialized fs.
        if i128::from(unsafe { fs.assume_init() }.f_type) != i128::from(libc::SYSFS_MAGIC) {
            return Err(unsupported("the CoW ABI marker is not in sysfs"));
        }
        let mut marker = String::new();
        source.by_ref().take(257).read_to_string(&mut marker)?;
        if marker.len() > 256 {
            return Err(unsupported("the CoW ABI marker is oversized"));
        }
        let nr = parse_marker(&marker)?;
        let mut reply = Query::default();
        // SAFETY: nr came from the matching kernel's sysfs ABI marker. QUERY
        // writes only the provided repr(C) object.
        let status = unsafe { libc::syscall(nr, QUERY, &raw mut reply, size_of::<Query>()) };
        syscall_result(status)?;
        // SAFETY: sysconf has no pointer arguments.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if reply.version != 1
            || reply.features & REQUIRED_FEATURES != REQUIRED_FEATURES
            || reply.import_size as usize != size_of::<Import>()
            || reply.page_size as usize != PAGE
            || page_size != PAGE as libc::c_long
            || reply.reserved != [0; 4]
        {
            return Err(unsupported("incompatible Worker CoW QUERY response"));
        }
        Ok(Self(nr))
    }

    /// Allocate a fresh, fixed-address anonymous RAM topology for a potential
    /// source VMM. Every entry is an entire VMA with a gap on either side.
    pub fn allocate(&self, layout: &RamLayout) -> io::Result<GuestMemoryMmap> {
        assemble(layout, |range| Mapping::reserve(range, RAM_PROT))
    }

    /// Import an already held source into this same process. Each completed
    /// mapping belongs to the returned guest memory and survives donor exit.
    /// A failed import drops every mapping created by this call.
    ///
    /// # Safety
    ///
    /// The caller must own or have been granted this exact donor execution,
    /// verify its RAM layout matches the supplied profile, keep all its RAM
    /// writers held until return, and pass a process pidfd acquired while that
    /// execution was live. A successful import does not acquire any other part
    /// of a captured VM.
    pub unsafe fn import_held(
        &self,
        donor: BorrowedFd<'_>,
        layout: &RamLayout,
    ) -> io::Result<PreparedRam> {
        assemble(layout, |range| {
            let mut mapping = Mapping::reserve(range, libc::PROT_NONE)?;
            let request = Import {
                source_pidfd: donor.as_raw_fd(),
                flags: 0,
                address: range.host as u64,
                length: range.length as u64,
                reserved: [0; 4],
            };
            // SAFETY: the caller owns the held donor, the pidfd remains valid,
            // and the exact destination belongs exclusively to mapping.
            let status =
                unsafe { libc::syscall(self.0, IMPORT, &raw const request, size_of::<Import>()) };
            syscall_result(status)?;
            // The source may be a read-only anchor. Restore write permission
            // through Linux's normal protections so its CoW PTEs stay intact.
            mapping.set_protection(RAM_PROT)?;
            Ok(mapping)
        })
        .map(PreparedRam)
    }
}

/// Owns imported RAM in the VMM's current address space. It cannot be
/// serialized or transferred across exec or converted to a file descriptor.
pub struct PreparedRam(GuestMemoryMmap);

impl PreparedRam {
    pub fn memory(&self) -> &GuestMemoryMmap {
        &self.0
    }

    pub(crate) fn into_memory(self) -> GuestMemoryMmap {
        self.0
    }
}

/// Import RAM in the final Worker VMM process before it assumes the target's
/// dedicated credentials. The source pidfd is closed before privileges are
/// dropped. A QUERY or IMPORT failure still goes through the credential drop.
///
/// # Safety
///
/// The requirements of [`KernelCow::import_held`] apply. Call this once in the
/// final, single-threaded bootstrap with only the target's authorized KVM
/// group (if needed). Terminate the bootstrap on any failure.
pub unsafe fn import_for_worker(
    donor: OwnedFd,
    layout: &RamLayout,
    target_uid: libc::uid_t,
    target_gid: libc::gid_t,
    kvm_group: Option<libc::gid_t>,
) -> io::Result<PreparedRam> {
    if target_uid == 0 || target_gid == 0 || kvm_group == Some(0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Worker CoW requires a non-root target identity and KVM group",
        ));
    }
    let mut threads = std::fs::read_dir("/proc/self/task")?;
    if threads.next().transpose()?.is_none() || threads.next().transpose()?.is_some() {
        return Err(io::Error::other(
            "Worker CoW bootstrap must be single-threaded",
        ));
    }
    drop(threads);
    // SAFETY: this changes process attributes in the single-threaded bootstrap.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    const PTRACE: u32 = 1 << 19;
    const SET_IDS: u32 = (1 << 6) | (1 << 7);
    set_worker_capabilities(PTRACE, PTRACE | SET_IDS)?;
    let prepared = KernelCow::probe().and_then(|kernel| {
        // SAFETY: the caller is responsible for authentication and the held cut.
        unsafe { kernel.import_held(donor.as_fd(), layout) }
    });
    drop(donor);
    set_worker_capabilities(SET_IDS, SET_IDS)?;
    drop_worker_credentials(target_uid, target_gid, kvm_group)?;
    prepared
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::pid_t,
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

impl CapHeader {
    fn current() -> Self {
        Self {
            version: 0x2008_0522, // _LINUX_CAPABILITY_VERSION_3
            pid: 0,
        }
    }
}

fn set_worker_capabilities(effective: u32, permitted: u32) -> io::Result<()> {
    let data = [
        CapData {
            effective,
            permitted,
            inheritable: 0,
        },
        CapData::default(),
    ];
    // SAFETY: this is the v3 capability layout of the calling thread.
    if unsafe { libc::syscall(libc::SYS_capset, &CapHeader::current(), data.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn drop_worker_credentials(
    uid: libc::uid_t,
    gid: libc::gid_t,
    kvm_group: Option<libc::gid_t>,
) -> io::Result<()> {
    let groups = kvm_group.as_slice();
    // SAFETY: valid group slice and scalar prctl/credential arguments. All
    // calls occur before the trusted bootstrap starts VMM threads.
    if unsafe {
        libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) != 0
            || libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            ) != 0
            || libc::setgroups(groups.len(), groups.as_ptr()) != 0
            || libc::setresgid(gid, gid, gid) != 0
            || libc::setresuid(uid, uid, uid) != 0
    } {
        return Err(io::Error::last_os_error());
    }
    set_worker_capabilities(0, 0)?;
    let mut header = CapHeader::current();
    let zero = [CapData::default(); 2];
    let mut current = zero;
    let (mut real_uid, mut effective_uid, mut saved_uid) = (0, 0, 0);
    let (mut real_gid, mut effective_gid, mut saved_gid) = (0, 0, 0);
    // SAFETY: capget receives two writable v3 capability words.
    // getresuid/getresgid receive writable outputs of their declared sizes.
    if unsafe {
        libc::syscall(libc::SYS_capget, &mut header, current.as_mut_ptr()) != 0
            || libc::getresuid(&mut real_uid, &mut effective_uid, &mut saved_uid) != 0
            || libc::getresgid(&mut real_gid, &mut effective_gid, &mut saved_gid) != 0
    } {
        return Err(io::Error::last_os_error());
    }
    if [real_uid, effective_uid, saved_uid] != [uid; 3]
        || [real_gid, effective_gid, saved_gid] != [gid; 3]
        || current != zero
    {
        return Err(io::Error::other(
            "Worker CoW credential drop was incomplete",
        ));
    }
    Ok(())
}

fn syscall_result(status: libc::c_long) -> io::Result<()> {
    match status {
        0 => Ok(()),
        -1 => Err(io::Error::last_os_error()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected result from strict CoW ABI",
        )),
    }
}

fn parse_marker(marker: &str) -> io::Result<libc::c_long> {
    let mut lines = marker.lines();
    if lines.next().and_then(|line| line.strip_prefix("abi_id=")) != Some(ABI_ID) {
        return Err(unsupported("unrecognized Worker CoW ABI"));
    }
    let nr = lines
        .next()
        .and_then(|line| line.strip_prefix("syscall_nr="))
        .filter(|value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|value| value.parse::<libc::c_long>().ok())
        .filter(|value| (1..=1023).contains(value))
        .ok_or_else(|| unsupported("invalid Worker CoW syscall number"))?;
    if lines
        .next()
        .and_then(|line| line.strip_prefix("layout_sha256="))
        != Some(LAYOUT_SHA256)
        || lines.next().is_some()
    {
        return Err(unsupported("incompatible Worker CoW header digest"));
    }
    Ok(nr)
}

#[derive(Clone, Copy, Debug)]
struct Range {
    guest: GuestAddress,
    host: usize,
    length: usize,
}

/// Deterministic private anonymous layout. Region boundaries and sizes are
/// part of the profile and must match during capture and restore.
#[derive(Clone, Debug)]
pub struct RamLayout(Vec<Range>);

impl RamLayout {
    pub fn new(regions: &[(GuestAddress, usize)]) -> io::Result<Self> {
        let invalid =
            || io::Error::new(io::ErrorKind::InvalidInput, "invalid fixed CoW RAM layout");
        if regions.is_empty() || regions.len() > MAX_RAM_REGIONS {
            return Err(invalid());
        }
        let mut previous_end = 0_u64;
        let mut ranges = Vec::with_capacity(regions.len());
        for (index, &(guest, length)) in regions.iter().enumerate() {
            let gpa = guest.raw_value();
            if !gpa.is_multiple_of(PAGE as u64)
                || length == 0
                || !length.is_multiple_of(PAGE)
                || gpa < previous_end
            {
                return Err(invalid());
            }
            previous_end = gpa.checked_add(length as u64).ok_or_else(invalid)?;
            let host = HOST_BASE
                .checked_add(gpa as usize)
                .and_then(|base| base.checked_add(index * PAGE))
                .filter(|base| {
                    base.checked_add(length)
                        .is_some_and(|end| end <= HOST_LIMIT)
                })
                .ok_or_else(invalid)?;
            ranges.push(Range {
                guest,
                host,
                length,
            });
        }
        Ok(Self(ranges))
    }

    /// The guest ranges required to reconstruct this fixed layout in the
    /// target. Host addresses are derived from the validated layout profile.
    pub fn regions(&self) -> impl Iterator<Item = (GuestAddress, usize)> + '_ {
        self.0.iter().map(|range| (range.guest, range.length))
    }

    pub(crate) fn matches(&self, memory: &GuestMemoryMmap) -> bool {
        memory.num_regions() == self.0.len()
            && memory.iter().zip(&self.0).all(|(region, expected)| {
                region.start_addr() == expected.guest
                    && region.len() == expected.length as u64
                    && region.file_offset().is_none()
                    && memory
                        .get_host_address(expected.guest)
                        .is_ok_and(|host| host as usize == expected.host)
            })
    }

    pub(crate) fn from_fixed_memory(memory: &GuestMemoryMmap) -> io::Result<Self> {
        let regions = memory
            .iter()
            .map(|region| (region.start_addr(), region.len() as usize))
            .collect::<Vec<_>>();
        let layout = Self::new(&regions)?;
        if !layout.matches(memory) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "source RAM does not match the fixed anonymous CoW profile",
            ));
        }
        Ok(layout)
    }
}

fn assemble(
    layout: &RamLayout,
    mut map: impl FnMut(Range) -> io::Result<Mapping>,
) -> io::Result<GuestMemoryMmap> {
    let regions = layout
        .0
        .iter()
        .map(|&range| {
            GuestRegionMmap::new(map(range)?.into_region()?, range.guest)
                .ok_or_else(|| io::Error::other("invalid guest RAM region"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    GuestMemoryMmap::from_regions(regions).map_err(io::Error::other)
}

struct Mapping {
    pointer: *mut libc::c_void,
    length: usize,
}

impl Mapping {
    fn reserve(range: Range, protection: libc::c_int) -> io::Result<Self> {
        // SAFETY: addresses come from the bounded profile, and NOREPLACE
        // forbids overwriting any existing mapping.
        let pointer = unsafe {
            libc::mmap(
                range.host as *mut libc::c_void,
                range.length,
                protection,
                RAM_FLAGS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let mapping = Self {
            pointer,
            length: range.length,
        };
        if pointer as usize != range.host {
            return Err(unsupported("the Worker did not honor MAP_FIXED_NOREPLACE"));
        }
        // SAFETY: this freshly reserved mapping belongs exclusively to mapping.
        if unsafe { libc::madvise(pointer, range.length, libc::MADV_NOHUGEPAGE) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(mapping)
    }

    fn set_protection(&mut self, protection: libc::c_int) -> io::Result<()> {
        // SAFETY: this mapping is live and exclusively owned by self.
        if unsafe { libc::mprotect(self.pointer, self.length, protection) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn into_region(self) -> io::Result<MmapRegion> {
        // SAFETY: the mapping is live and self is the only owner. On success
        // MmapRegion assumes that ownership. On error self still unmaps it.
        let region = unsafe {
            MmapRegion::build_raw_owned(self.pointer.cast(), self.length, RAM_PROT, RAM_FLAGS)
        }
        .map_err(io::Error::other)?;
        std::mem::forget(self);
        Ok(region)
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: the owner has not transferred or unmapped this range.
        unsafe { libc::munmap(self.pointer, self.length) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_requires_exact_layout_before_using_discovered_number() {
        let good = format!("abi_id={ABI_ID}\nsyscall_nr=500\nlayout_sha256={LAYOUT_SHA256}\n");
        assert_eq!(parse_marker(&good).unwrap(), 500);
        assert!(parse_marker(&good.replace("500", "0")).is_err());
        assert!(parse_marker(&good.replace(LAYOUT_SHA256, "other")).is_err());
        assert!(parse_marker(&(good + "unrecognized=value\n")).is_err());
    }

    #[test]
    fn layout_validates_vm_boundaries_and_keeps_regions_separate() {
        let layout =
            RamLayout::new(&[(GuestAddress(0), PAGE), (GuestAddress(PAGE as u64), PAGE)]).unwrap();
        assert_eq!(layout.0[1].host - layout.0[0].host, PAGE * 2);
        assert!(RamLayout::new(&[(GuestAddress(1), PAGE)]).is_err());
        assert!(RamLayout::new(&[(GuestAddress(0), 0)]).is_err());
        assert!(RamLayout::new(&[(GuestAddress(0), PAGE), (GuestAddress(0), PAGE)]).is_err());
        assert!(RamLayout::new(&[(GuestAddress(u64::MAX & !(PAGE as u64 - 1)), PAGE)]).is_err());
    }

    #[test]
    fn partial_allocation_drops_earlier_mappings() {
        let layout =
            RamLayout::new(&[(GuestAddress(0), PAGE), (GuestAddress(PAGE as u64), PAGE)]).unwrap();
        let occupied = Mapping::reserve(layout.0[1], RAM_PROT).unwrap();
        assert_eq!(
            assemble(&layout, |range| Mapping::reserve(range, RAM_PROT))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EEXIST)
        );
        let again = Mapping::reserve(layout.0[0], RAM_PROT).unwrap();
        drop((again, occupied));
    }
}
