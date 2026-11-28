//! Linux VMM-side held block transitions. The VMM itself owns the Worker peer.

use devices::virtio::block::ImageType;
use devices::virtio::block::managed::{ManagedAttachment, ManagedLayer};
use devices::virtio::block::range::ManagedRange;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use vmm::Vmm;
use vmm::managed_block_pivot::{ManagedBlockPivot, ManagedBlockPivotError, ManagedBlockTarget};

const MAX_PACKET: usize = 64 * 1024;
const MAX_FDS: usize = 64;
const PROTOCOL: &str = "WorkerResource/1";

#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    socket: PathBuf,
    worker_uid: u32,
    bundle_digest: String,
    instance_id: String,
    incarnation_id: String,
    execution_epoch: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RestoreScope {
    operation_id: String,
    request_digest: String,
    pub(super) source_pivot_id: String,
    grant_id: String,
    expected_revision: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatePointScope {
    operation_id: String,
    request_digest: String,
    capture_id: String,
    lease_id: String,
    #[serde(default)]
    volume_restore_policy: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatePointRegion {
    gpa: u64,
    length: u64,
}

pub(super) struct PreparedStatePoint {
    pub checkpoint: Vec<u8>,
    pub generation: vmm::layered_restore::Generation,
    pub source_operation_id: String,
    pub lease_id: String,
    pub disk_identities: BTreeMap<String, String>,
}

impl PreparedStatePoint {
    pub fn verify_read_only_disks(
        &self,
        resources: &vmm::resources::VmResources,
    ) -> Result<(), String> {
        for device in &resources.block.list {
            let block = device.lock().unwrap();
            if !block.is_read_only() {
                continue;
            }
            let attachment = block
                .managed_attachment()
                .ok_or("StatePoint requires managed read-only disks")?;
            let identities = block
                .managed_backing_identities()
                .ok_or("StatePoint has no opened backing identities")?;
            if identities.len() != attachment.layers.len()
                || attachment
                    .layers
                    .iter()
                    .zip(identities)
                    .any(|(layer, (dev, ino))| {
                        self.disk_identities.get(layer) != Some(&format!("inode:{dev}:{ino}"))
                    })
            {
                return Err(
                    "read-only disk differs from its verified StatePoint generation".into(),
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Command {
    operation_id: String,
    request_digest: String,
    previous_grant_revision: i64,
    next_grant_id: String,
    destinations: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct Head {
    volume_id: String,
    head_resource_id: String,
    next_resource_id: String,
}

#[derive(Deserialize, Serialize)]
struct Receipt {
    operation_id: String,
    previous_grant_id: String,
    next_grant_id: String,
    incarnation_id: String,
    execution_epoch: u64,
    state: String,
    revision: i64,
    heads: Vec<Head>,
}

#[derive(Clone, Deserialize, Serialize)]
struct Entry {
    index: usize,
    resource_id: String,
    role: String,
}

#[derive(Deserialize)]
struct Answer {
    protocol: String,
    request_id: Option<String>,
    result: Option<Value>,
    error: Option<WorkerFault>,
    #[serde(default)]
    fd_table: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
struct WorkerFault {
    code: String,
    message: String,
}

struct Reply {
    result: Value,
    table: Vec<Entry>,
    fds: Vec<OwnedFd>,
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            && digest.bytes().any(|byte| byte != b'0')
    })
}

impl Config {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, String> {
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| "invalid Worker pivot configuration".to_string())?;
        let socket = value.socket.as_os_str().as_bytes();
        if !value.socket.is_absolute()
            || socket.len() >= 108
            || socket.contains(&0)
            || !valid_id(&value.instance_id)
            || !valid_id(&value.incarnation_id)
            || !valid_digest(&value.bundle_digest)
            || value.execution_epoch == 0
            || value.execution_epoch > i64::MAX as u64
        {
            return Err("invalid Worker pivot address or execution binding".into());
        }
        Ok(value)
    }

    fn request(
        &self,
        method: &str,
        scope: (&str, &str),
        payload: Value,
        table: &[Entry],
        fds: &[File],
    ) -> Result<Reply, WorkerFault> {
        let call = |name: &str, payload, table: &[Entry], fds: &[File]| {
            let body = json!({
                "protocol":PROTOCOL,"method":name,"request_id":name,
                "route_id":"deep","bundle_digest":self.bundle_digest,
                "expected":{"instance_id":self.instance_id,"incarnation_id":self.incarnation_id,
                    "execution_epoch":self.execution_epoch},
                "operation_id":scope.0,"request_digest":scope.1,
                "payload":payload,"fd_table":table,
            });
            transact(self, name, body, fds)
        };
        let result = call(method, payload.clone(), table, fds);
        if result
            .as_ref()
            .is_err_and(|error| error.code == "E_PERMISSION_DENIED")
            && method != "ReconcileExecution"
        {
            let identity = call("ReconcileExecution", Value::Null, &[], &[])?;
            if !identity.fds.is_empty()
                || identity.result["incarnation_id"] != self.incarnation_id
                || identity.result["execution_epoch"].as_u64() != Some(self.execution_epoch)
            {
                return Err(WorkerFault::invalid(
                    "Worker returned a different execution identity",
                ));
            }
            return call(method, payload, table, fds);
        }
        result
    }

    fn acquire_statepoint(&self, scope: &StatePointScope) -> Result<PreparedStatePoint, String> {
        let operation = (scope.operation_id.as_str(), scope.request_digest.as_str());
        let policy = scope
            .volume_restore_policy
            .as_deref()
            .unwrap_or("clone_conflicts");
        let reply = self.request("AcquireStatePointRestore", operation,
            json!({"capture_id":scope.capture_id,"lease_id":scope.lease_id,"volume_restore_policy":policy}), &[], &[])
            .map_err(|error| error.render())?;
        let lease = &reply.result["lease"];
        let resource = lease["resource_id"]
            .as_str()
            .ok_or("Worker StatePoint has no representation")?;
        let source_operation_id = reply.result["source_operation_id"]
            .as_str()
            .filter(|id| valid_id(id))
            .ok_or("Worker StatePoint has no source operation")?
            .to_owned();
        if reply.result["capture_id"] != scope.capture_id
            || reply.result["volume_restore_policy"] != policy
            || lease["lease_id"] != scope.lease_id
            || lease["incarnation_id"] != self.incarnation_id
            || lease["operation_id"] != scope.operation_id
            || lease["state"] != "pending"
            || lease["revision"].as_i64() != Some(1)
            || reply.table.len() != 2
            || reply.table[0].role != "statepoint_checkpoint"
            || reply.table[1].role != "statepoint_ram"
            || reply
                .table
                .iter()
                .any(|entry| entry.resource_id != resource)
        {
            return Err("Worker StatePoint receipt does not match the target execution".into());
        }
        let [cpu, ram]: [OwnedFd; 2] = reply
            .fds
            .try_into()
            .map_err(|_| "Worker StatePoint has an incomplete descriptor pair")?;
        let mut bytes = Vec::new();
        let length = reply.result["checkpoint_bytes"]
            .as_u64()
            .filter(|length| (1..=64 * 1024 * 1024).contains(length))
            .ok_or("Worker StatePoint checkpoint length is invalid")?;
        File::from(cpu)
            .take(length + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() as u64 != length {
            return Err("Worker StatePoint checkpoint was truncated".into());
        }
        vmm::VmCheckpoint::deserialize(&bytes)?;
        let regions: Vec<StatePointRegion> =
            serde_json::from_value(reply.result["regions"].clone())
                .map_err(|error| error.to_string())?;
        let regions: Vec<_> = regions
            .into_iter()
            .map(|region| vmm::snapshot::MemoryRegionDesc {
                gpa: region.gpa,
                len: region.length,
            })
            .collect();
        let generation = vmm::layered_restore::Generation::from_verified_statepoint_file(
            &regions,
            &File::from(ram),
        )
        .map_err(|error| error.to_string())?;
        let disk_identities = serde_json::from_value(reply.result["disk_identities"].clone())
            .map_err(|error| error.to_string())?;
        let confirmed = self
            .request(
                "AckStatePointAttached",
                operation,
                json!({"lease_id":scope.lease_id,"expected_revision":1}),
                &[],
                &[],
            )
            .map_err(|error| error.render())?;
        if !confirmed.fds.is_empty()
            || confirmed.result["lease_id"] != scope.lease_id
            || confirmed.result["resource_id"] != resource
            || confirmed.result["incarnation_id"] != self.incarnation_id
            || confirmed.result["operation_id"] != scope.operation_id
            || confirmed.result["state"] != "attached"
            || confirmed.result["revision"].as_i64() != Some(2)
        {
            return Err("Worker did not attach the recovered StatePoint lease".into());
        }
        Ok(PreparedStatePoint {
            checkpoint: bytes,
            generation,
            source_operation_id,
            lease_id: scope.lease_id.clone(),
            disk_identities,
        })
    }
}

/// Acquire a verified durable StatePoint from this context's configured Worker.
/// # Safety
/// The configuration bytes must remain readable until this call returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_configure_worker_statepoint_restore_v1(
    ctx_id: u32,
    config: *const u8,
    length: usize,
) -> i32 {
    if config.is_null() || length == 0 || length > 4096 {
        return -libc::EINVAL;
    }
    let bytes = unsafe { std::slice::from_raw_parts(config, length) };
    let Ok(scope) = serde_json::from_slice::<StatePointScope>(bytes) else {
        return -libc::EINVAL;
    };
    if !valid_id(&scope.operation_id)
        || !valid_digest(&scope.request_digest)
        || !valid_id(&scope.capture_id)
        || !valid_id(&scope.lease_id)
        || scope
            .volume_restore_policy
            .as_deref()
            .is_some_and(|policy| !matches!(policy, "exact" | "clone_conflicts"))
    {
        return -libc::EINVAL;
    }
    let config = {
        let contexts = super::CTX_MAP.lock().unwrap();
        let Some(context) = contexts.get(&ctx_id) else {
            return -libc::ENOENT;
        };
        if context.worker_statepoint.is_some()
            || context.snapshot_dir.is_some()
            || context.diskless_snapshot_ram.is_some()
            || context.snapshot_memory.is_some()
        {
            return -libc::EINVAL;
        }
        let Some(config) = context.worker_pivot.clone() else {
            return -libc::EINVAL;
        };
        config
    };
    let prepared = match config.acquire_statepoint(&scope) {
        Ok(prepared) => prepared,
        Err(error) => {
            super::set_last_error(error);
            return -libc::EINVAL;
        }
    };
    let mut contexts = super::CTX_MAP.lock().unwrap();
    let Some(context) = contexts.get_mut(&ctx_id) else {
        return -libc::ENOENT;
    };
    if context.worker_statepoint.is_some() || context.worker_pivot.as_ref() != Some(&config) {
        return -libc::EBUSY;
    }
    context.worker_statepoint = Some(prepared);
    0
}

pub(super) fn validate_parked_restore(
    config: Option<&Config>,
    scope: Option<&RestoreScope>,
    resources: &vmm::resources::VmResources,
    checkpoint: &vmm::VmCheckpoint,
    statepoint_lease: Option<&str>,
) -> Result<bool, String> {
    let (hold_token, writers) =
        vmm::managed_block_restore::preflight_restore_writers(checkpoint, resources)?;
    let Some(first) = writers.first() else {
        return Ok(false);
    };
    let hold_token = hold_token.ok_or("parked writer capture has no Worker hold token")?;
    let config = config.ok_or("writable parked restore requires a provisioned Worker endpoint")?;
    let scope = scope
        .ok_or("writable parked restore requires the exact source and target writer grants")?;
    if resources
        .guest_target
        .as_ref()
        .is_none_or(|target| target.epoch != config.execution_epoch)
    {
        return Err(
            "Worker restore execution epoch does not match the parked identity target".into(),
        );
    }
    let mut table = Vec::new();
    let mut files = Vec::new();
    let mut heads = Vec::new();
    let origin = json!({"pivot_id":scope.source_pivot_id,"hold_token":hold_token,
        "grant_id":first.source.grant_id,"execution_epoch":first.source.execution_epoch});
    let source_grant = first.source.grant_id.clone();
    let source_epoch = first.source.execution_epoch;
    for writer in writers {
        let a = writer.attachment;
        let head = a
            .writable_head_id
            .as_ref()
            .ok_or("parked writer is missing its head identity")?;
        if a.execution_epoch != config.execution_epoch
            || a.grant_id.as_ref() != Some(&scope.grant_id)
            || writer.source.grant_id != source_grant
            || writer.source.execution_epoch != source_epoch
        {
            return Err(
                "parked writable attachments do not match the source and target grants".into(),
            );
        }
        table.push(Entry {
            index: table.len(),
            resource_id: head.clone(),
            role: "block_writer".into(),
        });
        heads.push(json!({"source_volume_id":writer.source.volume_id,"volume_id":a.volume_id,
            "head_resource_id":head,"generation_id":a.generation_id,"layers":writer.layer_identities}));
        files.push(writer.file);
    }
    let reply = config
        .request(
            "ValidateRestoreWriterSet",
            (&scope.operation_id, &scope.request_digest),
            json!({"origin":origin,"grant_id":scope.grant_id,"statepoint_lease_id":statepoint_lease,
                "expected_revision":scope.expected_revision,"heads":heads}),
            &table,
            &files,
        )
        .map_err(|error| error.render())?;
    let grant = &reply.result["grant"];
    if !reply.fds.is_empty()
        || reply.result["origin"] != origin
        || reply.result["heads"] != json!(heads)
        || grant["grant_id"] != scope.grant_id
        || grant["operation_id"] != scope.operation_id
        || grant["incarnation_id"] != config.incarnation_id
        || grant["execution_epoch"].as_u64() != Some(config.execution_epoch)
        || grant["state"] != "attached"
        || grant["revision"].as_i64() != Some(scope.expected_revision)
    {
        return Err("Worker parked restore receipt does not match the installed writer set".into());
    }
    Ok(true)
}

/// Bind a parked writable restore to the completed source pivot and target's
/// actual Worker grant.
///
/// # Safety
/// The configuration bytes must remain readable until this call returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_configure_worker_block_restore_v1(
    ctx_id: u32,
    config: *const u8,
    length: usize,
) -> i32 {
    if config.is_null() || length == 0 || length > 4096 {
        return -libc::EINVAL;
    }
    let bytes = unsafe { std::slice::from_raw_parts(config, length) };
    let Ok(value) = serde_json::from_slice::<RestoreScope>(bytes) else {
        return -libc::EINVAL;
    };
    if !valid_id(&value.operation_id)
        || !valid_digest(&value.request_digest)
        || !valid_id(&value.source_pivot_id)
        || !valid_id(&value.grant_id)
        || value.expected_revision <= 0
    {
        return -libc::EINVAL;
    }
    let mut contexts = super::CTX_MAP.lock().unwrap();
    let Some(context) = contexts.get_mut(&ctx_id) else {
        return -libc::ENOENT;
    };
    context.worker_restore = Some(value);
    0
}

/// Provision the authenticated Worker scope used by this VMM's held block actor.
///
/// # Safety
/// The configuration bytes must remain readable until this call returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_configure_worker_block_pivot_v1(
    ctx_id: u32,
    config: *const u8,
    config_len: usize,
) -> i32 {
    if config.is_null() || config_len == 0 || config_len > 4096 {
        return -libc::EINVAL;
    }
    let bytes = unsafe { std::slice::from_raw_parts(config, config_len) };
    let config = match Config::parse(bytes) {
        Ok(config) => config,
        Err(error) => {
            super::set_last_error(error);
            return -libc::EINVAL;
        }
    };
    let mut contexts = super::CTX_MAP.lock().unwrap();
    let Some(context) = contexts.get_mut(&ctx_id) else {
        return -libc::ENOENT;
    };
    if context.worker_statepoint.is_some() {
        return -libc::EBUSY;
    }
    context.worker_pivot = Some(config);
    0
}

impl WorkerFault {
    fn invalid(message: &str) -> Self {
        Self {
            code: "E_PROTOCOL_UNSUPPORTED".into(),
            message: message.into(),
        }
    }

    fn transport(error: io::Error) -> Self {
        Self {
            code: "E_RESOURCED_UNAVAILABLE".into(),
            message: error.to_string(),
        }
    }

    fn render(&self) -> String {
        format!("{} {}", self.code, self.message)
    }
}

fn connect(config: &Config) -> io::Result<OwnedFd> {
    let path = config.socket.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (slot, byte) in address.sun_path.iter_mut().zip(path) {
        *slot = *byte as libc::c_char;
    }
    let length =
        (std::mem::offset_of!(libc::sockaddr_un, sun_path) + path.len() + 1) as libc::socklen_t;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let raw = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        if unsafe { libc::connect(raw, (&address as *const libc::sockaddr_un).cast(), length) } != 0
        {
            let error = io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(libc::EAGAIN | libc::EINTR))
                && Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            return Err(error);
        }
        let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&peer) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut peer as *mut libc::ucred).cast(),
                &mut length,
            )
        } != 0
            || length as usize != std::mem::size_of_val(&peer)
            || peer.uid != config.worker_uid
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unexpected Worker peer UID",
            ));
        }
        if unsafe { libc::fcntl(raw, libc::F_SETFL, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let timeout = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        for opt in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
            if unsafe {
                libc::setsockopt(
                    raw,
                    libc::SOL_SOCKET,
                    opt,
                    (&timeout as *const libc::timeval).cast(),
                    std::mem::size_of_val(&timeout) as libc::socklen_t,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        return Ok(socket);
    }
}

fn control_space(count: usize) -> usize {
    unsafe { libc::CMSG_SPACE((count * std::mem::size_of::<RawFd>()) as u32) as usize }
}

fn send(socket: RawFd, body: &[u8], files: &[File]) -> io::Result<()> {
    if body.is_empty() || body.len() > MAX_PACKET || files.len() > MAX_FDS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Worker packet exceeds the transport limit",
        ));
    }
    let mut iov = libc::iovec {
        iov_base: body.as_ptr().cast_mut().cast(),
        iov_len: body.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    let size = control_space(files.len());
    let mut ancillary = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
    if !files.is_empty() {
        message.msg_control = ancillary.as_mut_ptr().cast();
        message.msg_controllen = size;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len =
                libc::CMSG_LEN((files.len() * std::mem::size_of::<RawFd>()) as u32) as usize;
            let data = libc::CMSG_DATA(header).cast::<RawFd>();
            for (index, file) in files.iter().enumerate() {
                data.add(index).write(file.as_raw_fd());
            }
        }
    }
    let written = unsafe { libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) };
    if written < 0 {
        return Err(io::Error::last_os_error());
    }
    if written as usize != body.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "incomplete Worker request",
        ));
    }
    Ok(())
}

fn receive(socket: RawFd) -> io::Result<(Vec<u8>, Vec<OwnedFd>)> {
    let mut body = vec![0u8; MAX_PACKET];
    let mut iov = libc::iovec {
        iov_base: body.as_mut_ptr().cast(),
        iov_len: body.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    let size = control_space(MAX_FDS);
    let mut ancillary = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = size;
    let received = unsafe { libc::recvmsg(socket, &mut message, libc::MSG_CMSG_CLOEXEC) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut descriptors = Vec::new();
    let mut unexpected = false;
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let count = ((*header)
                    .cmsg_len
                    .saturating_sub(libc::CMSG_LEN(0) as usize))
                    / std::mem::size_of::<RawFd>();
                for index in 0..count {
                    descriptors.push(OwnedFd::from_raw_fd(
                        libc::CMSG_DATA(header).cast::<RawFd>().add(index).read(),
                    ));
                }
            } else {
                unexpected = true;
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    if received == 0
        || unexpected
        || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || descriptors.len() > MAX_FDS
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Worker packet or descriptor transfer",
        ));
    }
    body.truncate(received as usize);
    Ok((body, descriptors))
}

fn transact(
    config: &Config,
    method: &str,
    body: Value,
    files: &[File],
) -> Result<Reply, WorkerFault> {
    let socket = connect(config).map_err(WorkerFault::transport)?;
    send(socket.as_raw_fd(), body.to_string().as_bytes(), files).map_err(WorkerFault::transport)?;
    let (bytes, fds) = receive(socket.as_raw_fd()).map_err(WorkerFault::transport)?;
    let answer: Answer = serde_json::from_slice(&bytes)
        .map_err(|_| WorkerFault::invalid("malformed Worker result"))?;
    if answer.protocol != PROTOCOL
        || answer.request_id.as_deref() != Some(method)
        || answer.fd_table.len() != fds.len()
        || answer
            .fd_table
            .iter()
            .enumerate()
            .any(|(index, entry)| index != entry.index || !valid_id(&entry.resource_id))
    {
        return Err(WorkerFault::invalid(
            "Worker result does not match the request or descriptor table",
        ));
    }
    match (answer.result, answer.error) {
        (Some(result), None) => Ok(Reply {
            result,
            table: answer.fd_table,
            fds,
        }),
        (None, Some(error)) if fds.is_empty() => Err(error),
        _ => Err(WorkerFault::invalid("unexpected Worker result fields")),
    }
}

#[derive(Deserialize)]
struct Offer {
    pivot: Receipt,
    block_sets: Vec<BlockSet>,
    #[serde(default)]
    bucket_ranges: BTreeMap<String, u64>,
}

#[derive(Deserialize)]
struct BlockSet {
    head: BlockHead,
    layers: Vec<Layer>,
}

#[derive(Deserialize)]
struct BlockHead {
    volume_id: String,
    head_resource_id: String,
}

#[derive(Deserialize)]
struct Layer {
    resource_id: String,
    backing_id: Option<String>,
    format: String,
    capacity_bytes: u64,
}

enum Phase {
    Preparing,
    Applied {
        rollback: ManagedBlockPivot,
        offer_revision: i64,
    },
    Finalizing {
        revision: i64,
    },
    Finished(Receipt),
    Aborted(Value),
    FailedHeld,
}

struct Held {
    capture: String,
    hold_token: String,
    command: Command,
    previous_grant_id: String,
    heads: Vec<Head>,
    installed: BTreeMap<String, ManagedAttachment>,
    phase: Phase,
}

pub(super) struct Controller {
    config: Config,
    held: Option<Held>,
}

impl Controller {
    pub(super) fn new(config: Config) -> Self {
        Self { config, held: None }
    }

    pub(super) fn blocks_release(&self, verb: &str, arguments: &str) -> bool {
        self.held
            .as_ref()
            .is_some_and(|active| match &active.phase {
                Phase::Aborted(_) => false,
                Phase::Finished(_) => {
                    verb == "CAPTURE_CANCEL"
                        && arguments
                            .split_ascii_whitespace()
                            .take(2)
                            .eq(active.capture.split_ascii_whitespace())
                }
                _ => true,
            })
    }

    pub(super) fn run(
        &mut self,
        verb: &str,
        arguments: &str,
        vmm: &Arc<Mutex<Vmm>>,
    ) -> Result<String, String> {
        let (capture, token, command) = split(arguments)?;
        let actor = vmm
            .lock()
            .unwrap()
            .held_capture_control("CAPTURE_QUERY", &capture)?;
        let held: Value = serde_json::from_str(
            actor
                .strip_prefix("OK ")
                .ok_or("EIO invalid capture response")?,
        )
        .map_err(|_| "EIO invalid capture response")?;
        if held["phase"] != "prepared" || held["hold_token"] != token {
            return Err("ESTALE writer pivot requires the current held capture".into());
        }
        if let Some(active) = &self.held {
            let different = active.capture != capture || active.command != command;
            if different && !matches!(active.phase, Phase::Finished(_) | Phase::Aborted(_)) {
                return Err("EBUSY a writer pivot already owns the held capture".into());
            }
            if different && (active.capture != capture || matches!(active.phase, Phase::Aborted(_)))
            {
                self.held = None;
            } else if different {
                return Err("ESTALE a writer pivot already completed for this capture".into());
            }
        }
        if self.held.is_none() && verb == "CAPTURE_BLOCK_PIVOT_ABORT" {
            return Err("ESTALE no writer pivot is in progress".into());
        }
        if self.held.is_none() {
            self.held = Some(Held::start(vmm, &self.config, capture, token, command)?);
        }
        let active = self.held.as_mut().expect("installed held operation");
        if verb == "CAPTURE_BLOCK_PIVOT_ABORT" {
            let result = active.abort(vmm, &self.config)?;
            active.phase = Phase::Aborted(result.clone());
            return Ok(format!("OK {result}\n"));
        }
        let receipt = active.drive(vmm, &self.config)?;
        Ok(format!("OK {}\n", json!(receipt)))
    }
}

fn split(arguments: &str) -> Result<(String, String, Command), String> {
    let mut parts = arguments.splitn(3, ' ');
    let session = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or("EINVAL missing capture session")?;
    let token = parts.next().ok_or("EINVAL missing capture token")?;
    let body = parts.next().ok_or("EINVAL missing writer pivot command")?;
    let command: Command =
        serde_json::from_str(body).map_err(|_| "EINVAL malformed writer pivot command")?;
    if !valid_id(&command.operation_id)
        || !valid_digest(&command.request_digest)
        || !valid_id(&command.next_grant_id)
        || command.previous_grant_revision <= 0
        || command.destinations.is_empty()
        || command.destinations.len() > MAX_FDS
        || command
            .destinations
            .iter()
            .any(|(volume, destination)| !valid_id(volume) || !valid_id(destination))
    {
        return Err("EINVAL malformed writer pivot operation scope or destinations".into());
    }
    Ok((format!("{session} {token}"), token.into(), command))
}

impl Held {
    fn start(
        vmm: &Arc<Mutex<Vmm>>,
        config: &Config,
        capture: String,
        hold_token: String,
        command: Command,
    ) -> Result<Self, String> {
        let inventory = vmm
            .lock()
            .unwrap()
            .managed_block_inventory()
            .map_err(|e| e.to_string())?;
        let mut installed = BTreeMap::new();
        let mut grant = None;
        for device in inventory {
            let value = device.attachment;
            if value.writable_head_id.is_none() {
                continue;
            }
            if value.execution_epoch != config.execution_epoch
                || grant
                    .as_ref()
                    .is_some_and(|prior| value.grant_id.as_ref() != Some(prior))
            {
                return Err("ESTALE managed blocks do not share the expected writer grant".into());
            }
            grant = value.grant_id.clone();
            if installed.insert(value.volume_id.clone(), value).is_some() {
                return Err("EINVAL installed block set repeats a volume".into());
            }
        }
        let previous_grant_id = grant.ok_or("EINVAL held execution has no managed writer grant")?;
        if !installed.keys().eq(command.destinations.keys())
            || previous_grant_id == command.next_grant_id
        {
            return Err(
                "EINVAL writer pivot must name the exact complete installed writable set".into(),
            );
        }
        let heads = installed
            .values()
            .map(|attachment| Head {
                volume_id: attachment.volume_id.clone(),
                head_resource_id: attachment.writable_head_id.clone().unwrap(),
                next_resource_id: command.destinations[&attachment.volume_id].clone(),
            })
            .collect();
        Ok(Self {
            capture,
            hold_token,
            command,
            previous_grant_id,
            heads,
            installed,
            phase: Phase::Preparing,
        })
    }

    fn verify(&self, config: &Config, receipt: &Receipt, expected: &str) -> Result<(), String> {
        if receipt.operation_id != self.command.operation_id
            || receipt.previous_grant_id != self.previous_grant_id
            || receipt.next_grant_id != self.command.next_grant_id
            || receipt.incarnation_id != config.incarnation_id
            || receipt.execution_epoch != config.execution_epoch
            || receipt.state != expected
            || receipt.revision <= 0
            || receipt.heads != self.heads
        {
            return Err(
                "EIO Worker pivot receipt does not match the held VMM or its authorized heads"
                    .into(),
            );
        }
        Ok(())
    }

    fn targets(
        &self,
        offer: Vec<BlockSet>,
        bucket_ranges: BTreeMap<String, u64>,
        table: Vec<Entry>,
        handles: Vec<OwnedFd>,
    ) -> Result<Vec<ManagedBlockTarget>, String> {
        let mut resources = BTreeMap::new();
        let mut ranges = BTreeMap::new();
        for (entry, file) in table.into_iter().zip(handles) {
            if entry.role == "bucket_range" {
                let bytes = bucket_ranges
                    .get(&entry.resource_id)
                    .ok_or("EIO unexpected Worker range descriptor")?;
                let range = ManagedRange::new(UnixStream::from(file), *bytes)
                    .map_err(|error| error.to_string())?;
                if ranges.insert(entry.resource_id, range).is_some() {
                    return Err("EIO Worker returned duplicate range capability".into());
                }
                continue;
            }
            if resources
                .insert(entry.resource_id, (entry.role, File::from(file)))
                .is_some()
            {
                return Err("EIO Worker returned duplicate block capability".into());
            }
        }
        let mut targets = Vec::new();
        let mut used = HashSet::new();
        let mut used_ranges = HashSet::new();
        if offer.len() != self.heads.len() {
            return Err("EIO Worker returned an incomplete writable block set".into());
        }
        for (set, planned) in offer.into_iter().zip(&self.heads) {
            if set.head.volume_id != planned.volume_id
                || set.head.head_resource_id != planned.next_resource_id
                || set
                    .layers
                    .first()
                    .is_none_or(|layer| layer.resource_id != planned.next_resource_id)
            {
                return Err("EIO Worker returned a different replacement block set".into());
            }
            let mut attachment = self.installed[&planned.volume_id].clone();
            attachment.writable_head_id = Some(planned.next_resource_id.clone());
            attachment.generation_id = planned.head_resource_id.clone();
            attachment.grant_id = Some(self.command.next_grant_id.clone());
            attachment.layers = set
                .layers
                .iter()
                .map(|layer| layer.resource_id.clone())
                .collect();
            let mut layers = Vec::new();
            for (index, layer) in set.layers.iter().enumerate() {
                let expected_backing = set.layers.get(index + 1).map(|next| &next.resource_id);
                if layer.backing_id.as_ref() != expected_backing
                    || layer.capacity_bytes != attachment.capacity_bytes
                {
                    return Err(
                        "EIO Worker returned a changed block capacity or backing chain".into(),
                    );
                }
                let (role, file) = resources
                    .get(&layer.resource_id)
                    .ok_or("EIO missing Worker block capability")?;
                if role
                    != if index == 0 {
                        "block_writer"
                    } else {
                        "block_ancestor"
                    }
                {
                    return Err("EIO Worker block capability has the wrong role".into());
                }
                used.insert(layer.resource_id.clone());
                let format = match layer.format.as_str() {
                    "raw" => ImageType::Raw,
                    "qcow2" => ImageType::Qcow2,
                    _ => return Err("EIO Worker returned an unsupported block format".into()),
                };
                let range = ranges.get(&layer.resource_id);
                if let Some(range) = range {
                    if index == 0
                        || file.metadata().map_err(|e| e.to_string())?.len() != range.size()
                    {
                        return Err("EIO Worker range differs from its immutable backing".into());
                    }
                    used_ranges.insert(layer.resource_id.clone());
                }
                layers.push(ManagedLayer {
                    resource_id: layer.resource_id.clone(),
                    format,
                    file: file.try_clone().map_err(|e| e.to_string())?,
                    range: range.cloned(),
                });
            }
            targets.push(ManagedBlockTarget { attachment, layers });
        }
        if used.len() != resources.len()
            || used_ranges.len() != ranges.len()
            || used_ranges.len() != bucket_ranges.len()
        {
            return Err("EIO Worker returned unreferenced descriptors".into());
        }
        Ok(targets)
    }

    fn writer_proof(&self, vmm: &Arc<Mutex<Vmm>>) -> Result<(Vec<Entry>, Vec<File>), String> {
        let current = vmm
            .lock()
            .unwrap()
            .managed_block_inventory()
            .map_err(|e| e.to_string())?;
        let mut current: BTreeMap<_, _> = current
            .into_iter()
            .filter(|item| item.writer.is_some())
            .map(|item| (item.attachment.volume_id.clone(), item))
            .collect();
        let mut table = Vec::new();
        let mut descriptors = Vec::new();
        for head in &self.heads {
            let disk = current
                .remove(&head.volume_id)
                .ok_or("EIO replacement block disappeared")?;
            if disk.attachment.writable_head_id.as_ref() != Some(&head.next_resource_id)
                || disk.attachment.grant_id.as_ref() != Some(&self.command.next_grant_id)
            {
                return Err("EIO live device does not hold the authorized replacement".into());
            }
            table.push(Entry {
                index: descriptors.len(),
                resource_id: head.next_resource_id.clone(),
                role: "block_writer".into(),
            });
            descriptors.push(disk.writer.expect("filtered writer"));
        }
        if !current.is_empty() {
            return Err("EIO live device inventory contains unexpected writers".into());
        }
        Ok((table, descriptors))
    }

    fn update(
        &self,
        config: &Config,
        method: &str,
        revision: i64,
        table: &[Entry],
        files: &[File],
    ) -> Result<Receipt, String> {
        let reply = config
            .request(
                method,
                (&self.command.operation_id, &self.command.request_digest),
                json!({
                    "expected_revision":revision, "hold_token":self.hold_token,
                }),
                table,
                files,
            )
            .map_err(|e| e.render())?;
        if !reply.fds.is_empty() {
            return Err("EIO unexpected descriptors in WriterPivot decision".into());
        }
        serde_json::from_value(reply.result)
            .map_err(|_| "EIO malformed WriterPivot decision".into())
    }

    fn drive(&mut self, vmm: &Arc<Mutex<Vmm>>, config: &Config) -> Result<&Receipt, String> {
        if matches!(self.phase, Phase::Preparing) {
            let response = config.request("PrepareWriterPivot", (&self.command.operation_id, &self.command.request_digest), json!({
                "previous_grant_id":self.previous_grant_id,"previous_grant_revision":self.command.previous_grant_revision,
                "next_grant_id":self.command.next_grant_id,"hold_token":self.hold_token,"heads":self.heads,
            }), &[], &[]).map_err(|e| e.render())?;
            let offer: Offer = serde_json::from_value(response.result)
                .map_err(|_| "EIO invalid WriterPivot offer")?;
            self.verify(config, &offer.pivot, "offered")?;
            let targets = self.targets(
                offer.block_sets,
                offer.bucket_ranges,
                response.table,
                response.fds,
            )?;
            let result = vmm.lock().unwrap().pivot_managed_blocks_held(targets);
            match result {
                Ok(rollback) => {
                    self.phase = Phase::Applied {
                        rollback,
                        offer_revision: offer.pivot.revision,
                    }
                }
                Err(error) => {
                    if matches!(error, ManagedBlockPivotError::RollbackFailed { .. }) {
                        self.phase = Phase::FailedHeld;
                    }
                    return Err(error.to_string());
                }
            }
        }
        if let Phase::Applied { offer_revision, .. } = &self.phase {
            let (table, files) = self.writer_proof(vmm)?;
            let decision =
                self.update(config, "CommitWriterPivot", *offer_revision, &table, &files)?;
            self.verify(config, &decision, "commit")?;
            if offer_revision.checked_add(1) != Some(decision.revision) {
                return Err("EIO unexpected WriterPivot commit revision".into());
            }
            let previous = std::mem::replace(
                &mut self.phase,
                Phase::Finalizing {
                    revision: decision.revision,
                },
            );
            if let Phase::Applied { rollback, .. } = previous {
                rollback.commit();
            }
        }
        if let Phase::Finalizing { revision } = &self.phase {
            let (table, files) = self.writer_proof(vmm)?;
            let receipt = self.update(config, "FinalizeWriterPivot", *revision, &table, &files)?;
            self.verify(config, &receipt, "complete")?;
            if revision.checked_add(1) != Some(receipt.revision) {
                return Err("EIO unexpected WriterPivot finalization revision".into());
            }
            let transitions: Vec<_> = receipt
                .heads
                .iter()
                .map(|head| vmm::managed_block_restore::ParkedWriterTransition {
                    volume_id: head.volume_id.clone(),
                    previous_head: head.head_resource_id.clone(),
                    next_head: head.next_resource_id.clone(),
                })
                .collect();
            vmm.lock().unwrap().record_held_block_commit(
                &self.capture,
                &receipt.previous_grant_id,
                &receipt.next_grant_id,
                &transitions,
            )?;
            self.phase = Phase::Finished(receipt);
        }
        match &self.phase {
            Phase::Finished(receipt) => Ok(receipt),
            Phase::Aborted(_) => Err("ESTALE writer pivot was aborted".into()),
            _ => Err("EBUSY writer pivot remains held".into()),
        }
    }

    fn abort(&mut self, vmm: &Arc<Mutex<Vmm>>, config: &Config) -> Result<Value, String> {
        if let Phase::Aborted(receipt) = &self.phase {
            return Ok(receipt.clone());
        }
        if matches!(
            self.phase,
            Phase::Finalizing { .. } | Phase::Finished(_) | Phase::FailedHeld
        ) {
            return Err("EBUSY writer pivot cannot roll back after the durable decision or a rollback failure".into());
        }
        let reply = match config.request(
            "QueryWriterPivot",
            (&self.command.operation_id, &self.command.request_digest),
            Value::Null,
            &[],
            &[],
        ) {
            Err(error) if error.code == "E_NOT_FOUND" && matches!(self.phase, Phase::Preparing) => {
                return Ok(json!({"state":"aborted","operation_id":self.command.operation_id}));
            }
            Err(error) => return Err(error.render()),
            Ok(reply) => reply,
        };
        if !reply.fds.is_empty() {
            return Err("EIO unexpected descriptors in WriterPivot query".into());
        }
        let receipt: Receipt =
            serde_json::from_value(reply.result).map_err(|_| "EIO malformed WriterPivot query")?;
        if !matches!(receipt.state.as_str(), "preparing" | "offered" | "aborted") {
            return Err("EBUSY Worker has already committed the writer pivot".into());
        }
        self.verify(config, &receipt, &receipt.state)?;
        if let Phase::Applied { rollback, .. } = &mut self.phase {
            if let Err(error) = vmm.lock().unwrap().rollback_managed_blocks_held(rollback) {
                self.phase = Phase::FailedHeld;
                return Err(error.to_string());
            }
            self.phase = Phase::Preparing;
        }
        if receipt.state == "aborted" {
            return Ok(json!(receipt));
        }
        let aborted = self.update(config, "AbortWriterPivot", receipt.revision, &[], &[])?;
        self.verify(config, &aborted, "aborted")?;
        Ok(json!(aborted))
    }
}
