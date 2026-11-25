// Copyright 2026. SPDX-License-Identifier: Apache-2.0

use super::{CTX_MAP, KRUN_SUCCESS, set_last_error};
use devices::virtio::block::managed::{ManagedAttachment, ManagedLayer};
use devices::virtio::block::{Block, ImageType};
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::{CStr, c_char};
use std::fs::File;
use std::io;
use std::os::fd::FromRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::{Arc, Mutex};

const MAX_DEVICES: usize = 64;
const MAX_CLOSURE_DEPTH: usize = 64;
const MAX_REFERENCED_FDS: usize = 64;

#[repr(C)]
pub struct KrunManagedBlockLayerV1 {
    resource_id: *const c_char,
    fd: i32,
    format: u32,
}

#[repr(C)]
pub struct KrunManagedBlockV1 {
    size: u32,
    version: u32,
    attachment_id: *const c_char,
    device_id: *const c_char,
    role: *const c_char,
    volume_id: *const c_char,
    generation_id: *const c_char,
    writable_head_id: *const c_char,
    grant_id: *const c_char,
    execution_epoch: u64,
    capacity_bytes: u64,
    layers: *const KrunManagedBlockLayerV1,
    layer_count: usize,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

unsafe fn identifier(id: *const c_char) -> io::Result<String> {
    if id.is_null() {
        return Err(invalid("missing block attachment identifier"));
    }
    let value = unsafe { CStr::from_ptr(id) }.to_bytes();
    if value.is_empty()
        || value.len() > 128
        || !value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(byte))
        || value == b"."
        || value == b".."
    {
        return Err(invalid("invalid block attachment identifier"));
    }
    Ok(String::from_utf8(value.to_vec()).expect("validated ASCII identifier"))
}

unsafe fn prepare_specs(specs: &[KrunManagedBlockV1]) -> io::Result<VecDeque<Arc<Mutex<Block>>>> {
    let mut devices = HashSet::new();
    let mut attachments = HashSet::new();
    let mut volumes = HashSet::new();
    let mut handles = HashSet::new();
    let mut identities = HashMap::new();
    let mut resources = HashMap::new();
    let mut grant = None;
    let mut blocks = VecDeque::new();
    let epoch = specs[0].execution_epoch;
    for spec in specs {
        if spec.size as usize != std::mem::size_of::<KrunManagedBlockV1>()
            || spec.version != 1
            || spec.layers.is_null()
            || spec.layer_count == 0
            || spec.layer_count > MAX_CLOSURE_DEPTH
            || spec.execution_epoch != epoch
        {
            return Err(invalid(
                "invalid block attachment version, closure or epoch",
            ));
        }
        let attachment_id = unsafe { identifier(spec.attachment_id) }?;
        let device_id = unsafe { identifier(spec.device_id) }?;
        let role = unsafe { identifier(spec.role) }?;
        let volume_id = unsafe { identifier(spec.volume_id) }?;
        let generation_id = unsafe { identifier(spec.generation_id) }?;
        if !attachments.insert(attachment_id.clone())
            || !devices.insert(device_id.clone())
            || !volumes.insert(volume_id.clone())
            || !matches!(
                role.as_str(),
                "root" | "storage" | "overlay" | "cache" | "data"
            )
        {
            return Err(invalid("duplicate or invalid managed block attachment"));
        }
        let writable_head_id = if spec.writable_head_id.is_null() {
            None
        } else {
            Some(unsafe { identifier(spec.writable_head_id) }?)
        };
        let grant_id = if spec.grant_id.is_null() {
            None
        } else {
            let id = unsafe { identifier(spec.grant_id) }?;
            if grant.as_ref().is_some_and(|expected| *expected != id) {
                return Err(invalid("writable blocks must belong to one grant"));
            }
            grant = Some(id.clone());
            Some(id)
        };
        let mut layers = Vec::new();
        for (index, layer) in unsafe { std::slice::from_raw_parts(spec.layers, spec.layer_count) }
            .iter()
            .enumerate()
        {
            handles.insert(layer.fd);
            if handles.len() > MAX_REFERENCED_FDS {
                return Err(invalid("block attachment set exceeds its descriptor limit"));
            }
            let format = ImageType::try_from(layer.format)
                .map_err(|_| invalid("unknown managed block format"))?;
            let resource_id = unsafe { identifier(layer.resource_id) }?;
            let duplicate = unsafe { libc::fcntl(layer.fd, libc::F_DUPFD_CLOEXEC, 0) };
            if duplicate < 0 {
                return Err(io::Error::last_os_error());
            }
            let file = unsafe { File::from_raw_fd(duplicate) };
            let metadata = file.metadata()?;
            let identity = (metadata.dev(), metadata.ino());
            let writable = index == 0 && writable_head_id.is_some();
            if identities
                .get(&identity)
                .is_some_and(|prior: &(String, bool)| prior.0 != resource_id || prior.1 || writable)
                || resources
                    .insert(resource_id.clone(), identity)
                    .is_some_and(|prior| prior != identity)
            {
                return Err(invalid(
                    "managed disk set contains a backing alias or conflicting resource",
                ));
            }
            identities.insert(identity, (resource_id.clone(), writable));
            layers.push(ManagedLayer {
                resource_id,
                format,
                file,
            });
        }
        let block = Block::from_managed_fds(
            ManagedAttachment {
                attachment_id,
                device_id,
                role,
                volume_id,
                generation_id,
                writable_head_id,
                grant_id,
                execution_epoch: epoch,
                capacity_bytes: spec.capacity_bytes,
                layers: layers
                    .iter()
                    .map(|layer| layer.resource_id.clone())
                    .collect(),
            },
            layers,
        )?;
        blocks.push_back(Arc::new(Mutex::new(block)));
    }
    Ok(blocks)
}

/// Install the entire explicit block set into a cold VM context.
///
/// # Safety
/// The descriptors and NUL-terminated strings in the input array must remain
/// readable until the call returns. Every original FD remains caller-owned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_attach_block_set_v1(
    ctx_id: u32,
    specs: *const KrunManagedBlockV1,
    count: usize,
) -> i32 {
    if specs.is_null() || count == 0 || count > MAX_DEVICES {
        return -libc::EINVAL;
    }
    let specs = unsafe { std::slice::from_raw_parts(specs, count) };
    let blocks = match unsafe { prepare_specs(specs) } {
        Ok(blocks) => blocks,
        Err(error) => {
            set_last_error(format!("prepare managed block set: {error}"));
            return -error.raw_os_error().unwrap_or(libc::EINVAL);
        }
    };
    let mut contexts = CTX_MAP.lock().unwrap();
    let Some(cfg) = contexts.get_mut(&ctx_id) else {
        return -libc::ENOENT;
    };
    if !cfg.block_cfgs.is_empty() || !cfg.vmr.block.list.is_empty() || cfg.snapshot_dir.is_some() {
        return -libc::EINVAL;
    }
    cfg.vmr.block.list = blocks;
    KRUN_SUCCESS
}
