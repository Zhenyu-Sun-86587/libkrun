// Copyright 2026. SPDX-License-Identifier: Apache-2.0
//! Block devices with an explicit Worker-owned closure of open files.

use super::device::{DiskBackend, DiskProperties, disk_backend};
use super::{Block, BlockIoEngine, CacheType, ImageType, SECTOR_SIZE, SyncMode};
use imago::{DynStorage, FormatAccess, Storage, file::File as ImageFile, qcow2::Qcow2, raw::Raw};
use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;

#[derive(Debug)]
pub struct ManagedAttachment {
    pub attachment_id: String,
    pub device_id: String,
    pub role: String,
    pub volume_id: String,
    pub generation_id: String,
    pub writable_head_id: Option<String>,
    pub grant_id: Option<String>,
    pub execution_epoch: u64,
    pub capacity_bytes: u64,
    pub layers: Vec<String>,
}

pub struct ManagedLayer {
    pub resource_id: String,
    pub format: ImageType,
    pub file: File,
}

type StorageFile = Box<dyn DynStorage>;
type ImageAccess = Arc<FormatAccess<StorageFile>>;
type Qcow2Image = Qcow2<StorageFile, ImageAccess>;
type Backing = Option<(String, &'static str, ImageAccess)>;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn disk_format(format: ImageType) -> io::Result<&'static str> {
    match format {
        ImageType::Raw => Ok("raw"),
        ImageType::Qcow2 => Ok("qcow2"),
        ImageType::Vmdk => Err(invalid("managed disks support raw and qcow2")),
    }
}

fn validate_layers(layers: &[ManagedLayer], writable: bool) -> io::Result<()> {
    let mut identities = HashSet::new();
    let mut resource_ids = HashSet::new();
    for (index, layer) in layers.iter().enumerate() {
        let meta = layer.file.metadata()?;
        let flags = unsafe { libc::fcntl(layer.file.as_raw_fd(), libc::F_GETFL) };
        let access = if index == 0 && writable {
            libc::O_RDWR
        } else {
            libc::O_RDONLY
        };
        if !meta.is_file()
            || flags < 0
            || flags & (libc::O_PATH | libc::O_APPEND | libc::O_DIRECT) != 0
            || flags & libc::O_ACCMODE != access
            || !identities.insert((meta.dev(), meta.ino()))
            || !resource_ids.insert(&layer.resource_id)
        {
            return Err(invalid(
                "managed block layer has an invalid file, access or identity",
            ));
        }
    }
    Ok(())
}

fn read_only_backing(layer: ManagedLayer, backing: Backing) -> io::Result<ImageAccess> {
    let storage: StorageFile = Box::new(ImageFile::try_from(layer.file)?);
    let access = match layer.format {
        ImageType::Raw if backing.is_none() => {
            FormatAccess::new(Raw::open_image_sync(storage, false)?)
        }
        ImageType::Qcow2 => FormatAccess::new(open_qcow2(storage, false, backing)?),
        _ => return Err(invalid("invalid managed block backing format")),
    };
    Ok(Arc::new(access))
}

fn open_qcow2(storage: StorageFile, writable: bool, backing: Backing) -> io::Result<Qcow2Image> {
    let mut image = Qcow2Image::open_image_sync(storage, writable)?;
    if image.requires_external_data_file() || image.implicit_external_data_file().is_some() {
        return Err(invalid("managed qcow2 forbids an external data file"));
    }
    match backing {
        Some((id, format, access))
            if image.implicit_backing_file().map(String::as_str) == Some(id.as_str())
                && image.implicit_backing_format().map(String::as_str) == Some(format) =>
        {
            image.set_backing(Some(access));
        }
        None if image.implicit_backing_file().is_none() => image.set_backing(None),
        _ => {
            return Err(invalid(
                "qcow2 header does not match its managed backing resource",
            ));
        }
    }
    image.set_data_file(None);
    Ok(image)
}

fn open_layers(layers: Vec<ManagedLayer>, writable: bool) -> io::Result<(Arc<DiskBackend>, usize)> {
    let mut layers = layers.into_iter();
    let top = layers
        .next()
        .ok_or_else(|| invalid("empty block closure"))?;
    let mut parent = None;
    for layer in layers.rev() {
        let id = layer.resource_id.clone();
        let format = disk_format(layer.format)?;
        let access = read_only_backing(layer, parent)?;
        parent = Some((id, format, access));
    }
    let file = ImageFile::try_from(top.file)?;
    let discard = file.discard_align();
    let storage: StorageFile = Box::new(file);
    let backend = match top.format {
        ImageType::Raw if parent.is_none() => disk_backend(
            Raw::open_image_sync(storage, writable)?,
            BlockIoEngine::Sync,
            None,
        )?,
        ImageType::Qcow2 => disk_backend(
            open_qcow2(storage, writable, parent)?,
            BlockIoEngine::Sync,
            None,
        )?,
        _ => return Err(invalid("invalid managed block head format")),
    };
    Ok((backend, discard))
}

impl Block {
    pub fn from_managed_fds(
        attachment: ManagedAttachment,
        layers: Vec<ManagedLayer>,
    ) -> io::Result<Self> {
        let writable = attachment.writable_head_id.is_some();
        let top = layers
            .first()
            .ok_or_else(|| invalid("empty block closure"))?;
        let expected_top = attachment
            .writable_head_id
            .as_deref()
            .unwrap_or(&attachment.generation_id);
        let generation = if writable {
            layers.get(1).unwrap_or(top)
        } else {
            top
        };
        if top.resource_id != expected_top
            || generation.resource_id != attachment.generation_id
            || attachment.grant_id.is_some() != writable
            || attachment.execution_epoch == 0
            || attachment.capacity_bytes == 0
            || !attachment.capacity_bytes.is_multiple_of(SECTOR_SIZE)
            || !layers
                .iter()
                .map(|layer| &layer.resource_id)
                .eq(attachment.layers.iter())
        {
            return Err(invalid(
                "block attachment does not match its managed closure",
            ));
        }
        validate_layers(&layers, writable)?;
        let image_id = DiskProperties::build_disk_image_id(&top.file);
        let (backend, discard) = open_layers(layers, writable)?;
        if backend.size() != attachment.capacity_bytes {
            return Err(invalid("block image capacity differs from the attachment"));
        }
        let cache = CacheType::Writeback;
        let disk = DiskProperties::new(backend.clone(), image_id.clone(), cache)?;
        let mut block = Self::from_opened_disk(
            attachment.device_id.clone(),
            None,
            cache,
            backend,
            image_id,
            disk,
            discard,
            !writable,
            false,
            SyncMode::Full,
            BlockIoEngine::Sync,
        )?;
        block.managed_attachment = Some(attachment);
        Ok(block)
    }

    pub fn managed_attachment(&self) -> Option<&ManagedAttachment> {
        self.managed_attachment.as_ref()
    }
}
