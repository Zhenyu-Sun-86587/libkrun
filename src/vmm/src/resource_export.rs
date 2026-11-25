// Copyright 2026. SPDX-License-Identifier: Apache-2.0
//! Transfer a complete layered RAM generation through owned descriptor handles.

use crate::layered_restore::{ExtentDescription, Generation, RegionDescription};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, Metadata};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RamGenerationDescriptor {
    pub regions: Vec<Region>,
    pub backing_sizes: BTreeMap<String, u64>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Region {
    pub gpa: u64,
    pub length: u64,
    pub extents: Vec<Extent>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Extent {
    pub offset: u64,
    pub length: u64,
    pub backing_id: String,
    pub backing_offset: u64,
}

pub struct ResourceExport {
    pub descriptor: RamGenerationDescriptor,
    pub backings: BTreeMap<String, Arc<File>>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn sealed(file: &File, require_readonly: bool) -> io::Result<Metadata> {
    let metadata = file.metadata()?;
    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    let required = libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW;
    if !metadata.is_file()
        || flags < 0
        || flags & libc::O_PATH != 0
        || flags & libc::O_ACCMODE == libc::O_WRONLY
        || (require_readonly && flags & libc::O_ACCMODE != libc::O_RDONLY)
        || seals < 0
        || seals & required != required
    {
        return Err(invalid(
            "RAM export requires readable and fully sealed files",
        ));
    }
    Ok(metadata)
}

fn backing_id(metadata: &Metadata) -> String {
    format!("ram-{:x}-{:x}", metadata.dev(), metadata.ino())
}

impl ResourceExport {
    pub(crate) fn new(
        descriptions: Vec<RegionDescription>,
        files: impl Iterator<Item = Arc<File>>,
    ) -> io::Result<Self> {
        let mut backings = BTreeMap::new();
        let mut backing_sizes = BTreeMap::new();
        let mut fd_ids = HashMap::new();
        for file in files {
            if let std::collections::hash_map::Entry::Vacant(entry) = fd_ids.entry(file.as_raw_fd())
            {
                let metadata = sealed(&file, false)?;
                let id = backing_id(&metadata);
                backing_sizes.insert(id.clone(), metadata.len());
                backings.entry(id.clone()).or_insert(file);
                entry.insert(id);
            }
        }
        let regions = descriptions
            .into_iter()
            .map(|region| Region {
                gpa: region.gpa,
                length: region.len,
                extents: region
                    .extents
                    .into_iter()
                    .map(|extent| Extent {
                        offset: extent.start,
                        length: extent.len,
                        backing_id: fd_ids[&extent.fd].clone(),
                        backing_offset: extent.offset,
                    })
                    .collect(),
            })
            .collect();
        Ok(Self {
            descriptor: RamGenerationDescriptor {
                regions,
                backing_sizes,
            },
            backings,
        })
    }

    /// Acquire an independent generation using the broker's read-only handles.
    /// The IDs refer to sealed kernel objects on this boot and survive process exit.
    pub fn import(self) -> io::Result<Generation> {
        let mut files = HashMap::new();
        if self.descriptor.backing_sizes.len() != self.backings.len() || self.backings.len() > 1024
        {
            return Err(invalid("RAM import received the wrong backing count"));
        }
        for (id, file) in &self.backings {
            let metadata = sealed(file, true)?;
            if backing_id(&metadata) != *id
                || self.descriptor.backing_sizes.get(id) != Some(&metadata.len())
            {
                return Err(invalid("RAM import backing has the wrong ID or size"));
            }
            files.insert(file.as_raw_fd(), Arc::clone(file));
        }
        let mut used = HashSet::new();
        let mut regions = Vec::new();
        for region in self.descriptor.regions {
            let mut extents = Vec::new();
            for extent in region.extents {
                let file = self
                    .backings
                    .get(&extent.backing_id)
                    .ok_or_else(|| invalid("RAM extent requires an absent backing"))?;
                used.insert(file.as_raw_fd());
                extents.push(ExtentDescription {
                    start: extent.offset,
                    len: extent.length,
                    offset: extent.backing_offset,
                    fd: file.as_raw_fd(),
                });
            }
            regions.push(RegionDescription {
                gpa: region.gpa,
                len: region.length,
                extents,
            });
        }
        if used.len() != files.len() {
            return Err(invalid("RAM import received unused backings"));
        }
        Generation::from_descriptions_with_files(None, &regions, files)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::MemoryRegionDesc;
    use std::os::unix::fs::FileExt;
    use vm_memory::{Bytes, GuestAddress};

    #[test]
    fn detached_import_preserves_sparse_base_and_private_delta() {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let len = page * 32;
        let base = crate::builder::create_guest_ram_memfd(len).unwrap();
        base.write_all_at(b"cold", (len - page) as u64).unwrap();
        let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
        assert_eq!(
            unsafe { libc::fcntl(base.as_raw_fd(), libc::F_ADD_SEALS, seals) },
            0
        );
        let generation = Generation::from_immutable_file(
            &[MemoryRegionDesc {
                gpa: 0,
                len: len as u64,
            }],
            &base,
        )
        .unwrap();
        let source = generation.restore().unwrap();
        source.write_slice(b"delta", GuestAddress(0)).unwrap();
        let (captured, bytes_copied) = generation.capture_quiesced(&source).unwrap();
        assert_eq!(bytes_copied, page);
        let exported = captured.export_resource().unwrap();
        assert_eq!(exported.backings.len(), 2);

        let readonly = exported
            .backings
            .iter()
            .map(|(id, file)| {
                let ro = File::open(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
                (id.clone(), Arc::new(ro))
            })
            .collect();
        let descriptor =
            serde_json::from_slice(&serde_json::to_vec(&exported.descriptor).unwrap()).unwrap();
        drop((base, generation, source, captured, exported));
        let imported = ResourceExport {
            descriptor,
            backings: readonly,
        }
        .import()
        .unwrap();
        let child = imported.restore().unwrap();
        let sibling = imported.restore().unwrap();
        let mut cold = [0; 4];
        child
            .read_slice(&mut cold, GuestAddress((len - page) as u64))
            .unwrap();
        assert_eq!(&cold, b"cold");
        child.write_slice(b"child", GuestAddress(0)).unwrap();
        let mut unchanged = [0; 5];
        sibling.read_slice(&mut unchanged, GuestAddress(0)).unwrap();
        assert_eq!(&unchanged, b"delta");
        let (grandchild, copied) = imported.capture_quiesced(&child).unwrap();
        assert!(copied < len);
        assert_eq!(grandchild.export_resource().unwrap().backings.len(), 2);
    }
}
