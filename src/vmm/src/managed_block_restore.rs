// SPDX-License-Identifier: Apache-2.0
//! Exact block lineage checks for parked captures and their replacement devices.

use crate::VmCheckpoint;
use crate::resources::VmResources;
use devices::virtio::TYPE_BLOCK;
use devices::virtio::block::managed::ManagedAttachment;
use devices::virtio::persist::DeviceSnapshot;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs::File;

pub struct RestoreWriter {
    pub attachment: ManagedAttachment,
    pub source: ParkedWriter,
    pub layer_identities: Vec<(u64, u64)>,
    pub file: File,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParkedWriter {
    pub volume_id: String,
    pub head_resource_id: String,
    pub grant_id: String,
    pub execution_epoch: u64,
}

pub struct ParkedWriterTransition {
    pub volume_id: String,
    pub previous_head: String,
    pub next_head: String,
}

impl crate::Vmm {
    pub(crate) fn parked_storage_writers(&self) -> Result<Vec<ParkedWriter>, String> {
        let mut writers = Vec::new();
        for disk in self
            .managed_block_inventory()
            .map_err(|error| error.to_string())?
        {
            if let Some(head_resource_id) = disk.attachment.writable_head_id {
                writers.push(ParkedWriter {
                    volume_id: disk.attachment.volume_id,
                    head_resource_id,
                    grant_id: disk
                        .attachment
                        .grant_id
                        .ok_or("writable disk has no grant")?,
                    execution_epoch: disk.attachment.execution_epoch,
                });
            }
        }
        writers.sort_unstable_by(|a, b| a.volume_id.cmp(&b.volume_id));
        Ok(writers)
    }

    pub(crate) fn verify_parked_storage_commit(
        &self,
        original: &[ParkedWriter],
        previous: &str,
        next: &str,
        transitions: &[ParkedWriterTransition],
    ) -> Result<(), String> {
        let current = self.parked_storage_writers()?;
        if original.len() != transitions.len()
            || original.len() != current.len()
            || original
                .iter()
                .zip(transitions)
                .zip(current)
                .any(|((old, change), opened)| {
                    old.grant_id != previous
                        || opened.grant_id != next
                        || old.volume_id != change.volume_id
                        || old.volume_id != opened.volume_id
                        || old.execution_epoch != opened.execution_epoch
                        || old.head_resource_id != change.previous_head
                        || opened.head_resource_id != change.next_head
                })
        {
            return Err(
                "Worker block commit does not match the captured and installed writer sets".into(),
            );
        }
        Ok(())
    }
}

pub fn parked_block_binding(
    attachment: &ManagedAttachment,
    read_only: bool,
    capacity: u64,
) -> Result<Value, String> {
    if capacity != attachment.capacity_bytes || capacity == 0 || attachment.layers.is_empty() {
        return Err("managed block capacity or closure differs from the actual device".into());
    }
    let mut binding = vec![
        json!(attachment.attachment_id),
        json!(attachment.volume_id),
        json!(attachment.generation_id),
        json!(attachment.role),
        json!(attachment.layers),
        json!(capacity),
    ];
    match (
        &attachment.writable_head_id,
        &attachment.grant_id,
        read_only,
    ) {
        (None, None, true) if attachment.layers[0] == attachment.generation_id => {}
        (Some(head), Some(grant), false) if &attachment.layers[0] == head => {
            binding.push(json!({
                "head_resource_id":head,
                "grant_id":grant,
                "volume_id":attachment.volume_id,
                "execution_epoch":attachment.execution_epoch,
            }));
        }
        _ => return Err("managed block has no exact generation or writer attachment".into()),
    }
    Ok(Value::Array(binding))
}

pub fn verify_parked_block_binding(
    expected: &Value,
    actual: &Value,
) -> Result<Option<ParkedWriter>, String> {
    let (Some(source), Some(target)) = (expected.as_array(), actual.as_array()) else {
        return Err("malformed parked block binding".into());
    };
    if source.len() == 6 && target.len() == 6 && source == target {
        return Ok(None);
    }
    if source.len() != 7 || target.len() != 7 {
        return Err("parked block access changed at restore".into());
    }
    let old: ParkedWriter =
        serde_json::from_value(source[6].clone()).map_err(|_| "malformed captured writer")?;
    let new: ParkedWriter =
        serde_json::from_value(target[6].clone()).map_err(|_| "malformed replacement writer")?;
    let original = source[4]
        .as_array()
        .ok_or("missing captured block closure")?;
    let replacement = target[4]
        .as_array()
        .ok_or("missing replacement block closure")?;
    if source[0] != target[0]
        || source[1] != old.volume_id
        || target[1] != new.volume_id
        || old.head_resource_id == new.head_resource_id
        || old.grant_id == new.grant_id
        || source[3] != target[3]
        || source[5] != target[5]
        || target[2] != old.head_resource_id
        || original.first().and_then(Value::as_str) != Some(&old.head_resource_id)
        || replacement.first().and_then(Value::as_str) != Some(&new.head_resource_id)
        || replacement.get(1..) != Some(original.as_slice())
    {
        return Err("replacement disk does not extend the exact captured block generation".into());
    }
    Ok(Some(old))
}

/// Validate the semantic disk closure before building or activating a target.
/// MMIO slot and other transport identity are independently checked on the VMM.
pub fn preflight_restore_writers<'a>(
    checkpoint: &'a VmCheckpoint,
    resources: &VmResources,
) -> Result<(Option<&'a str>, Vec<RestoreWriter>), String> {
    let parked = checkpoint
        .devices
        .devices
        .iter()
        .find_map(|device| match device {
            DeviceSnapshot::ParkedGuestGate(state) => Some(state),
            _ => None,
        })
        .ok_or("missing parked storage and identity bindings")?;
    let mut expected = BTreeMap::new();
    for encoded in &parked.bindings {
        let binding: Value =
            serde_json::from_str(encoded).map_err(|_| "malformed parked device binding")?;
        if binding.get(1).and_then(Value::as_u64) == Some(TYPE_BLOCK as u64) {
            let id = binding
                .get(0)
                .and_then(Value::as_str)
                .ok_or("missing captured block ID")?;
            let storage = binding.get(5).ok_or("missing captured block closure")?;
            if expected.insert(id.to_string(), storage.clone()).is_some() {
                return Err("duplicate captured block ID".into());
            }
        }
    }
    let mut writers = BTreeMap::new();
    for device in &resources.block.list {
        let block = device.lock().unwrap();
        let attachment = block
            .managed_attachment()
            .ok_or("unmanaged block in parked target")?;
        let wanted = expected
            .remove(block.id())
            .ok_or("target block is absent from the capture")?;
        let found =
            parked_block_binding(attachment, block.is_read_only(), attachment.capacity_bytes)?;
        if let Some(source) = verify_parked_block_binding(&wanted, &found)? {
            let file = block
                .managed_writer()
                .map_err(|error| error.to_string())?
                .ok_or("parked target has no writable OFD")?;
            let layer_identities = block
                .managed_backing_identities()
                .ok_or("parked target has no measured backing identities")?
                .to_vec();
            if writers
                .insert(
                    attachment.volume_id.clone(),
                    RestoreWriter {
                        attachment: attachment.clone(),
                        source,
                        layer_identities,
                        file,
                    },
                )
                .is_some()
            {
                return Err("duplicate target writer volume".into());
            }
        }
    }
    if !expected.is_empty() {
        return Err("parked capture is missing a target block device".into());
    }
    Ok((
        parked.writer_hold_token.as_deref(),
        writers.into_values().collect(),
    ))
}
