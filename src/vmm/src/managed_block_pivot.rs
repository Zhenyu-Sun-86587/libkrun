//! Whole-set backing changes under the VMM's held capture actor.

use crate::device_manager::mmio::BlockPivotsRollback;
use crate::{Vmm, VmmRunState};
use devices::virtio::block::managed::{ManagedAttachment, ManagedLayer};
use std::fmt;
use std::fs::File;

pub struct ManagedBlockTarget {
    pub attachment: ManagedAttachment,
    pub layers: Vec<ManagedLayer>,
}

pub struct ManagedBlockInventory {
    pub attachment: ManagedAttachment,
    pub writer: Option<File>,
}

#[derive(Debug)]
pub enum ManagedBlockPivotError {
    Refused(String),
    RollbackFailed { apply: String, rollback: String },
}

impl fmt::Display for ManagedBlockPivotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(error) => f.write_str(error),
            Self::RollbackFailed { apply, rollback } => write!(
                f,
                "managed block install failed ({apply}); rollback failed ({rollback})"
            ),
        }
    }
}

impl std::error::Error for ManagedBlockPivotError {}

#[must_use = "a held pivot must either roll back or release its retained writers after a durable decision"]
pub struct ManagedBlockPivot(pub(crate) Option<BlockPivotsRollback>);

impl ManagedBlockPivot {
    /// Release the drained old writers after the Worker records the decision.
    /// The VMM must stay held until the Worker proves the old OFDs are gone
    /// and publishes the new writer set.
    pub fn commit(self) {
        drop(self);
    }
}

impl Vmm {
    fn managed_block_held(&self) -> Result<(), ManagedBlockPivotError> {
        if !matches!(self.run_state, VmmRunState::Paused) || !self.devices_quiesced {
            return Err(ManagedBlockPivotError::Refused(
                "managed block pivot requires the VMM and every device to be held".into(),
            ));
        }
        Ok(())
    }

    pub fn managed_block_inventory(
        &self,
    ) -> Result<Vec<ManagedBlockInventory>, ManagedBlockPivotError> {
        self.mmio_device_manager.managed_block_inventory()
    }

    pub fn pivot_managed_blocks_held(
        &mut self,
        targets: Vec<ManagedBlockTarget>,
    ) -> Result<ManagedBlockPivot, ManagedBlockPivotError> {
        self.managed_block_held()?;
        self.mmio_device_manager.pivot_managed_blocks(targets)
    }

    pub fn rollback_managed_blocks_held(
        &mut self,
        pivot: &mut ManagedBlockPivot,
    ) -> Result<(), ManagedBlockPivotError> {
        if let Err(error) = self.managed_block_held() {
            return Err(ManagedBlockPivotError::RollbackFailed {
                apply: "managed replacement is installed".into(),
                rollback: error.to_string(),
            });
        }
        let rollback = pivot.0.take().ok_or_else(|| {
            ManagedBlockPivotError::Refused("managed block pivot is no longer pending".into())
        })?;
        self.mmio_device_manager
            .rollback_block_pivots(rollback)
            .map_err(|rollback| ManagedBlockPivotError::RollbackFailed {
                apply: "managed replacement is installed".into(),
                rollback,
            })
    }
}
