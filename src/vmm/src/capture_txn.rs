// SPDX-License-Identifier: Apache-2.0
//! Native control for one live deep VMM. The VMM mutex serializes decisions.
use crate::{Vmm, VmmRunState};
use devices::virtio::{Balloon, Block, Console, Rng, VirtioDevice, Vsock, guest_gate::GuestGate};
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct BlockInfo {
    capacity_bytes: u64,
    read_only: bool,
}

#[derive(Serialize)]
pub(crate) struct DeviceInfo {
    pub device_id: String,
    pub virtio_type: u32,
    pub mmio_address: u64,
    pub irq: u32,
    driver: String,
    activated: bool,
    queues: usize,
    offered_features: u64,
    negotiated_features: u64,
    pub quiesce_supported: bool,
    pub block: Option<BlockInfo>,
}

impl DeviceInfo {
    pub fn from_device(
        id: &str,
        addr: u64,
        irq: u32,
        dev: &dyn VirtioDevice,
    ) -> Result<Self, String> {
        let concrete = dev.as_any();
        let block = concrete.downcast_ref::<Block>();
        if block.is_some_and(|b| b.id() != id) {
            return Err(format!(
                "block ID does not match the registered transport: {id}"
            ));
        }
        let mut quiesce_supported = block.is_some()
            || concrete.is::<Balloon>()
            || concrete.is::<Console>()
            || concrete.is::<Rng>()
            || concrete.is::<Vsock>()
            || concrete.is::<GuestGate>();
        #[cfg(not(feature = "aws-nitro"))]
        {
            quiesce_supported |= concrete.is::<devices::virtio::Fs>();
        }
        #[cfg(feature = "net")]
        {
            quiesce_supported |= concrete.is::<devices::virtio::Net>();
        }
        Ok(Self {
            device_id: id.to_owned(),
            virtio_type: dev.device_type(),
            mmio_address: addr,
            irq,
            driver: dev.device_name().to_owned(),
            activated: dev.is_activated(),
            queues: dev.queue_config().len(),
            offered_features: dev.avail_features(),
            negotiated_features: dev.acked_features(),
            quiesce_supported,
            block: block.map(|b| BlockInfo {
                capacity_bytes: b.capacity_bytes(),
                read_only: b.is_read_only(),
            }),
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Standby,
    Running,
    FailedHeld,
    Unknown,
}

struct StandbyReceipt {
    sequence: u32,
    nonce: u128,
    disposition: Disposition,
}

#[derive(Default)]
pub(super) struct CaptureControl {
    standby: Option<StandbyReceipt>,
}

impl Vmm {
    pub fn deep_control_holds_vmm(&self) -> bool {
        self.capture_control
            .standby
            .as_ref()
            .is_some_and(|s| s.disposition != Disposition::Running)
    }

    fn raw_profile(&self) -> Result<(), String> {
        self.ensure_restore_complete().map_err(|e| e.to_string())?;
        self.ensure_ram_mapping_valid().map_err(|e| e.to_string())?;
        if self.prototype_memory.is_some() || self.prototype_cpu_topology.is_some() {
            return Err("live resize topology needs reconciliation before standby".into());
        }
        for device in self.mmio_device_manager.capture_inventory()? {
            if !device.quiesce_supported {
                return Err(format!("unsupported standby device {}", device.device_id));
            }
        }
        Ok(())
    }

    pub fn deep_virtio_inventory(&self) -> Result<String, String> {
        if self.guest_gate.is_none() {
            return Err("native deep control was not provisioned".into());
        }
        let inventory = self.mmio_device_manager.capture_inventory()?;
        Ok(format!(
            "OK {}\n",
            serde_json::json!({"protocol":"CaptureControl/1","devices":inventory})
        ))
    }

    pub fn standby_control(&mut self, verb: &str, arguments: &str) -> Result<String, String> {
        if self.guest_gate.is_none() {
            return Err("ENOTSUP native deep control was not provisioned".into());
        }
        let mut fields = arguments.split_ascii_whitespace();
        let sequence = fields
            .next()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|v| *v > 0)
            .ok_or("EINVAL expected a nonzero standby session")?;
        let nonce = fields
            .next()
            .filter(|v| v.len() == 32 && v.bytes().all(|b| b.is_ascii_hexdigit()))
            .and_then(|v| u128::from_str_radix(v, 16).ok())
            .filter(|v| *v > 0)
            .ok_or("EINVAL expected a 128-bit standby hold token")?;
        if verb == "STANDBY_ENTER" && fields.next() != Some("raw") {
            return Err("ENOTSUP expected explicitly raw standby".into());
        }
        if fields.next().is_some() {
            return Err("EINVAL trailing standby parameters".into());
        }
        let matching = self
            .capture_control
            .standby
            .as_ref()
            .is_some_and(|s| s.sequence == sequence && s.nonce == nonce);
        match verb {
            "STANDBY_ENTER" if !matching => {
                if self
                    .capture_control
                    .standby
                    .as_ref()
                    .is_some_and(|s| sequence <= s.sequence)
                {
                    return Err("ESTALE stale standby session".into());
                }
                if self.deep_control_holds_vmm() || self.run_state != VmmRunState::Running {
                    return Err("EBUSY VMM is already held".into());
                }
                if !self
                    .guest_gate
                    .as_ref()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .allows_raw_standby()
                {
                    return Err("EBUSY a Guest gate session is active".into());
                }
                self.raw_profile().map_err(|e| format!("ENOTSUP {e}"))?;
                self.capture_control.standby = Some(StandbyReceipt {
                    sequence,
                    nonce,
                    disposition: Disposition::Unknown,
                });
                if let Err(e) = self.pause() {
                    if self.run_state == VmmRunState::Running {
                        self.capture_control.standby.as_mut().unwrap().disposition =
                            Disposition::Running;
                    }
                    return Err(format!("EIO pause: {e}"));
                }
                self.capture_control.standby.as_mut().unwrap().disposition =
                    Disposition::FailedHeld;
                self.mmio_device_manager.quiesce_devices();
                self.devices_quiesced = true;
                self.mmio_device_manager
                    .validate_standby_boundary()
                    .map_err(|e| format!("EIO {e}"))?;
                self.capture_control.standby.as_mut().unwrap().disposition = Disposition::Standby;
            }
            "STANDBY_ENTER" | "STANDBY_QUERY" if matching => (),
            "STANDBY_WAKE" if matching => {
                match self.capture_control.standby.as_ref().unwrap().disposition {
                    Disposition::Standby => {
                        self.capture_control.standby.as_mut().unwrap().disposition =
                            Disposition::Unknown;
                        self.resume().map_err(|e| format!("EIO wake: {e}"))?;
                        self.capture_control.standby.as_mut().unwrap().disposition =
                            Disposition::Running;
                    }
                    Disposition::Running => (),
                    _ => return Err("EIO unresolved VMM or device state".into()),
                }
            }
            _ => return Err("ESTALE unknown standby session".into()),
        }
        let disposition = match self.capture_control.standby.as_ref().unwrap().disposition {
            Disposition::Running => "RUNNING",
            Disposition::Standby => "STANDBY",
            Disposition::FailedHeld => "FAILED_HELD",
            Disposition::Unknown => "UNKNOWN",
        };
        Ok(format!(
            "OK {}\n",
            serde_json::json!({
                "protocol":"CaptureControl/1", "session":sequence, "hold_token":format!("{nonce:032x}"),
                "source_disposition":disposition,"mode":"raw","clone_ready":false
            })
        ))
    }
}
