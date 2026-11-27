// SPDX-License-Identifier: Apache-2.0
//! Native control for one live deep VMM. The VMM mutex serializes decisions.
use crate::{Vmm, VmmRunState};
use devices::virtio::block::managed::ManagedAttachment;
use devices::virtio::{Balloon, Block, Console, Rng, VirtioDevice, Vsock, guest_gate::GuestGate};
use serde::Serialize;

mod held;

#[derive(Serialize)]
pub(crate) struct BlockInfo {
    capacity_bytes: u64,
    read_only: bool,
    managed_attachment: Option<ManagedAttachment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    managed_backing_identities: Option<Vec<(u64, u64)>>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parked_vsock_rebind: Option<bool>,
    #[serde(skip)]
    vsock_binding: Option<(u64, Vec<(u32, bool, String)>)>,
    pub block: Option<BlockInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tap: Option<(devices::virtio::guest_gate::ParkedUplink, serde_json::Value)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bootstrap_init_sha256: Option<String>,
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
        let vsock = concrete.downcast_ref::<Vsock>();
        let vsock_binding = vsock.and_then(Vsock::parked_binding);
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
            || concrete.is::<devices::virtio::memory::MemoryDevice>()
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
            parked_vsock_rebind: vsock.map(|_| vsock_binding.is_some()),
            vsock_binding,
            #[cfg(not(feature = "aws-nitro"))]
            bootstrap_init_sha256: concrete
                .downcast_ref::<devices::virtio::Fs>()
                .and_then(|fs| fs.block_bootstrap_digest()),
            #[cfg(feature = "aws-nitro")]
            bootstrap_init_sha256: None,
            #[cfg(feature = "net")]
            tap: concrete
                .downcast_ref::<devices::virtio::Net>()
                .and_then(|net| net.managed_tap_identity())
                .map(|(binding, mac)| {
                    (
                        devices::virtio::guest_gate::ParkedUplink {
                            device_id: binding.profile.device_id.clone(),
                            attachment: binding.attachment_digest,
                            mac,
                        },
                        serde_json::json!(binding.profile),
                    )
                }),
            #[cfg(not(feature = "net"))]
            tap: None,
            block: block.map(|b| BlockInfo {
                capacity_bytes: b.capacity_bytes(),
                read_only: b.is_read_only(),
                managed_attachment: b.managed_attachment().cloned(),
                managed_backing_identities: b
                    .managed_backing_identities()
                    .map(|identities| identities.to_vec()),
            }),
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Standby,
    Waking,
    Running,
    FailedHeld,
    Unknown,
}

struct StandbyReceipt {
    managed: bool,
    preserve_credential_relay: bool,
    sequence: u32,
    nonce: u128,
    disposition: Disposition,
}

#[derive(Default)]
pub(super) struct CaptureControl {
    standby: Option<StandbyReceipt>,
    capture: Option<held::Capture>,
}

impl Vmm {
    fn supports_credential_relay_fork(&self) -> Result<bool, String> {
        Ok(self
            .mmio_device_manager
            .with_vsock(|vsock| Ok(vsock.supports_credential_relay_fork()))?
            .unwrap_or(false))
    }

    pub fn deep_control_holds_vmm(&self) -> bool {
        self.guest_gate
            .as_ref()
            .is_some_and(|g| g.lock().unwrap().target_quarantined())
            || self
                .capture_control
                .capture
                .as_ref()
                .is_some_and(held::Capture::holds_vmm)
            || self
                .capture_control
                .standby
                .as_ref()
                .is_some_and(|s| s.disposition != Disposition::Running)
    }

    fn standby_profile(&self, inventory: &[DeviceInfo]) -> Result<(), String> {
        self.ensure_restore_complete().map_err(|e| e.to_string())?;
        self.ensure_ram_mapping_valid().map_err(|e| e.to_string())?;
        if self.prototype_cpu_topology.is_some() {
            self.prototype_cpu_status()?;
        }
        if self.prototype_memory.is_some() {
            let (mapped, plugged) = self.prototype_memory_status()?;
            if mapped != plugged {
                return Err("Guest memory growth is still pending".into());
            }
        }
        for device in inventory {
            if !device.quiesce_supported {
                return Err(format!("unsupported standby device {}", device.device_id));
            }
        }
        Ok(())
    }

    pub fn deep_virtio_inventory(&self) -> Result<String, String> {
        let (gate_session, gate_phase, measured, quarantined, stop_supported) = {
            let gate = self
                .guest_gate
                .as_ref()
                .ok_or("native deep control was not provisioned")?
                .lock()
                .unwrap();
            let (session, phase, measured) = gate.source_status();
            (session, phase, measured, gate.target_quarantined(), gate.stop_supported())
        };
        let capture = self.capture_control.capture.as_ref();
        let standby = self.capture_control.standby.as_ref();
        let last_session = gate_session
            .max(standby.map_or(0, |s| s.sequence))
            .max(capture.map_or(0, held::Capture::sequence));
        let disposition = if quarantined {
            "QUARANTINED"
        } else if capture.is_some_and(held::Capture::holds_vmm) {
            "HELD"
        } else {
            match (self.run_state, standby.map(|s| s.disposition)) {
                (VmmRunState::Paused, Some(Disposition::Standby)) => "STANDBY",
                (_, Some(Disposition::FailedHeld)) => "FAILED_HELD",
                (_, Some(Disposition::Waking)) => "WAKING",
                (VmmRunState::Running, None | Some(Disposition::Running))
                    if matches!(
                        gate_phase,
                        "idle" | "released" | "aborted" | "expired_thawed" | "failed_thawed"
                    ) =>
                {
                    "RUNNING"
                }
                (VmmRunState::Running, _)
                    if matches!(gate_phase, "armed" | "parking" | "parked" | "stop_parked") =>
                {
                    "GUEST_HELD"
                }
                _ => "UNKNOWN",
            }
        };
        let inventory = self.mmio_device_manager.capture_inventory()?;
        let standby_blocker = self.standby_profile(&inventory).err();
        let mut reply = serde_json::json!({"protocol":"CaptureControl/1","devices":inventory,"source_disposition":disposition,
            "last_session":last_session, "guest_gate":gate_phase, "measured_helper":measured,"standby_blocker":standby_blocker,
            "stop_barrier":stop_supported});
        if self.supports_credential_relay_fork()? {
            reply["credential_relay_fork"] = true.into();
        }
        Ok(format!("OK {reply}\n"))
    }

    pub fn standby_control(&mut self, verb: &str, arguments: &str) -> Result<String, String> {
        if self.guest_gate.is_none() {
            return Err("ENOTSUP native deep control was not provisioned".into());
        }
        if verb != "STANDBY_QUERY"
            && self
                .capture_control
                .capture
                .as_ref()
                .is_some_and(held::Capture::holds_vmm)
        {
            return Err("EBUSY held capture owns the VMM".into());
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
        let mode = match (verb, fields.next()) {
            ("STANDBY_ENTER", Some("raw")) => Some((false, false)),
            ("STANDBY_ENTER", Some("managed")) => Some((true, false)),
            ("STANDBY_FORK_ENTER", Some("managed")) => Some((true, true)),
            ("STANDBY_ENTER" | "STANDBY_FORK_ENTER", _) => {
                return Err("EINVAL invalid standby mode".into());
            }
            (_, None) => None,
            _ => return Err("EINVAL trailing standby parameters".into()),
        };
        if fields.next().is_some() {
            return Err("EINVAL trailing standby parameters".into());
        }
        let matching = self
            .capture_control
            .standby
            .as_ref()
            .is_some_and(|s| s.sequence == sequence && s.nonce == nonce);
        if matching && mode.is_some_and(|(managed, preserve)| {
            let s = self.capture_control.standby.as_ref().unwrap();
            (managed, preserve) != (s.managed, s.preserve_credential_relay)
        }) {
            return Err("EINVAL standby mode differs from the original request".into());
        }
        match verb {
            "STANDBY_ENTER" | "STANDBY_FORK_ENTER" if !matching => {
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
                let (managed, preserve_credential_relay) = mode.unwrap();
                let permitted = {
                    let gate = self.guest_gate.as_ref().unwrap().lock().unwrap();
                    if managed {
                        gate.parked(sequence, nonce)
                            || (!preserve_credential_relay && gate.stop_parked(sequence, nonce))
                    } else {
                        gate.allows_raw_standby()
                    }
                };
                if !permitted {
                    return Err(
                        "EBUSY Guest freezer does not match the requested standby mode".into(),
                    );
                }
                self.standby_profile(&self.mmio_device_manager.capture_inventory()?)
                    .map_err(|e| format!("ENOTSUP {e}"))?;
                if preserve_credential_relay && !self.supports_credential_relay_fork()? {
                    return Err("ENOTSUP source has no managed credential relay".into());
                }
                self.capture_control.standby = Some(StandbyReceipt {
                    managed,
                    preserve_credential_relay,
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
            "STANDBY_ENTER" | "STANDBY_FORK_ENTER" | "STANDBY_QUERY" if matching => (),
            "STANDBY_WAKE" if matching => {
                match self.capture_control.standby.as_ref().unwrap().disposition {
                    Disposition::Standby => {
                        self.capture_control.standby.as_mut().unwrap().disposition =
                            Disposition::Unknown;
                        let managed = self.capture_control.standby.as_ref().unwrap().managed;
                        if managed {
                            self.guest_gate
                                .as_ref()
                                .unwrap()
                                .lock()
                                .unwrap()
                                .control("GUEST_GATE_RELEASE", arguments)
                                .map_err(str::to_owned)?;
                        }
                        self.resume().map_err(|e| format!("EIO wake: {e}"))?;
                        self.capture_control.standby.as_mut().unwrap().disposition = if managed {
                            Disposition::Waking
                        } else {
                            Disposition::Running
                        };
                    }
                    Disposition::Running | Disposition::Waking => (),
                    _ => return Err("EIO unresolved VMM or device state".into()),
                }
            }
            _ => return Err("ESTALE unknown standby session".into()),
        }
        if self.capture_control.standby.as_ref().unwrap().disposition == Disposition::Waking {
            let released = self
                .guest_gate
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .source_released(sequence, nonce);
            if released {
                self.capture_control.standby.as_mut().unwrap().disposition = Disposition::Running;
            }
        }
        let disposition = match self.capture_control.standby.as_ref().unwrap().disposition {
            Disposition::Running => "RUNNING",
            Disposition::Standby => "STANDBY",
            Disposition::Waking => "WAKING",
            Disposition::FailedHeld => "FAILED_HELD",
            Disposition::Unknown => "UNKNOWN",
        };
        Ok(format!(
            "OK {}\n",
            serde_json::json!({
                "protocol":"CaptureControl/1", "session":sequence, "hold_token":format!("{nonce:032x}"),
                "source_disposition":disposition,"mode": if self.capture_control.standby.as_ref().unwrap().managed {"managed"} else {"raw"}, "clone_ready":false
            })
        ))
    }
}
