// SPDX-License-Identifier: Apache-2.0
use crate::managed_block_restore::{
    ParkedWriter, ParkedWriterTransition, parked_block_binding, verify_parked_block_binding,
};
use crate::{VmCheckpoint, Vmm, VmmRunState, resource_export::ResourceExport, snapshot};
use serde_json::json;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
struct Token {
    session: u32,
    nonce: u128,
}
impl Token {
    fn parse(arguments: &str) -> Result<(Self, Vec<&str>), String> {
        let mut words = arguments.split_ascii_whitespace();
        let session = words
            .next()
            .and_then(|s| s.parse().ok())
            .filter(|s| *s != 0)
            .ok_or("EINVAL expected a nonzero capture session")?;
        let nonce = words
            .next()
            .filter(|s| s.len() == 32 && s.bytes().all(|c| c.is_ascii_hexdigit()))
            .and_then(|s| u128::from_str_radix(s, 16).ok())
            .filter(|s| *s != 0)
            .ok_or("EINVAL expected a 128-bit capture challenge")?;
        Ok((Self { session, nonce }, words.collect()))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Held,
    Finished,
    Cancelled,
    FailedHeld,
    Unknown,
    FailedRunning,
    Thawing,
    ReturnedStandby,
}

pub(super) struct Capture {
    token: Token,
    managed: bool,
    from_standby: bool,
    cancelled: bool,
    phase: Phase,
    point: Option<Arc<HeldExport>>,
    writers: Vec<ParkedWriter>,
    writers_committed: bool,
    error: Option<String>,
}

impl Capture {
    pub(super) fn holds_vmm(&self) -> bool {
        matches!(
            self.phase,
            Phase::Held | Phase::FailedHeld | Phase::Unknown | Phase::Thawing
        )
    }
    fn receipt(&self) -> String {
        let (phase, disposition) = match self.phase {
            Phase::Held => ("prepared", "HELD"),
            Phase::Finished => ("finished", "RUNNING"),
            Phase::Cancelled => ("cancelled", "RUNNING"),
            Phase::Thawing => ("finishing", "WAKING"),
            Phase::ReturnedStandby => (
                if self.cancelled {
                    "cancelled"
                } else {
                    "finished"
                },
                "STANDBY",
            ),
            Phase::FailedRunning => ("failed", "RUNNING"),
            Phase::FailedHeld => ("failed", "FAILED_HELD"),
            Phase::Unknown => ("failed", "UNKNOWN"),
        };
        format!(
            "OK {}\n",
            json!({"protocol":"CaptureControl/1", "mode": if self.managed {"parked"} else {"raw"},
          "session":self.token.session, "hold_token":format!("{:032x}",self.token.nonce),
          "phase":phase,"source_disposition":disposition, "clone_ready":false, "error":self.error})
        )
    }
}

/// Immutable bytes and pinned RAM inodes for exactly one pause boundary.
/// The returned object owns these references independently of the VMM mutex.
pub struct HeldExport {
    header: Vec<u8>,
    checkpoint: Vec<u8>,
    descriptor: Vec<u8>,
    backings: Vec<File>,
}

impl HeldExport {
    pub fn send_to(&self, mut stream: &UnixStream) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        stream.write_all(&self.header)?;
        stream.write_all(&self.checkpoint)?;
        stream.write_all(&self.descriptor)?;
        for fd in &self.backings {
            crate::retained_fds::send_fd(stream, fd.as_raw_fd(), deadline)?;
        }
        Ok(())
    }
}

impl Vmm {
    pub fn record_held_block_commit(
        &mut self,
        arguments: &str,
        previous: &str,
        next: &str,
        transitions: &[ParkedWriterTransition],
    ) -> Result<(), String> {
        let (token, fields) = Token::parse(arguments)?;
        let capture = self
            .capture_control
            .capture
            .as_ref()
            .filter(|capture| capture.token == token && capture.phase == Phase::Held)
            .ok_or("ESTALE block commit does not belong to a held capture")?;
        if !fields.is_empty() {
            return Err("EINVAL trailing block capture arguments".into());
        }
        if !capture.managed {
            return Ok(());
        }
        self.verify_parked_storage_commit(&capture.writers, previous, next, transitions)?;
        self.capture_control
            .capture
            .as_mut()
            .unwrap()
            .writers_committed = true;
        Ok(())
    }

    /// Record the actual block graph and transport slots with the parked state.
    fn parked_bindings(&self) -> Result<Vec<String>, String> {
        use devices::virtio::{
            TYPE_BALLOON, TYPE_BLOCK, TYPE_CONSOLE, TYPE_RNG, guest_gate::DEVICE_TYPE,
        };
        let mut bindings = Vec::new();
        for dev in self.mmio_device_manager.capture_inventory()? {
            let block = if dev.virtio_type == TYPE_BLOCK {
                let spec = dev.block.ok_or("missing managed block")?;
                let a = spec
                    .managed_attachment
                    .ok_or("unmanaged block in parked identity profile")?;
                parked_block_binding(&a, spec.read_only, spec.capacity_bytes)?
            } else if let Some(init) = dev.bootstrap_init_sha256 {
                json!(["block-bootstrap", init])
            } else if matches!(
                dev.virtio_type,
                TYPE_RNG | TYPE_CONSOLE | TYPE_BALLOON | DEVICE_TYPE
            ) {
                serde_json::Value::Null
            } else {
                return Err(format!(
                    "device {} requires a rebind contract",
                    dev.device_id
                ));
            };
            bindings.push(
                json!([
                    dev.device_id,
                    dev.virtio_type,
                    dev.mmio_address,
                    dev.irq,
                    dev.offered_features,
                    block
                ])
                .to_string(),
            );
        }
        Ok(bindings)
    }

    pub(crate) fn validate_parked_target(&self, checkpoint: &VmCheckpoint) -> Result<(), String> {
        use devices::virtio::persist::DeviceSnapshot;
        let mut gates = checkpoint.devices.devices.iter().filter_map(|d| match d {
            DeviceSnapshot::ParkedGuestGate(s) => Some(s),
            _ => None,
        });
        let state = gates.next().ok_or("missing parked capture")?;
        let target = self.parked_bindings()?;
        if gates.next().is_some()
            || target.len() != state.bindings.len()
            || checkpoint.devices.devices.len() != state.bindings.len()
        {
            return Err("parked target device or storage closure mismatch".into());
        }
        for (wanted, actual) in state.bindings.iter().zip(&target) {
            let wanted: serde_json::Value =
                serde_json::from_str(wanted).map_err(|_| "malformed source binding")?;
            let actual: serde_json::Value =
                serde_json::from_str(actual).map_err(|_| "malformed target binding")?;
            let (Some(wanted), Some(actual)) = (wanted.as_array(), actual.as_array()) else {
                return Err("malformed parked transport binding".into());
            };
            if wanted.len() != 6 || actual.len() != 6 || wanted[..5] != actual[..5] {
                return Err("parked target device slot or descriptor mismatch".into());
            }
            if wanted[1].as_u64() == Some(devices::virtio::TYPE_BLOCK as u64) {
                let _ = verify_parked_block_binding(&wanted[5], &actual[5])?;
            } else if wanted[5] != actual[5] {
                return Err("parked target device slot or descriptor mismatch".into());
            }
        }
        Ok(())
    }

    pub fn target_identity_request(&mut self, packet: &[u8]) -> Result<&'static str, String> {
        let result = self
            .guest_gate
            .as_ref()
            .ok_or("no Guest gate")?
            .lock()
            .unwrap()
            .target_request(packet)
            .map_err(str::to_owned)?;
        if packet.first() == Some(&1)
            && result == "applying"
            && self.run_state == VmmRunState::Paused
        {
            self.resume()
                .map_err(|e| format!("identity-stage resume: {e}"))?;
        }
        Ok(result)
    }

    fn capture_boundary(&mut self, token: Token, managed: bool) -> Result<HeldExport, String> {
        self.mmio_device_manager.quiesce_devices();
        self.devices_quiesced = true;
        self.mmio_device_manager.validate_standby_boundary()?;
        let inventory = self.mmio_device_manager.capture_inventory()?;
        let vcpu_states = self.save_vcpu_states().map_err(|e| e.to_string())?;
        if vcpu_states.iter().any(|v| v.runs_nested_guest()) {
            return Err("nested KVM memory cannot form a sealed generation".into());
        }
        let mut devices = self.snapshot_devices();
        if managed {
            use devices::virtio::{guest_gate::ParkedState, persist::DeviceSnapshot};
            let (anchor, helper) = self
                .guest_gate
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .parked_identity()
                .ok_or("measured gate lost its parked state")?;
            let gate = devices
                .devices
                .iter_mut()
                .find(|d| matches!(d, DeviceSnapshot::GuestGate { .. }))
                .ok_or("missing parked Guest gate transport")?;
            *gate = DeviceSnapshot::ParkedGuestGate(ParkedState {
                acked_features: gate.acked_features(),
                anchor,
                helper,
                writer_hold_token: self
                    .capture_control
                    .capture
                    .as_ref()
                    .filter(|capture| !capture.writers.is_empty())
                    .map(|_| format!("{:032x}", token.nonce)),
                bindings: self.parked_bindings()?,
            });
        }
        if devices.devices.len() != inventory.len() {
            return Err("incomplete device snapshot at capture boundary".into());
        }
        let checkpoint = VmCheckpoint {
            vm_state: self.save_vm_state().map_err(|e| e.to_string())?,
            vcpu_states,
            devices,
            ioapic: None,
            cpu_growth: self.snapshot_cpu_growth(),
            memory_growth: self.snapshot_memory_growth(),
        }
        .serialize();
        // Reject a malformed state section before changing the source's RAM view.
        VmCheckpoint::deserialize(&checkpoint)?;
        devices::virtio::balloon::mark_guest_ram_shared();
        let generation = if self.has_layered_ram() {
            self.capture_layered_ram()
                .map_err(|e| e.to_string())?
                .ok_or("missing layered RAM")?
        } else {
            if snapshot::guest_memory_has_private_backing(&self.guest_memory)
                .map_err(|e| e.to_string())?
            {
                return Err(
                    "untracked private RAM cannot be captured without materialization".into(),
                );
            }
            self.adopt_layered_ram().map_err(|e| e.to_string())?;
            self.layered_ram.clone().ok_or("missing adopted RAM")?
        };
        let resource = generation.export_resource().map_err(|e| e.to_string())?;
        let descriptor = resource.descriptor_json().map_err(|e| e.to_string())?;
        if resource.backings.len() > ResourceExport::MAX_BACKINGS
            || descriptor.len() > ResourceExport::MAX_DESCRIPTOR_BYTES
        {
            return Err("captured generation exceeds the native handoff limits".into());
        }
        // A sealed RDWR descriptor cannot be used as an imported read-only lease.
        // Reopen only the file handles this VMM already owns, in descriptor key order.
        let backings: Vec<File> = resource
            .backings
            .values()
            .map(|f| File::open(format!("/proc/self/fd/{}", f.as_raw_fd())))
            .collect::<io::Result<_>>()
            .map_err(|e| e.to_string())?;
        let header=format!("OK {}\n",json!({"protocol":"CaptureControl/1", "export": if managed {"parked"} else {"raw"},
           "session":token.session,"hold_token":format!("{:032x}",token.nonce),"clone_ready":false,
           "checkpoint_bytes":checkpoint.len(),"descriptor_bytes":descriptor.len(),"fd_count":backings.len(),
           "devices":inventory})).into_bytes();
        Ok(HeldExport {
            header,
            checkpoint,
            descriptor,
            backings,
        })
    }

    pub fn held_capture_control(&mut self, verb: &str, arguments: &str) -> Result<String, String> {
        let (token, fields) = Token::parse(arguments)?;
        match (verb, fields.as_slice()) {
            ("CAPTURE_PREPARE", ["raw" | "parked"])
            | ("CAPTURE_QUERY" | "CAPTURE_CANCEL", [])
            | ("CAPTURE_FINISH", ["CONTINUE" | "KEEP_HELD" | "RETURN_STANDBY"]) => (),
            _ => return Err("EINVAL invalid held capture parameters or source disposition".into()),
        }
        let current = self.capture_control.capture.as_ref();
        let matching = current.is_some_and(|c| c.token == token);
        if verb == "CAPTURE_PREPARE" && !matching {
            if current.is_some_and(|c| c.token.session >= token.session) {
                return Err("ESTALE stale capture session".into());
            }
            let managed = fields == ["parked"];
            let from_standby = managed
                && self.capture_control.standby.as_ref().is_some_and(|s| {
                    s.managed
                        && s.sequence == token.session
                        && s.nonce == token.nonce
                        && s.disposition == super::Disposition::Standby
                });
            if from_standby {
                if self.run_state != VmmRunState::Paused
                    || !self.devices_quiesced
                    || current.is_some_and(Capture::holds_vmm)
                {
                    return Err("EBUSY standby has no stable device boundary".into());
                }
            } else if self.deep_control_holds_vmm() || self.run_state != VmmRunState::Running {
                return Err("EBUSY VMM is already held".into());
            }
            let gate = self
                .guest_gate
                .as_ref()
                .ok_or("ENOTSUP native deep control is missing")?
                .lock()
                .unwrap();
            if (managed && !gate.parked(token.session, token.nonce))
                || (!managed && !gate.allows_raw_standby())
            {
                return Err("EBUSY Guest gate differs from the requested capture mode".into());
            }
            drop(gate);
            if managed {
                self.parked_bindings().map_err(|e| format!("ENOTSUP {e}"))?;
            }
            self.raw_profile().map_err(|e| format!("ENOTSUP {e}"))?;
            if !self.has_layered_ram() {
                let regions = snapshot::memfd_region_descs(&self.guest_memory);
                if regions.is_empty() || regions.iter().any(|r| r.fd < 0) {
                    return Err(
                        "ENOTSUP held capture requires a complete file-backed RAM generation"
                            .into(),
                    );
                }
            }
            self.capture_control.capture = Some(Capture {
                token,
                managed,
                from_standby,
                cancelled: false,
                phase: Phase::Unknown,
                point: None,
                writers: if managed {
                    self.parked_storage_writers()?
                } else {
                    Vec::new()
                },
                writers_committed: false,
                error: None,
            });
            if !from_standby && let Err(e) = self.pause() {
                let running = self.run_state == VmmRunState::Running;
                let record = self.capture_control.capture.as_mut().unwrap();
                if running {
                    record.phase = Phase::FailedRunning;
                }
                record.error = Some(e.to_string());
                return Err(format!("EIO pause: {e}"));
            }
            self.capture_control.capture.as_mut().unwrap().phase = Phase::FailedHeld;
            match self.capture_boundary(token, managed) {
                Ok(point) => {
                    let record = self.capture_control.capture.as_mut().unwrap();
                    record.point = Some(Arc::new(point));
                    record.phase = Phase::Held;
                }
                Err(e) => {
                    self.capture_control.capture.as_mut().unwrap().error = Some(e.clone());
                    return Err(format!("EIO held capture: {e}"));
                }
            }
        } else if !matching {
            return Err("ESTALE unknown capture session".into());
        } else if verb == "CAPTURE_PREPARE" && current.unwrap().managed != (fields == ["parked"]) {
            return Err("EINVAL capture mode differs from original request".into());
        } else if matches!(verb, "CAPTURE_FINISH" | "CAPTURE_CANCEL") {
            let record = self.capture_control.capture.as_ref().unwrap();
            let cancelled = verb == "CAPTURE_CANCEL";
            if !record.writers.is_empty()
                && !cancelled
                && fields != ["KEEP_HELD"]
                && !record.writers_committed
            {
                return Err("EBUSY parked capture requires a complete Worker writer pivot".into());
            }
            if cancelled && record.writers_committed {
                return Err("EBUSY the captured block generations are already committed".into());
            }
            if (fields == ["RETURN_STANDBY"] && !record.from_standby)
                || (fields == ["CONTINUE"] && record.from_standby)
            {
                return Err(
                    "EINVAL source disposition conflicts with the original stable state".into(),
                );
            }
            let decision = if fields == ["KEEP_HELD"] {
                Phase::Held
            } else if record.from_standby {
                Phase::ReturnedStandby
            } else if cancelled {
                Phase::Cancelled
            } else {
                Phase::Finished
            };
            let phase = record.phase;
            if phase != Phase::Held {
                if (phase != decision && phase != Phase::Thawing)
                    || cancelled != record.cancelled
                    || decision == Phase::Held
                {
                    return Err("EBUSY capture decision cannot be changed".into());
                }
            } else if decision != Phase::Held {
                let managed = record.managed;
                let record = self.capture_control.capture.as_mut().unwrap();
                record.cancelled = cancelled;
                if cancelled {
                    record.point = None;
                }
                if decision == Phase::ReturnedStandby {
                    record.phase = decision;
                } else {
                    record.phase = Phase::Unknown;
                    if managed {
                        let arguments = format!("{} {:032x}", token.session, token.nonce);
                        self.guest_gate
                            .as_ref()
                            .unwrap()
                            .lock()
                            .unwrap()
                            .control("GUEST_GATE_RELEASE", &arguments)
                            .map_err(str::to_owned)?;
                    }
                    if let Err(e) = self.resume() {
                        self.capture_control.capture.as_mut().unwrap().error = Some(e.to_string());
                        return Err(format!("EIO resume: {e}"));
                    }
                    self.capture_control.capture.as_mut().unwrap().phase =
                        if managed { Phase::Thawing } else { decision };
                }
            }
        }
        if self.capture_control.capture.as_ref().unwrap().phase == Phase::Thawing
            && self
                .guest_gate
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .source_released(token.session, token.nonce)
        {
            let record = self.capture_control.capture.as_mut().unwrap();
            record.phase = if record.cancelled {
                Phase::Cancelled
            } else {
                Phase::Finished
            };
        }
        Ok(self.capture_control.capture.as_ref().unwrap().receipt())
    }

    pub fn held_capture_export(&self, arguments: &str) -> Result<Arc<HeldExport>, String> {
        let (token, fields) = Token::parse(arguments)?;
        if !fields.is_empty() {
            return Err("EINVAL trailing export arguments".into());
        }
        let capture = self
            .capture_control
            .capture
            .as_ref()
            .filter(|c| c.token == token)
            .ok_or("ESTALE unknown capture session")?;
        if capture.cancelled
            || (!capture.writers.is_empty() && !capture.writers_committed)
            || !matches!(
                capture.phase,
                Phase::Held | Phase::Finished | Phase::ReturnedStandby
            )
        {
            return Err("EBUSY capture is unavailable".into());
        }
        capture
            .point
            .clone()
            .ok_or_else(|| "EIO capture is incomplete".into())
    }
}
