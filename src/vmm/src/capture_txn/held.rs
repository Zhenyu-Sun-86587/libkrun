// SPDX-License-Identifier: Apache-2.0
use super::DeviceInfo;
use crate::kernel_cow::{MAX_CHECKPOINT_BYTES, RamLayout};
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
use vm_memory::Address;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Token {
    session: u32,
    nonce: u128,
}
impl Token {
    fn parse(arguments: &str) -> Result<(Self, Vec<&str>), String> {
        let mut words = arguments.split_ascii_whitespace();
        let token = Self::parse_fields(words.next(), words.next())?;
        Ok((token, words.collect()))
    }

    fn parse_fields(session: Option<&str>, nonce: Option<&str>) -> Result<Self, String> {
        let session = session
            .and_then(|s| s.parse().ok())
            .filter(|s| *s != 0)
            .ok_or("EINVAL expected a nonzero capture session")?;
        let nonce = nonce
            .filter(|s| s.len() == 32 && s.bytes().all(|c| c.is_ascii_hexdigit()))
            .and_then(|s| u128::from_str_radix(s, 16).ok())
            .filter(|s| *s != 0)
            .ok_or("EINVAL expected a 128-bit capture challenge")?;
        Ok(Self { session, nonce })
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum RamBackend {
    Native,
    KernelCow,
}

enum CapturePoint {
    Native(Arc<HeldExport>),
    KernelCow {
        export: Arc<HeldKernelCowExport>,
        imported: bool,
    },
    KernelCowCommitted,
    KernelCowAbandoned,
}

pub(super) struct Capture {
    token: Token,
    gate_token: Token,
    managed: bool,
    backend: RamBackend,
    from_standby: bool,
    cancelled: bool,
    phase: Phase,
    point: Option<CapturePoint>,
    writers: Vec<ParkedWriter>,
    writers_committed: bool,
    stop_reserved: bool,
    error: Option<String>,
}

impl Capture {
    fn writers_ready(&self) -> bool {
        self.writers.is_empty() || self.writers_committed
    }

    pub(super) fn sequence(&self) -> u32 {
        self.token.session
    }

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
          "phase":phase,"source_disposition":disposition, "clone_ready":false, "error":self.error,
          "from_standby":self.from_standby,"stop_reserved":self.stop_reserved})
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

pub struct HeldKernelCowExport {
    token: Token,
    layout: RamLayout,
    checkpoint: Vec<u8>,
    devices: Vec<DeviceInfo>,
}

impl HeldKernelCowExport {
    pub fn send_to(&self, mut stream: &UnixStream) -> io::Result<()> {
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        self.write_to(&mut stream)
    }

    pub fn write_to(&self, output: &mut impl Write) -> io::Result<()> {
        let regions = self
            .layout
            .regions()
            .map(|(guest, size)| json!({"guest_start":guest.raw_value(),"size":size}))
            .collect::<Vec<_>>();
        let head = json!({
            "protocol":"KernelCowHeld/1",
            "session":self.token.session,
            "hold_token":format!("{:032x}",self.token.nonce),
            "regions":regions,
            "checkpoint_bytes":self.checkpoint.len(),
            "devices":self.devices,
        });
        writeln!(output, "OK {head}")?;
        output.write_all(&self.checkpoint)?;
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
            } else if let Some((tap, profile)) = dev.tap {
                if dev.device_id != tap.device_id {
                    return Err("registered TAP has a different stable id".into());
                }
                json!(["tap", profile])
            } else if let Some(init) = dev.bootstrap_init_sha256 {
                json!(["block-bootstrap", init])
            } else if let Some(vsock) = dev.vsock_binding {
                json!(["unix-ipc-v1", vsock])
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

    fn parked_uplink(&self) -> Result<Option<devices::virtio::guest_gate::ParkedUplink>, String> {
        let mut uplinks = self
            .mmio_device_manager
            .capture_inventory()?
            .into_iter()
            .filter_map(|d| d.tap.map(|(u, _)| u));
        let result = uplinks.next();
        if uplinks.next().is_some() {
            return Err(
                "multiple managed uplinks require a distinct network identity profile".into(),
            );
        }
        Ok(result)
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
            } else if wanted[1].as_u64() == Some(19) {
                type Binding = (u64, Vec<(u32, bool, String)>);
                let (before_tag, before): (String, Binding) =
                    serde_json::from_value(wanted[5].clone())
                        .map_err(|_| "malformed parked source vsock binding")?;
                let (after_tag, after): (String, Binding) =
                    serde_json::from_value(actual[5].clone())
                        .map_err(|_| "malformed parked target vsock binding")?;
                if before_tag != "unix-ipc-v1"
                    || after_tag != before_tag
                    || before.0 == after.0
                    || !before
                        .1
                        .iter()
                        .map(|(port, listen, _)| (port, listen))
                        .eq(after.1.iter().map(|(port, listen, _)| (port, listen)))
                    || before
                        .1
                        .iter()
                        .any(|(_, _, endpoint)| after.1.iter().any(|(_, _, new)| endpoint == new))
                {
                    return Err("parked target needs independent vsock endpoints and CID".into());
                }
                let snapshot = checkpoint
                    .devices
                    .devices
                    .iter()
                    .find_map(|device| match device {
                        DeviceSnapshot::Vsock(state) => Some(state),
                        _ => None,
                    })
                    .ok_or("missing parked vsock ring state")?;
                if snapshot.cid != before.0 || !snapshot.parked_rebind {
                    return Err("source vsock was not fenced at the parked cut".into());
                }
            } else if wanted[5] != actual[5] {
                return Err("parked target device slot or descriptor mismatch".into());
            }
        }
        let target_uplink = self.parked_uplink()?;
        self.guest_gate
            .as_ref()
            .ok_or("missing target Guest gate")?
            .lock()
            .unwrap()
            .bind_uplinks(state.uplink.as_ref(), target_uplink)
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
        if result == "released"
            && self
                .mmio_device_manager
                .with_vsock(|vsock| vsock.publish_parked_backend())?
                == Some(false)
        {
            return Ok("activating");
        }
        Ok(result)
    }

    fn capture_boundary(
        &mut self,
        token: Token,
        managed: bool,
        from_standby: bool,
        kernel_ram: Option<RamLayout>,
    ) -> Result<CapturePoint, String> {
        self.mmio_device_manager.quiesce_devices();
        self.devices_quiesced = true;
        self.mmio_device_manager.validate_standby_boundary()?;
        if managed {
            self.mmio_device_manager
                .with_vsock(|vsock| vsock.fence_parked_source())?;
        }
        let inventory = self.mmio_device_manager.capture_inventory()?;
        let vcpu_states = self.save_vcpu_states().map_err(|e| e.to_string())?;
        if vcpu_states.iter().any(|v| v.runs_nested_guest()) {
            return Err("nested KVM memory cannot form a held capture".into());
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
            let uplink = self.parked_uplink()?;
            if self
                .guest_gate
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .packets_parked()
                != uplink.is_some()
            {
                return Err(
                    "network capture requires a confirmed Guest packet gate and one managed TAP"
                        .into(),
                );
            }
            let capture = self.capture_control.capture.as_ref().unwrap();
            *gate = DeviceSnapshot::ParkedGuestGate(ParkedState {
                uplink,
                acked_features: gate.acked_features(),
                source_session: capture.gate_token.session,
                anchor,
                helper,
                writer_hold_token: (!capture.writers.is_empty())
                    .then(|| format!("{:032x}", token.nonce)),
                bindings: self.parked_bindings()?,
            });
        }
        if devices.devices.len() != inventory.len() {
            return Err("incomplete device snapshot at capture boundary".into());
        }
        let standby_pause_ns = if from_standby {
            let paused_at = self.paused_at.ok_or("managed standby has no pause clock")?;
            Some(Self::paused_duration_ns(paused_at.elapsed()))
        } else {
            None
        };
        let mut vm_state = self.save_vm_state().map_err(|e| e.to_string())?;
        vm_state.standby_pause_ns = standby_pause_ns;
        let checkpoint = VmCheckpoint {
            vm_state,
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
        if let Some(layout) = kernel_ram {
            if checkpoint.len() > MAX_CHECKPOINT_BYTES {
                return Err("captured checkpoint exceeds the Kernel CoW handoff limit".into());
            }
            return Ok(CapturePoint::KernelCow {
                export: Arc::new(HeldKernelCowExport {
                    token,
                    layout,
                    checkpoint,
                    devices: inventory,
                }),
                imported: false,
            });
        }
        let generation = if self.has_layered_ram() {
            self.capture_layered_ram_within(crate::layered_restore::CompactLimits::HANDOFF)
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
        Ok(CapturePoint::Native(Arc::new(HeldExport {
            header,
            checkpoint,
            descriptor,
            backings,
        })))
    }

    pub fn held_capture_control(&mut self, verb: &str, arguments: &str) -> Result<String, String> {
        let (token, fields) = Token::parse(arguments)?;
        self.held_capture_control_with_backend(verb, token, &fields, RamBackend::Native, None)
    }

    /// Enter the same CPU and device boundary used for Native capture, leaving
    /// RAM in place while the authorized Worker imports this held cut.
    /// On an existing Standby, the Worker can identify the unchanged Guest
    /// hold separately from this capture's fresh transaction scope.
    pub fn prepare_held_kernel_cow(&mut self, arguments: &str) -> Result<String, String> {
        let (token, fields) = Token::parse(arguments)?;
        let standby = match fields.as_slice() {
            [] => None,
            [session, nonce] => Some(Token::parse_fields(Some(session), Some(nonce))?),
            _ => return Err("EINVAL expected an optional original Standby scope".into()),
        };
        self.held_capture_control_with_backend(
            "CAPTURE_PREPARE",
            token,
            &["parked"],
            RamBackend::KernelCow,
            standby,
        )
    }

    fn held_capture_control_with_backend(
        &mut self,
        verb: &str,
        token: Token,
        fields: &[&str],
        backend: RamBackend,
        standby: Option<Token>,
    ) -> Result<String, String> {
        match (verb, fields) {
            ("CAPTURE_PREPARE", ["raw" | "parked"])
            | (
                "CAPTURE_QUERY"
                | "CAPTURE_CANCEL"
                | "CAPTURE_DROP_EXPORT"
                | "CAPTURE_STOP_RESERVE"
                | "CAPTURE_STOP_UNRESERVE",
                [],
            )
            | ("CAPTURE_FINISH", ["CONTINUE" | "KEEP_HELD" | "RETURN_STANDBY"]) => (),
            _ => return Err("EINVAL invalid held capture parameters or source disposition".into()),
        }
        let gate_token = standby.unwrap_or(token);
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
                        && s.sequence == gate_token.session
                        && s.nonce == gate_token.nonce
                        && s.disposition == super::Disposition::Standby
                });
            if standby.is_some()
                && (!from_standby
                    || token.session <= gate_token.session
                    || token.nonce == gate_token.nonce)
            {
                return Err(
                    "ESTALE capture requires its exact earlier managed Standby scope".into(),
                );
            }
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
            if (managed && !gate.parked(gate_token.session, gate_token.nonce))
                || (!managed && !gate.allows_raw_standby())
            {
                return Err("EBUSY Guest gate differs from the requested capture mode".into());
            }
            let packets_parked = gate.packets_parked();
            drop(gate);
            if managed {
                if packets_parked != self.parked_uplink()?.is_some() {
                    return Err("ENOTSUP parked network capture needs one TAP and a confirmed Guest packet gate".into());
                }
                self.parked_bindings().map_err(|e| format!("ENOTSUP {e}"))?;
            }
            if self.prototype_memory.is_some() || self.prototype_cpu_topology.is_some() {
                return Err(
                    "ENOTSUP capture of live resize topology requires a compatible state reader"
                        .into(),
                );
            }
            self.standby_profile(&self.mmio_device_manager.capture_inventory()?)
                .map_err(|e| format!("ENOTSUP {e}"))?;
            let kernel_ram = match backend {
                RamBackend::Native => {
                    if !self.has_layered_ram() {
                        let regions = snapshot::memfd_region_descs(&self.guest_memory);
                        if regions.is_empty() || regions.iter().any(|r| r.fd < 0) {
                            return Err(
                                "ENOTSUP held capture requires a complete file-backed RAM generation"
                                    .into(),
                            );
                        }
                    }
                    None
                }
                RamBackend::KernelCow => {
                    if !self.kernel_cow_ram {
                        return Err(
                            "ENOTSUP VM was not built with the kernel CoW RAM profile".into()
                        );
                    }
                    Some(
                        RamLayout::from_fixed_memory(&self.guest_memory)
                            .map_err(|e| format!("ENOTSUP {e}"))?,
                    )
                }
            };
            self.capture_control.capture = Some(Capture {
                token,
                gate_token,
                managed,
                backend,
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
                stop_reserved: false,
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
            match self.capture_boundary(token, managed, from_standby, kernel_ram) {
                Ok(point) => {
                    let record = self.capture_control.capture.as_mut().unwrap();
                    record.point = Some(point);
                    record.phase = Phase::Held;
                }
                Err(e) => {
                    self.capture_control.capture.as_mut().unwrap().error = Some(e.clone());
                    return Err(format!("EIO held capture: {e}"));
                }
            }
        } else if !matching {
            return Err("ESTALE unknown capture session".into());
        } else if verb == "CAPTURE_PREPARE"
            && current.is_some_and(|c| {
                c.backend != backend
                    || c.managed != (fields == ["parked"])
                    || c.gate_token != gate_token
            })
        {
            return Err(
                "EINVAL capture mode or Standby scope differs from original request".into(),
            );
        } else if verb == "CAPTURE_DROP_EXPORT" {
            let record = self.capture_control.capture.as_mut().unwrap();
            if !record.managed
                || !matches!(
                    record.phase,
                    Phase::Held | Phase::Finished | Phase::ReturnedStandby | Phase::Thawing
                )
            {
                return Err("EBUSY no stable parked capture export to drop".into());
            }
            match record.backend {
                RamBackend::Native => record.point = None,
                RamBackend::KernelCow
                    if matches!(
                        record.point,
                        Some(CapturePoint::KernelCowCommitted | CapturePoint::KernelCowAbandoned)
                    ) => {}
                RamBackend::KernelCow => {
                    return Err("EBUSY Kernel CoW export still owns the cut".into());
                }
            }
        } else if matches!(verb, "CAPTURE_STOP_RESERVE" | "CAPTURE_STOP_UNRESERVE") {
            let record = self.capture_control.capture.as_mut().unwrap();
            if !record.managed
                || record.phase != Phase::Held
                || !record.writers_ready()
                || (record.backend == RamBackend::KernelCow
                    && !matches!(
                        record.point,
                        Some(CapturePoint::KernelCow { imported: true, .. })
                    ))
            {
                return Err("EBUSY stop requires the current complete parked capture".into());
            }
            record.stop_reserved = verb == "CAPTURE_STOP_RESERVE";
        } else if matches!(verb, "CAPTURE_FINISH" | "CAPTURE_CANCEL") {
            let record = self.capture_control.capture.as_ref().unwrap();
            let cancelled = verb == "CAPTURE_CANCEL";
            if record.stop_reserved && fields != ["KEEP_HELD"] {
                return Err("EBUSY the Worker reserved this capture for stop".into());
            }
            if !cancelled
                && fields != ["KEEP_HELD"]
                && matches!(
                    record.point,
                    Some(CapturePoint::KernelCow {
                        imported: false,
                        ..
                    })
                )
            {
                return Err("EBUSY Kernel CoW target has not confirmed import".into());
            }
            if !cancelled && fields != ["KEEP_HELD"] && !record.writers_ready() {
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
            // A failed capture taken from managed Standby still owns that
            // exact parked gate. Only return it after the RAM remap is sound.
            let can_abort_failed_hold =
                phase == Phase::FailedHeld && cancelled && record.from_standby;
            if can_abort_failed_hold {
                self.ensure_ram_mapping_valid().map_err(|e| e.to_string())?;
            }
            if phase != Phase::Held && !can_abort_failed_hold {
                if (phase != decision && phase != Phase::Thawing)
                    || cancelled != record.cancelled
                    || decision == Phase::Held
                {
                    return Err("EBUSY capture decision cannot be changed".into());
                }
            } else if decision != Phase::Held {
                let managed = record.managed;
                let gate_token = record.gate_token;
                let record = self.capture_control.capture.as_mut().unwrap();
                record.cancelled = cancelled;
                if cancelled {
                    record.point = None;
                } else if matches!(
                    record.point,
                    Some(CapturePoint::KernelCow { imported: true, .. })
                ) {
                    record.point = Some(CapturePoint::KernelCowCommitted);
                }
                if decision == Phase::ReturnedStandby {
                    record.phase = decision;
                } else {
                    record.phase = Phase::Unknown;
                    if managed {
                        let arguments = format!("{} {:032x}", gate_token.session, gate_token.nonce);
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
        let record = self.capture_control.capture.as_ref().unwrap();
        if record.phase == Phase::Thawing
            && self
                .guest_gate
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .source_released(record.gate_token.session, record.gate_token.nonce)
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
            || !capture.writers_ready()
            || !matches!(
                capture.phase,
                Phase::Held | Phase::Finished | Phase::ReturnedStandby
            )
        {
            return Err("EBUSY capture is unavailable".into());
        }
        match capture.point.as_ref() {
            Some(CapturePoint::Native(export)) => Ok(Arc::clone(export)),
            _ if capture.backend == RamBackend::KernelCow => {
                Err("ENOTSUP Kernel CoW RAM has no native file export".into())
            }
            _ => Err("EIO capture is incomplete".into()),
        }
    }

    /// Return immutable metadata only. The Worker must keep the source held
    /// and supply a separately authenticated pidfd for the import.
    pub fn held_kernel_cow_export(
        &self,
        arguments: &str,
    ) -> Result<Arc<HeldKernelCowExport>, String> {
        let (token, fields) = Token::parse(arguments)?;
        if !fields.is_empty() {
            return Err("EINVAL trailing Kernel CoW cut arguments".into());
        }
        let capture = self
            .capture_control
            .capture
            .as_ref()
            .filter(|c| c.token == token)
            .ok_or("ESTALE unknown capture session")?;
        if capture.phase != Phase::Held || !capture.writers_ready() {
            return Err("EBUSY Kernel CoW export requires the complete held cut".into());
        }
        match capture.point.as_ref() {
            Some(CapturePoint::KernelCow { export, .. }) => Ok(Arc::clone(export)),
            _ => Err("EBUSY no Kernel CoW RAM at the held boundary".into()),
        }
    }

    /// Confirm a successful import by the trusted target for this exact cut.
    pub fn confirm_held_kernel_cow_import(&mut self, arguments: &str) -> Result<(), String> {
        let (token, fields) = Token::parse(arguments)?;
        if !fields.is_empty() {
            return Err("EINVAL trailing Kernel CoW cut arguments".into());
        }
        let capture = self
            .capture_control
            .capture
            .as_mut()
            .filter(|c| c.token == token)
            .ok_or("ESTALE no matching held Kernel CoW capture")?;
        if !capture.writers_ready() {
            return Err("EBUSY Kernel CoW confirmation requires the complete held cut".into());
        }
        match capture.point.as_mut() {
            Some(CapturePoint::KernelCow { imported, .. }) if capture.phase == Phase::Held => {
                *imported = true;
                Ok(())
            }
            Some(CapturePoint::KernelCowCommitted) => Ok(()),
            _ => Err("EINVAL capture used another RAM backend".into()),
        }
    }

    /// Revoke a definitively failed capture and retain the committed source
    /// writers. The Worker then finishes using the original source disposition.
    pub fn abandon_held_kernel_cow(&mut self, arguments: &str) -> Result<(), String> {
        let (token, fields) = Token::parse(arguments)?;
        if !fields.is_empty() {
            return Err("EINVAL trailing Kernel CoW cut arguments".into());
        }
        let capture = self
            .capture_control
            .capture
            .as_mut()
            .filter(|c| c.token == token)
            .ok_or("ESTALE no matching held Kernel CoW capture")?;
        if matches!(capture.point, Some(CapturePoint::KernelCowAbandoned)) {
            return Ok(());
        }
        if capture.phase != Phase::Held || capture.stop_reserved || !capture.writers_ready() {
            return Err("EBUSY Kernel CoW abandonment requires a releasable held cut".into());
        }
        if !matches!(capture.point, Some(CapturePoint::KernelCow { .. })) {
            return Err("EINVAL capture used another RAM backend".into());
        }
        capture.point = Some(CapturePoint::KernelCowAbandoned);
        Ok(())
    }
}
