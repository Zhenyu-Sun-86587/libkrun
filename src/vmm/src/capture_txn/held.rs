// SPDX-License-Identifier: Apache-2.0
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
}

pub(super) struct Capture {
    token: Token,
    phase: Phase,
    point: Option<Arc<HeldExport>>,
    error: Option<String>,
}

impl Capture {
    pub(super) fn holds_vmm(&self) -> bool {
        matches!(self.phase, Phase::Held | Phase::FailedHeld | Phase::Unknown)
    }
    fn receipt(&self) -> String {
        let (phase, disposition) = match self.phase {
            Phase::Held => ("prepared", "HELD"),
            Phase::Finished => ("finished", "RUNNING"),
            Phase::Cancelled => ("cancelled", "RUNNING"),
            Phase::FailedRunning => ("failed", "RUNNING"),
            Phase::FailedHeld => ("failed", "FAILED_HELD"),
            Phase::Unknown => ("failed", "UNKNOWN"),
        };
        format!(
            "OK {}\n",
            json!({"protocol":"CaptureControl/1", "mode":"raw",
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
    fn capture_raw_boundary(&mut self, token: Token) -> Result<HeldExport, String> {
        self.mmio_device_manager.quiesce_devices();
        self.devices_quiesced = true;
        self.mmio_device_manager.validate_standby_boundary()?;
        let inventory = self.mmio_device_manager.capture_inventory()?;
        let vcpu_states = self.save_vcpu_states().map_err(|e| e.to_string())?;
        if vcpu_states.iter().any(|v| v.runs_nested_guest()) {
            return Err("nested KVM memory cannot form a sealed generation".into());
        }
        let devices = self.snapshot_devices();
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
        let header=format!("OK {}\n",json!({"protocol":"CaptureControl/1", "export":"raw",
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
            ("CAPTURE_PREPARE", ["raw"])
            | ("CAPTURE_QUERY" | "CAPTURE_CANCEL", [])
            | ("CAPTURE_FINISH", ["CONTINUE" | "KEEP_HELD"]) => (),
            _ => return Err("EINVAL invalid held capture parameters or source disposition".into()),
        }
        let current = self.capture_control.capture.as_ref();
        let matching = current.is_some_and(|c| c.token == token);
        if verb == "CAPTURE_PREPARE" && !matching {
            if current.is_some_and(|c| c.token.session >= token.session) {
                return Err("ESTALE stale capture session".into());
            }
            if self.deep_control_holds_vmm() || self.run_state != VmmRunState::Running {
                return Err("EBUSY VMM is already held".into());
            }
            if !self
                .guest_gate
                .as_ref()
                .ok_or("ENOTSUP native deep control was not provisioned")?
                .lock()
                .unwrap()
                .allows_raw_standby()
            {
                return Err("EBUSY guest gate session is active".into());
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
                phase: Phase::Unknown,
                point: None,
                error: None,
            });
            if let Err(e) = self.pause() {
                let running = self.run_state == VmmRunState::Running;
                let record = self.capture_control.capture.as_mut().unwrap();
                if running {
                    record.phase = Phase::FailedRunning;
                }
                record.error = Some(e.to_string());
                return Err(format!("EIO pause: {e}"));
            }
            self.capture_control.capture.as_mut().unwrap().phase = Phase::FailedHeld;
            match self.capture_raw_boundary(token) {
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
        } else if matches!(verb, "CAPTURE_FINISH" | "CAPTURE_CANCEL") {
            let phase = self.capture_control.capture.as_ref().unwrap().phase;
            let decision = match (verb, fields.as_slice()) {
                ("CAPTURE_CANCEL", _) => Phase::Cancelled,
                (_, ["CONTINUE"]) => Phase::Finished,
                _ => Phase::Held,
            };
            if phase != decision {
                if phase != Phase::Held {
                    return Err("EBUSY capture decision cannot be changed".into());
                }
                self.capture_control.capture.as_mut().unwrap().phase = Phase::Unknown;
                if let Err(e) = self.resume() {
                    self.capture_control.capture.as_mut().unwrap().error = Some(e.to_string());
                    return Err(format!("EIO resume: {e}"));
                }
                let record = self.capture_control.capture.as_mut().unwrap();
                record.phase = decision;
                if decision == Phase::Cancelled {
                    record.point = None;
                }
            }
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
        if !matches!(capture.phase, Phase::Held | Phase::Finished) {
            return Err("EBUSY capture is unavailable".into());
        }
        capture
            .point
            .clone()
            .ok_or_else(|| "EIO capture is incomplete".into())
    }
}
