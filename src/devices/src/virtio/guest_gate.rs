// SPDX-License-Identifier: Apache-2.0
//! Host-controlled freezer mailbox. This transport has no DMA queues. Its
//! session and guest acknowledgements belong to one live VMM.
use super::{
    ActivateError, ActivateResult, DeviceQueue, InterruptTransport, QueueConfig, VirtioDevice,
};
use log::warn;
use vm_memory::GuestMemoryMmap;

mod target;
pub use target::{ParkedState, ParkedUplink, TargetScope};

pub const DEVICE_TYPE: u32 = 0xff51;
const COMMAND_BYTES: usize = 36;
const RESPONSE_BYTES: usize = 28;
const STOP_BARRIER_FEATURE: u64 = 1;
const PARK_STOP: u32 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Preparing,
    Armed,
    Applying,
    IdentityReady,
    Activating,
    FailedHeld,
    Parking,
    Parked,
    StopParked,
    Releasing,
    Aborting,
    Released,
    Aborted,
    Expired,
    FailedThawed,
    Uncertain,
}

impl Phase {
    fn terminal(self) -> bool {
        matches!(
            self,
            Self::Released | Self::Aborted | Self::Expired | Self::FailedThawed
        )
    }

    fn wire(self) -> &'static str {
        match self {
            Self::Preparing => "preparing",
            Self::Armed => "armed",
            Self::Applying => "applying",
            Self::IdentityReady => "identity_ready",
            Self::Activating => "activating",
            Self::FailedHeld => "failed_held",
            Self::Parking => "parking",
            Self::Parked => "parked",
            Self::StopParked => "stop_parked",
            Self::Releasing => "releasing",
            Self::Aborting => "aborting",
            Self::Released => "released",
            Self::Aborted => "aborted",
            Self::Expired => "expired_thawed",
            Self::FailedThawed => "failed_thawed",
            Self::Uncertain => "unknown",
        }
    }
}

struct Session {
    number: u32,
    nonce: u128,
    freeze_ms: u32,
    hold_ms: u32,
    phase: Phase,
    error: i32,
}

pub struct GuestGate {
    helper_digest: Option<[u8; 32]>,
    target_scope: Option<TargetScope>,
    target_bound: bool,
    target_session: u32,
    target_done: bool,
    identity_frame: [u8; 256],
    request_digest: Option<[u8; 32]>,
    network_park: bool,
    target_uplinks: Option<(ParkedUplink, ParkedUplink)>,
    anchor: [u8; 16],
    features: u64,
    interrupt: Option<InterruptTransport>,
    session: Option<Session>,
    command: [u8; COMMAND_BYTES],
    response: [u8; RESPONSE_BYTES],
}

impl Default for GuestGate {
    fn default() -> Self {
        Self {
            helper_digest: None,
            target_scope: None,
            target_bound: false,
            target_session: 1,
            target_done: false,
            identity_frame: [0; 256],
            request_digest: None,
            network_park: false,
            target_uplinks: None,
            anchor: [0; 16],
            features: 0,
            interrupt: None,
            session: None,
            command: [0; COMMAND_BYTES],
            response: [0; RESPONSE_BYTES],
        }
    }
}

impl GuestGate {
    pub fn with_helper(helper_digest: Option<[u8; 32]>) -> Self {
        Self {
            helper_digest,
            ..Self::default()
        }
    }

    pub fn provision_target(&mut self, scope: Option<TargetScope>) {
        self.target_scope = scope;
    }

    pub fn parked(&self, number: u32, nonce: u128) -> bool {
        self.session
            .as_ref()
            .is_some_and(|s| s.phase == Phase::Parked && s.number == number && s.nonce == nonce)
    }

    pub fn stop_supported(&self) -> bool {
        self.features & STOP_BARRIER_FEATURE != 0
    }

    pub fn stop_parked(&self, number: u32, nonce: u128) -> bool {
        self.session.as_ref().is_some_and(|s| {
            s.phase == Phase::StopParked && s.number == number && s.nonce == nonce
        })
    }

    pub fn source_released(&self, number: u32, nonce: u128) -> bool {
        self.session
            .as_ref()
            .is_some_and(|s| s.phase == Phase::Released && s.number == number && s.nonce == nonce)
    }

    pub fn source_status(&self) -> (u32, &'static str, bool) {
        let (number, phase) = self
            .session
            .as_ref()
            .map_or((0, "idle"), |s| (s.number, s.phase.wire()));
        (number, phase, self.helper_digest.is_some())
    }

    pub fn packets_parked(&self) -> bool {
        self.network_park
            && self
                .session
                .as_ref()
                .is_some_and(|s| s.phase == Phase::Parked)
    }

    pub fn parked_identity(&self) -> Option<([u8; 16], [u8; 32])> {
        self.session.as_ref().filter(|s| s.phase == Phase::Parked)?;
        Some((self.anchor, self.helper_digest?))
    }

    pub fn allows_raw_standby(&self) -> bool {
        self.session.as_ref().is_none_or(|s| s.phase.terminal())
    }

    fn publish(&mut self, opcode: u32) {
        // Readers sample the revision before and after loading the command.
        let revision = u32::from_le_bytes(self.command[..4].try_into().unwrap()).wrapping_add(1);
        self.command[..4].copy_from_slice(&revision.to_le_bytes());
        let session = self.session.as_ref().unwrap();
        self.command[4..8].copy_from_slice(&session.number.to_le_bytes());
        self.command[8..12].copy_from_slice(&opcode.to_le_bytes());
        self.command[12..16].copy_from_slice(&session.freeze_ms.to_le_bytes());
        self.command[16..20].copy_from_slice(&session.hold_ms.to_le_bytes());
        self.command[20..36].copy_from_slice(&session.nonce.to_le_bytes());
        self.response.fill(0);
        if let Some(interrupt) = &self.interrupt {
            interrupt.signal_config_change();
        }
    }

    pub fn control(&mut self, verb: &str, arguments: &str) -> Result<String, &'static str> {
        if self.target_scope.is_some() && !self.target_done {
            return Err("EPERM target requires its private host authority");
        }
        let mut fields = arguments.split_ascii_whitespace();
        let number = fields
            .next()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|v| *v != 0)
            .ok_or("EINVAL expected a nonzero session number")?;
        let nonce = fields
            .next()
            .filter(|v| v.len() == 32 && v.bytes().all(|b| b.is_ascii_hexdigit()))
            .and_then(|v| u128::from_str_radix(v, 16).ok())
            .filter(|v| *v != 0)
            .ok_or("EINVAL expected a 128-bit session challenge")?;
        if verb == "GUEST_GATE_PREPARE" {
            let mut deadline = |min, max| {
                fields
                    .next()
                    .and_then(|v| v.parse::<u32>().ok())
                    .filter(|v| (min..=max).contains(v))
                    .ok_or("EINVAL invalid gate deadline")
            };
            let freeze_ms = deadline(100, 3000)?;
            let hold_ms = deadline(100, 60000)?;
            if fields.next().is_some() {
                return Err("EINVAL trailing gate parameters");
            }
            let replay = self
                .session
                .as_ref()
                .is_some_and(|s| s.number == number && s.nonce == nonce);
            if replay {
                let s = self.session.as_ref().unwrap();
                if (s.freeze_ms, s.hold_ms) != (freeze_ms, hold_ms) {
                    return Err("EINVAL gate replay has different deadlines");
                }
            } else {
                if self.interrupt.is_none() {
                    return Err("EAGAIN guest driver is inactive");
                }
                if let Some(s) = &self.session {
                    if number <= s.number {
                        return Err("ESTALE stale gate session");
                    }
                    if !s.phase.terminal() {
                        return Err("EBUSY gate session is active");
                    }
                }
                self.network_park = false;
                self.anchor.fill(0);
                self.session = Some(Session {
                    number,
                    nonce,
                    freeze_ms,
                    hold_ms,
                    phase: Phase::Preparing,
                    error: 0,
                });
                self.publish(if self.helper_digest.is_some() { 4 } else { 1 });
            }
        } else {
            let request_network = verb == "GUEST_GATE_PARK_NETWORK";
            let park = match verb {
                "GUEST_GATE_PARK" => Some(5),
                "GUEST_GATE_PARK_NETWORK" => Some(8),
                "GUEST_GATE_PARK_STOP" if self.stop_supported() => Some(PARK_STOP),
                "GUEST_GATE_PARK_STOP" => return Err("ENOTSUP Guest kernel did not negotiate the stop barrier"),
                _ => None,
            };
            let anchor = if park.is_some() {
                let value = fields
                    .next()
                    .filter(|v| v.len() == 32 && v.bytes().all(|b| b.is_ascii_hexdigit()))
                    .and_then(|v| u128::from_str_radix(v, 16).ok())
                    .filter(|v| *v != 0 && *v != nonce)
                    .ok_or("EINVAL expected a distinct nonzero capture anchor")?;
                if self.helper_digest.is_none() {
                    return Err("ENOTSUP measured helper is required to park");
                }
                Some(value.to_be_bytes())
            } else {
                None
            };
            if fields.next().is_some() {
                return Err("EINVAL trailing gate parameters");
            }
            let s = self
                .session
                .as_mut()
                .filter(|s| s.number == number && s.nonce == nonce)
                .ok_or("ESTALE unknown gate session")?;
            match (park, verb, s.phase) {
                (_, "GUEST_GATE_QUERY", _) => (),
                (Some(opcode), _, Phase::Armed) => {
                    self.network_park = request_network;
                    self.anchor = anchor.unwrap();
                    s.phase = Phase::Parking;
                    self.publish(opcode);
                }
                (Some(opcode), _, Phase::Parking | Phase::Parked | Phase::StopParked)
                    if Some(self.anchor) == anchor
                        && u32::from_le_bytes(self.command[8..12].try_into().unwrap()) == opcode =>
                {
                    ()
                }
                (_, "GUEST_GATE_RELEASE", Phase::Armed | Phase::Parked | Phase::StopParked) => {
                    s.phase = Phase::Releasing;
                    self.publish(2);
                }
                (_, "GUEST_GATE_RELEASE", Phase::Releasing | Phase::Released) => (),
                (_, "GUEST_GATE_ABORT", Phase::Preparing | Phase::Armed | Phase::Parked | Phase::StopParked) => {
                    s.phase = Phase::Aborting;
                    self.publish(3);
                }
                (_, "GUEST_GATE_ABORT", Phase::Aborting | Phase::Aborted) => (),
                _ => return Err("EINVAL gate decision conflicts with current phase"),
            }
        }
        let s = self.session.as_ref().unwrap();
        Ok(format!(
            "OK {} {:032x} {} {}\n",
            s.number,
            s.nonce,
            s.phase.wire(),
            s.error
        ))
    }

    fn acknowledge(&mut self) {
        let Some(s) = self.session.as_mut() else {
            return;
        };
        let number = u32::from_le_bytes(self.response[..4].try_into().unwrap());
        let nonce = u128::from_le_bytes(self.response[4..20].try_into().unwrap());
        if number != s.number || nonce != s.nonce || self.interrupt.is_none() {
            return;
        }
        let error = i32::from_le_bytes(self.response[20..24].try_into().unwrap());
        let status = u32::from_le_bytes(self.response[24..28].try_into().unwrap());
        let command = u32::from_le_bytes(self.command[8..12].try_into().unwrap());
        let next = match (s.phase, status, error) {
            (Phase::Preparing, 1, 0) => Phase::Armed,
            (Phase::Parking, 6, 0) if command == 5 => Phase::Parked,
            (Phase::Parking, 9, 0) if self.network_park => Phase::Parked,
            (Phase::Parking, 10, 0) if command == PARK_STOP => Phase::StopParked,
            (Phase::Applying, 7, 0) => Phase::IdentityReady,
            (Phase::Applying | Phase::Activating, 8, e) if e < 0 => Phase::FailedHeld,
            (Phase::Activating, 2, 0) => Phase::Released,
            (Phase::Releasing, 2, 0) => Phase::Released,
            (Phase::Aborting, 3, 0) => Phase::Aborted,
            (
                Phase::Preparing
                | Phase::Armed
                | Phase::Parking
                | Phase::Releasing
                | Phase::Aborting,
                4,
                e,
            ) if e == -libc::ETIMEDOUT => Phase::Expired,
            (
                Phase::Preparing
                | Phase::Armed
                | Phase::Parking
                | Phase::Releasing
                | Phase::Aborting,
                5,
                e,
            ) if e < 0 => Phase::FailedThawed,
            _ => return,
        };
        if matches!(next, Phase::IdentityReady | Phase::FailedHeld) {
            self.identity_frame[64..].fill(0);
        }
        if next == Phase::FailedHeld {
            warn!("Guest gate target {} failed with guest errno {error}", s.phase.wire());
        }
        if s.phase == Phase::Activating && next == Phase::Released {
            self.target_done = true;
        }
        s.phase = next;
        s.error = error;
    }
}

impl VirtioDevice for GuestGate {
    fn avail_features(&self) -> u64 {
        (1 << 32) | STOP_BARRIER_FEATURE
    }
    fn acked_features(&self) -> u64 {
        self.features
    }
    fn set_acked_features(&mut self, value: u64) {
        self.features = value & self.avail_features();
    }
    fn device_type(&self) -> u32 {
        DEVICE_TYPE
    }
    fn device_name(&self) -> &str {
        "smolvm-guest-gate"
    }
    fn queue_config(&self) -> &[QueueConfig] {
        &[]
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        data.fill(0);
        let index = offset as usize;
        let Some(end) = index.checked_add(data.len()) else {
            return;
        };
        if (112..368).contains(&index) && end <= 368 {
            if self
                .session
                .as_ref()
                .is_some_and(|s| s.phase == Phase::Applying)
            {
                data.copy_from_slice(&self.identity_frame[index - 112..end - 112]);
            }
            return;
        }
        if (96..112).contains(&index) && end <= 112 {
            data.copy_from_slice(&self.anchor[index - 96..end - 96]);
            return;
        }
        if (64..96).contains(&index) && end <= 96 {
            if let Some(digest) = &self.helper_digest {
                data.copy_from_slice(&digest[index - 64..end - 64]);
            }
            return;
        }
        if let Some(bytes) = self.command.get(index..end) {
            data.copy_from_slice(bytes);
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        if data.len() != 4 || !(36..=60).contains(&offset) || offset % 4 != 0 {
            return;
        }
        let index = offset as usize - COMMAND_BYTES;
        self.response[index..index + 4].copy_from_slice(data);
        if offset == 60 {
            self.acknowledge();
        }
    }

    fn activate(
        &mut self,
        _: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if !queues.is_empty() {
            return Err(ActivateError::BadActivate);
        }
        self.interrupt = Some(interrupt);
        Ok(())
    }
    fn is_activated(&self) -> bool {
        self.interrupt.is_some()
    }

    fn reset(&mut self) -> bool {
        self.interrupt = None;
        self.features = 0;
        self.command.fill(0);
        self.response.fill(0);
        if let Some(s) = self.session.as_mut()
            && !s.phase.terminal()
        {
            s.phase = Phase::Uncertain;
            s.error = -libc::ECONNRESET;
        }
        true
    }

    fn snapshot_error(&self) -> Option<&str> {
        Some("guest gate requires a host-bound capture and restore protocol")
    }
}
