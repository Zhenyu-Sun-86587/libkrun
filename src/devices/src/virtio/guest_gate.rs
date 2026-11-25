// SPDX-License-Identifier: Apache-2.0
//! Host-controlled freezer mailbox. This transport has no DMA queues. Its
//! session and guest acknowledgements belong to one live VMM.
use super::{
    ActivateError, ActivateResult, DeviceQueue, InterruptTransport, QueueConfig, VirtioDevice,
};
use vm_memory::GuestMemoryMmap;

pub const DEVICE_TYPE: u32 = 0xff51;
const COMMAND_BYTES: usize = 36;
const RESPONSE_BYTES: usize = 28;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Preparing,
    Armed,
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
    features: u64,
    interrupt: Option<InterruptTransport>,
    session: Option<Session>,
    command: [u8; COMMAND_BYTES],
    response: [u8; RESPONSE_BYTES],
}

impl Default for GuestGate {
    fn default() -> Self {
        Self {
            features: 0,
            interrupt: None,
            session: None,
            command: [0; COMMAND_BYTES],
            response: [0; RESPONSE_BYTES],
        }
    }
}

impl GuestGate {
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
                self.session = Some(Session {
                    number,
                    nonce,
                    freeze_ms,
                    hold_ms,
                    phase: Phase::Preparing,
                    error: 0,
                });
                self.publish(1);
            }
        } else {
            if fields.next().is_some() {
                return Err("EINVAL trailing gate parameters");
            }
            let s = self
                .session
                .as_mut()
                .filter(|s| s.number == number && s.nonce == nonce)
                .ok_or("ESTALE unknown gate session")?;
            match (verb, s.phase) {
                ("GUEST_GATE_QUERY", _) => (),
                ("GUEST_GATE_RELEASE", Phase::Armed) => {
                    s.phase = Phase::Releasing;
                    self.publish(2);
                }
                ("GUEST_GATE_RELEASE", Phase::Releasing | Phase::Released) => (),
                ("GUEST_GATE_ABORT", Phase::Preparing | Phase::Armed) => {
                    s.phase = Phase::Aborting;
                    self.publish(3);
                }
                ("GUEST_GATE_ABORT", Phase::Aborting | Phase::Aborted) => (),
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
        let next = match (s.phase, status, error) {
            (Phase::Preparing, 1, 0) => Phase::Armed,
            (Phase::Releasing, 2, 0) => Phase::Released,
            (Phase::Aborting, 3, 0) => Phase::Aborted,
            (Phase::Preparing | Phase::Armed | Phase::Releasing | Phase::Aborting, 4, e)
                if e == -libc::ETIMEDOUT =>
            {
                Phase::Expired
            }
            (Phase::Preparing | Phase::Armed | Phase::Releasing | Phase::Aborting, 5, e)
                if e < 0 =>
            {
                Phase::FailedThawed
            }
            _ => return,
        };
        s.phase = next;
        s.error = error;
    }
}

impl VirtioDevice for GuestGate {
    fn avail_features(&self) -> u64 {
        1 << 32
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
