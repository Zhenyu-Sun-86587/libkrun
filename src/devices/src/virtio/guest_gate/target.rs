// SPDX-License-Identifier: Apache-2.0
use super::{GuestGate, Phase, Session};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
pub struct TargetScope {
    pub anchor: [u8; 16],
    pub epoch: u64,
    pub context: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ParkedUplink {
    pub device_id: String,
    pub attachment: [u8; 32],
    pub mac: [u8; 6],
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ParkedState {
    pub acked_features: u64,
    pub anchor: [u8; 16],
    pub helper: [u8; 32],
    /// Identifiers of the allowed hardware and immutable storage at the boundary.
    pub bindings: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uplink: Option<ParkedUplink>,
}

impl GuestGate {
    pub fn bind_uplinks(
        &mut self,
        source: Option<&ParkedUplink>,
        target: Option<ParkedUplink>,
    ) -> Result<(), String> {
        self.target_uplinks = match (source, target) {
            (None, None) => None,
            (Some(old), Some(new))
                if old.device_id == new.device_id && old.attachment != new.attachment =>
            {
                Some((old.clone(), new))
            }
            _ => {
                return Err(
                    "target requires a freshly provisioned TAP for the captured uplink".into(),
                );
            }
        };
        Ok(())
    }

    fn valid_frame(&self, frame: &[u8]) -> bool {
        match &self.target_uplinks {
            None => frame.len() == 192 && &frame[..8] == b"SGI1\x01\0\0\0",
            Some((source, target)) => {
                frame.len() == 256
                    && &frame[..8] == b"SGI2\x02\0\0\0"
                    && &frame[192..196] == b"NET1"
                    && frame[200..206] == source.mac
                    && frame[206..212] == target.mac
            }
        }
    }

    pub fn bind_target(&mut self, state: &ParkedState) -> Result<(), String> {
        let scope = self
            .target_scope
            .ok_or("restoring a parked Guest requires a new host authority")?;
        if state.anchor != scope.anchor
            || self.helper_digest != Some(state.helper)
            || state.uplink.as_ref() != self.target_uplinks.as_ref().map(|(old, _)| old)
            || self.session.is_some()
        {
            return Err("parked source or measured helper does not match the target".into());
        }
        self.anchor = state.anchor;
        self.target_bound = true;
        Ok(())
    }

    /// Commands on the private authority socket. A source control socket cannot
    /// send identity, authorize a child or replay a captured source decision.
    pub fn target_request(&mut self, packet: &[u8]) -> Result<&'static str, &'static str> {
        let scope = self.target_scope.ok_or("missing target scope")?;
        if !self.target_bound || self.interrupt.is_none() {
            return Err("target is unbound");
        }
        if self.target_done {
            let replay = match packet {
                [2 | 3, binding @ ..] => binding == &self.identity_frame[8..64],
                [1, frame @ ..] if self.valid_frame(frame) => {
                    Some(<[u8; 32]>::from(Sha256::digest(frame))) == self.request_digest
                }
                _ => false,
            };
            return if replay {
                Ok("released")
            } else {
                Err("stale completed target authority")
            };
        }
        match packet {
            [1, frame @ ..] if self.valid_frame(frame) => {
                let nonce = u128::from_le_bytes(frame[8..24].try_into().unwrap());
                let epoch = u64::from_le_bytes(frame[24..32].try_into().unwrap());
                if nonce == 0
                    || epoch != scope.epoch
                    || frame[32..64] != scope.context
                    || frame[64..96].iter().all(|v| *v == 0)
                {
                    return Err("invalid target identity scope");
                }
                let digest: [u8; 32] = Sha256::digest(frame).into();
                if self.session.is_some() {
                    if self.request_digest != Some(digest) {
                        return Err("identity is already bound");
                    }
                } else {
                    self.request_digest = Some(digest);
                    self.identity_frame[..frame.len()].copy_from_slice(frame);
                    self.session = Some(Session {
                        number: 1,
                        nonce,
                        freeze_ms: 0,
                        hold_ms: 0,
                        phase: Phase::Applying,
                        error: 0,
                    });
                    self.publish(if self.target_uplinks.is_some() { 9 } else { 6 });
                }
            }
            [op @ (2 | 3), scope_bytes @ ..] if scope_bytes.len() == 56 => {
                if scope_bytes != &self.identity_frame[8..64] {
                    return Err("stale target authority");
                }
                let session = self.session.as_mut().ok_or("identity has not begun")?;
                if *op == 3 {
                    match session.phase {
                        Phase::IdentityReady => {
                            session.phase = Phase::Activating;
                            self.publish(7);
                        }
                        Phase::Activating | Phase::Released => (),
                        _ => return Err("identity is not ready for activation"),
                    }
                }
            }
            _ => return Err("invalid target authority request"),
        }
        Ok(self.session.as_ref().unwrap().phase.wire())
    }

    pub fn target_quarantined(&self) -> bool {
        self.target_scope.is_some() && !self.target_done
    }
}
