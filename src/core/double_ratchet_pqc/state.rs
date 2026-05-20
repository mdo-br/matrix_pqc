//! PQC hybrid Double Ratchet state machine.

use crate::core::crypto::{CryptoError, KemAlgorithm};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use hkdf::Hkdf;
use crate::utils::logging::VerbosityLevel;
use crate::vlog;
use super::keys::{PqcRatchetKeyPair, PqcRatchetPublicKey};

type HmacSha256 = Hmac<Sha256>;

// Derivation constants following the OLM convention
const MESSAGE_KEY_SEED: &[u8; 1] = b"\x01";

// Constants reserved for future implementation
#[allow(dead_code)]
const MAX_RECEIVING_CHAINS: usize = 5;
#[allow(dead_code)]
const MAX_MESSAGE_KEYS: usize = 40;
#[allow(dead_code)]
const MAX_MESSAGE_GAP: u64 = 2000;

/// Hybrid Double Ratchet states (following the vodozemac convention).
///
/// `Clone` is intentionally not derived; private keys inside each variant are
/// protected by `ZeroizingKyber*Key` wrappers.
pub enum PqcRatchetState {
    /// Sending direction: has an active chain key for the next outgoing message.
    Active {
        root_key: [u8; 32],
        our_ratchet_keys: PqcRatchetKeyPair,
        their_ratchet_key: Option<PqcRatchetPublicKey>,
        chain_key: [u8; 32],
        send_counter: u32,
    },
    /// Receiving direction: waiting to send in order to trigger an asymmetric advance.
    Inactive {
        root_key: [u8; 32],
        our_ratchet_keys: PqcRatchetKeyPair,
        their_ratchet_key: PqcRatchetPublicKey,
        receive_counter: u32,
    },
}

/// Full state of the hybrid Double Ratchet.
pub struct PqcDoubleRatchetState {
    /// Current ratchet state (Active or Inactive).
    pub(super) state: PqcRatchetState,
    /// Whether hybrid mode is enabled.
    hybrid_mode_enabled: bool,
    /// KEM algorithm used for this session.
    pub(super) kem_algorithm: KemAlgorithm,
    /// Number of asymmetric advances (direction changes) performed so far.
    pub(super) asymmetric_advance_count: u32,
}

impl PqcDoubleRatchetState {
    /// Creates a new state seeded from a PQXDH root key.
    pub fn new(
        initial_root_key: [u8; 32],
        kem_algorithm: KemAlgorithm,
        starts_as_sender: bool,
    ) -> Self {
        vlog!(
            VerbosityLevel::Debug,
            "Inicializando Double Ratchet PQC com {} (sender: {})",
            kem_algorithm.name(),
            starts_as_sender
        );

        let our_ratchet_keys = PqcRatchetKeyPair::generate(kem_algorithm);

        let state = if starts_as_sender {
            let chain_key = Self::derive_initial_chain_key(&initial_root_key);
            PqcRatchetState::Active {
                root_key: initial_root_key,
                our_ratchet_keys,
                their_ratchet_key: None,
                chain_key,
                send_counter: 0,
            }
        } else {
            let temp_their_key = PqcRatchetKeyPair::generate(kem_algorithm).public_keys();
            PqcRatchetState::Inactive {
                root_key: initial_root_key,
                our_ratchet_keys,
                their_ratchet_key: temp_their_key,
                receive_counter: 0,
            }
        };

        Self {
            state,
            hybrid_mode_enabled: true,
            kem_algorithm,
            asymmetric_advance_count: 0,
        }
    }

    /// Derives the initial chain key from the root key.
    fn derive_initial_chain_key(root_key: &[u8; 32]) -> [u8; 32] {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"pqc-initial-chain-key-v1");
        hasher.update(root_key);
        hasher.finalize().into()
    }

    /// Derives a chain key from the hybrid secret for consecutive messages.
    fn derive_chain_key_from_hybrid(
        hybrid_secret: &[u8],
        message_counter: u32,
    ) -> Result<[u8; 32], CryptoError> {
        let salt = b"matrix-hybrid-chain-key-v1";
        let info = format!("hybrid-chain-msg-{}", message_counter);
        let hk = Hkdf::<Sha256>::new(Some(salt), hybrid_secret);
        let mut chain_key = [0u8; 32];
        hk.expand(info.as_bytes(), &mut chain_key)
            .map_err(|_| CryptoError::Protocol)?;
        Ok(chain_key)
    }

    /// Derives a message key from the chain key (OLM convention: seed `0x01`).
    pub(super) fn derive_message_key_from_chain(
        chain_key: &[u8; 32],
    ) -> Result<[u8; 32], CryptoError> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(chain_key).map_err(|_| CryptoError::Protocol)?;
        mac.update(MESSAGE_KEY_SEED);
        let result = mac.finalize();
        let bytes = result.into_bytes();
        let mut message_key = [0u8; 32];
        message_key.copy_from_slice(&bytes);
        Ok(message_key)
    }

    /// Sets the peer's public ratchet key (session initialisation).
    pub fn set_peer_ratchet_key(&mut self, peer_key: PqcRatchetPublicKey) {
        match &mut self.state {
            PqcRatchetState::Active {
                their_ratchet_key, ..
            } => {
                *their_ratchet_key = Some(peer_key);
            }
            PqcRatchetState::Inactive {
                their_ratchet_key, ..
            } => {
                *their_ratchet_key = peer_key;
            }
        }
    }

    /// Advances the ratchet for sending, performing a KEM encapsulation when needed.
    ///
    /// Returns `(chain_key, kem_ciphertext)`. `kem_ciphertext` is `Some` only on an
    /// Inactive → Active transition (direction change / asymmetric advance).
    pub fn advance_sending_ratchet_with_kem(
        &mut self,
    ) -> Result<([u8; 32], Option<Vec<u8>>), CryptoError> {
        let old_state = std::mem::replace(
            &mut self.state,
            PqcRatchetState::Active {
                root_key: [0u8; 32],
                our_ratchet_keys: PqcRatchetKeyPair::generate(self.kem_algorithm),
                their_ratchet_key: None,
                chain_key: [0u8; 32],
                send_counter: 0,
            },
        );

        match old_state {
            PqcRatchetState::Inactive {
                root_key,
                our_ratchet_keys: _,
                their_ratchet_key,
                receive_counter: _,
            } => {
                // Inactive → Active: asymmetric advance (direction change)
                vlog!(
                    VerbosityLevel::Normal,
                    " Troca de direção: avanço da catraca assimétrica!"
                );
                self.asymmetric_advance_count += 1;

                let new_ratchet_keys = PqcRatchetKeyPair::generate(self.kem_algorithm);
                let (hybrid_secret, kem_ciphertext) =
                    new_ratchet_keys.hybrid_dh_with_kem(&their_ratchet_key)?;
                let (new_root_key, chain_key) =
                    Self::derive_root_chain_keys(&hybrid_secret, &root_key)?;

                vlog!(
                    VerbosityLevel::Debug,
                    " Ratchet PQC avançado: envio #1 ({})",
                    self.kem_algorithm.name()
                );
                vlog!(
                    VerbosityLevel::Normal,
                    "   Nova root key: {}",
                    hex::encode(&new_root_key[..8])
                );

                self.state = PqcRatchetState::Active {
                    root_key: new_root_key,
                    our_ratchet_keys: new_ratchet_keys,
                    their_ratchet_key: Some(their_ratchet_key),
                    chain_key,
                    send_counter: 1,
                };

                Ok((chain_key, Some(kem_ciphertext)))
            }
            PqcRatchetState::Active {
                root_key,
                our_ratchet_keys,
                their_ratchet_key,
                chain_key: old_chain_key,
                send_counter,
            } => {
                // Still Active: symmetric advance (chain key only)
                vlog!(
                    VerbosityLevel::Normal,
                    "  Canal ativo: avanço simétrico da chain key (mesmo destinatário)"
                );

                let mut mac = HmacSha256::new_from_slice(&old_chain_key)
                    .map_err(|_| CryptoError::Protocol)?;
                mac.update(&[0x02]);
                let new_chain_key: [u8; 32] = mac.finalize().into_bytes().into();
                let new_counter = send_counter + 1;

                self.state = PqcRatchetState::Active {
                    root_key,
                    our_ratchet_keys,
                    their_ratchet_key,
                    chain_key: new_chain_key,
                    send_counter: new_counter,
                };

                vlog!(
                    VerbosityLevel::Debug,
                    "    Nova chain key: {}...",
                    hex::encode(&new_chain_key[..8])
                );

                Ok((new_chain_key, None))
            }
        }
    }

    /// Returns `true` if the peer's ratchet key has changed since the last advance.
    pub fn has_peer_key_changed(&self, new_key: &PqcRatchetPublicKey) -> bool {
        match &self.state {
            PqcRatchetState::Active {
                their_ratchet_key, ..
            } => {
                if let Some(ref current_key) = their_ratchet_key {
                    current_key.to_bytes() != new_key.to_bytes()
                } else {
                    true
                }
            }
            PqcRatchetState::Inactive {
                their_ratchet_key, ..
            } => their_ratchet_key.to_bytes() != new_key.to_bytes(),
        }
    }

    /// Advances the ratchet for receiving, decapsulating the KEM ciphertext.
    pub fn advance_receiving_ratchet_with_decapsulate(
        &mut self,
        peer_new_key: &PqcRatchetPublicKey,
        kem_ciphertext: Option<&[u8]>,
    ) -> Result<[u8; 32], CryptoError> {
        if peer_new_key.kem_algorithm != self.kem_algorithm {
            return Err(CryptoError::Protocol);
        }

        let old_state = std::mem::replace(
            &mut self.state,
            PqcRatchetState::Active {
                root_key: [0u8; 32],
                our_ratchet_keys: PqcRatchetKeyPair::generate(self.kem_algorithm),
                their_ratchet_key: None,
                chain_key: [0u8; 32],
                send_counter: 0,
            },
        );

        match old_state {
            PqcRatchetState::Active {
                root_key,
                our_ratchet_keys,
                their_ratchet_key: _,
                send_counter: _,
                chain_key: _,
            } => {
                // Active → Inactive
                self.asymmetric_advance_count += 1;

                let kem_ct = kem_ciphertext.ok_or(CryptoError::Protocol)?;
                let hybrid_secret =
                    our_ratchet_keys.hybrid_dh_with_decapsulate(peer_new_key, kem_ct)?;
                let (new_root_key, chain_key) =
                    Self::derive_root_chain_keys(&hybrid_secret, &root_key)?;
                let new_our_keys = PqcRatchetKeyPair::generate(self.kem_algorithm);

                self.state = PqcRatchetState::Inactive {
                    root_key: new_root_key,
                    our_ratchet_keys: new_our_keys,
                    their_ratchet_key: peer_new_key.clone(),
                    receive_counter: 1,
                };

                vlog!(
                    VerbosityLevel::Normal,
                    "  Recebimento: Active → Inactive (aguardando envio) - KEM decapsulate"
                );
                vlog!(
                    VerbosityLevel::Normal,
                    "   Nova root key: {}",
                    hex::encode(&new_root_key[..8])
                );

                Ok(chain_key)
            }
            PqcRatchetState::Inactive {
                root_key,
                our_ratchet_keys,
                their_ratchet_key: _,
                receive_counter,
            } => {
                // Already Inactive: consecutive messages from the peer
                let new_counter = receive_counter + 1;

                let kem_ct = kem_ciphertext.ok_or(CryptoError::Protocol)?;
                let hybrid_secret =
                    our_ratchet_keys.hybrid_dh_with_decapsulate(peer_new_key, kem_ct)?;
                let chain_key = Self::derive_chain_key_from_hybrid(&hybrid_secret, new_counter)?;

                self.state = PqcRatchetState::Inactive {
                    root_key,
                    our_ratchet_keys,
                    their_ratchet_key: peer_new_key.clone(),
                    receive_counter: new_counter,
                };

                vlog!(
                    VerbosityLevel::Normal,
                    "  Recebimento: permanece Inactive (mensagem #{}) - KEM decapsulate",
                    new_counter
                );

                Ok(chain_key)
            }
        }
    }

    /// Derives the new root key and chain key via HKDF (accepts dynamic input sizes).
    pub(super) fn derive_root_chain_keys(
        hybrid_dh: &[u8],
        current_root_key: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32]), CryptoError> {
        let salt = b"matrix-ratchet-root-derivation-v1";
        let info = b"root-chain-keys";
        let hk = Hkdf::<Sha256>::new(Some(salt), hybrid_dh);

        const SHA256_SIZE: usize = 32;
        let mut expanded = [0u8; SHA256_SIZE * 2];
        hk.expand(info, &mut expanded)
            .map_err(|_| CryptoError::Protocol)?;

        // XOR with the current root key (ratcheting property)
        for i in 0..SHA256_SIZE {
            expanded[i] ^= current_root_key[i];
        }

        let new_root_key: [u8; SHA256_SIZE] = expanded[0..SHA256_SIZE].try_into().unwrap();
        let chain_key: [u8; SHA256_SIZE] =
            expanded[SHA256_SIZE..(SHA256_SIZE * 2)].try_into().unwrap();

        Ok((new_root_key, chain_key))
    }

    /// Returns current ratchet statistics.
    pub fn get_ratchet_stats(&self) -> RatchetStats {
        let (messages_sent, messages_received, root_key_hash) = match &self.state {
            PqcRatchetState::Active {
                root_key,
                send_counter,
                ..
            } => (*send_counter, 0, hex::encode(&root_key[..8])),
            PqcRatchetState::Inactive {
                root_key,
                receive_counter,
                ..
            } => (0, *receive_counter, hex::encode(&root_key[..8])),
        };

        RatchetStats {
            messages_sent,
            messages_received,
            hybrid_mode: self.hybrid_mode_enabled,
            current_root_key_hash: root_key_hash,
            ratchet_advances: messages_sent + messages_received,
            asymmetric_advances: self.asymmetric_advance_count,
        }
    }
}

/// Ratchet statistics snapshot.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct RatchetStats {
    pub messages_sent: u32,
    pub messages_received: u32,
    pub hybrid_mode: bool,
    pub current_root_key_hash: String,
    pub ratchet_advances: u32,
    pub asymmetric_advances: u32,
}
