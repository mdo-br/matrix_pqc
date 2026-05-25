//! PQXDH protocol data types: keys, messages, and zeroization wrappers.

use pqcrypto_kyber::kyber1024::SecretKey as KyberSecretKey;
use serde::{Serialize, Deserialize};
use crate::utils::serde_helpers;

/// Wraps `KyberSecretKey` with manual zeroization on `Drop`.
///
/// `pqcrypto-kyber` does not implement `Zeroize`, unlike the `dalek` crates which
/// provide it natively. This wrapper overwrites key memory when dropped.
pub(super) struct ZeroizingKyberKey(pub(super) KyberSecretKey);

impl Drop for ZeroizingKyberKey {
    fn drop(&mut self) {
        unsafe {
            let ptr = &mut self.0 as *mut KyberSecretKey as *mut u8;
            std::ptr::write_bytes(ptr, 0, std::mem::size_of::<KyberSecretKey>());
        }
    }
}

impl std::ops::Deref for ZeroizingKyberKey {
    type Target = KyberSecretKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<KyberSecretKey> for ZeroizingKyberKey {
    fn as_ref(&self) -> &KyberSecretKey {
        &self.0
    }
}

/// Signed X25519 prekey for Matrix.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedX25519Prekey {
    pub key_id: String,
    #[serde(with = "serde_helpers::bytes_32")]
    pub public_key: [u8; 32],
    #[serde(with = "serde_helpers::bytes_64")]
    pub signature: [u8; 64],
}

/// Signed CRYSTALS-Kyber prekey for Matrix.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedKyberPrekey {
    pub key_id: String,
    #[serde(with = "serde_helpers::vec_bytes")]
    pub public_key: Vec<u8>,
    #[serde(with = "serde_helpers::bytes_64")]
    pub signature: [u8; 64],
}

/// PQXDH initialisation message sent by the initiator to the responder.
///
/// Carries all data needed to complete the key agreement, including ephemeral keys,
/// the Kyber KEM ciphertext, and prekey IDs used in this handshake.
///
/// Includes two identity keys following the vodozemac model:
/// - `sender_signing_key`: Ed25519, used only for signature verification.
/// - `sender_dh_public_key`: independent Curve25519, used for DH operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixPqxdhInitMessage {
    pub sender_user_id: String,
    #[serde(with = "serde_helpers::bytes_32")]
    pub sender_signing_key: [u8; 32],
    #[serde(with = "serde_helpers::bytes_32")]
    pub sender_dh_public_key: [u8; 32],
    #[serde(with = "serde_helpers::bytes_64")]
    pub sender_dh_key_signature: [u8; 64],
    #[serde(with = "serde_helpers::bytes_32")]
    pub ephemeral_key: [u8; 32],
    #[serde(with = "serde_helpers::vec_bytes")]
    pub kyber_ciphertext: Vec<u8>,
    pub used_x25519_prekey_id: String,
    pub used_kyber_prekey_id: String,
    pub used_one_time_key_id: Option<String>,
}

/// Output of a successful PQXDH initialisation: session key and message for the responder.
pub struct MatrixPqxdhOutput {
    pub session_key: [u8; 32],
    pub init_message: MatrixPqxdhInitMessage,
}
