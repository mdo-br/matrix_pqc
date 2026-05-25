//! `MatrixUser` struct and full PQXDH key hierarchy implementation.

use anyhow::Result;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, Signer};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret, ReusableSecret as X25519ReusableSecret};
use pqcrypto_kyber::kyber1024::{self};
use pqcrypto_traits::kem::PublicKey;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::{rngs::OsRng, CryptoRng, RngCore};
use std::collections::HashMap;
use super::message::{ZeroizingKyberKey, SignedX25519Prekey, SignedKyberPrekey};

/// Matrix user with the full PQXDH key hierarchy.
///
/// Holds all keys needed to participate in quantum-resistant hybrid key agreements.
///
/// # Key hierarchy (vodozemac model)
///
/// **Long-term identity keys** (never rotated):
/// - Ed25519 signing key — signs prekeys and messages only, never used in DH.
/// - Curve25519 DH key — generated independently (not derived from Ed25519), used in DH.
///   Bound to the signing key via a cross-signature.
///
/// **Medium-term prekeys** (rotated periodically):
/// - X25519 prekey — for ephemeral DH exchanges.
/// - Kyber-1024 prekey — for post-quantum KEM encapsulation.
/// Both are signed by the Ed25519 signing key.
///
/// **One-time keys** (consumed once, guarantee forward secrecy):
/// - X25519 OTKs — removed from storage after a single use.
///
/// # Zeroization
/// Ed25519 and X25519 keys are zeroized automatically by the `dalek` crates.
/// Kyber keys are wrapped in `ZeroizingKyberKey`, which overwrites memory on `Drop`.
pub struct MatrixUser {
    /// Matrix user ID (e.g. `@alice:matrix.org`).
    pub user_id: String,

    /// Matrix device ID.
    pub device_id: String,

    // --- Ed25519 signing key ---

    /// Long-term Ed25519 signing key (private). Used exclusively to sign prekeys.
    #[allow(dead_code)]
    signing_key: Box<SigningKey>,

    /// Long-term Ed25519 verifying key (public). Published for signature verification.
    pub signing_public_key: VerifyingKey,

    // --- Curve25519 DH identity key ---

    /// Long-term Curve25519 DH secret key. Generated independently from the Ed25519 key.
    pub(super) diffie_hellman_key: Box<X25519StaticSecret>,

    /// Long-term Curve25519 DH public key. Published for DH operations.
    pub dh_public_key: X25519PublicKey,

    /// Cross-signature: Ed25519 signing key signs the Curve25519 DH public key.
    pub(super) dh_key_signature: Signature,

    // --- Prekeys ---

    /// Medium-term X25519 prekey secret.
    pub(super) x25519_prekey_private: Box<X25519ReusableSecret>,

    /// Signed X25519 prekey, published to the Matrix homeserver.
    pub x25519_prekey: SignedX25519Prekey,

    /// Medium-term Kyber-1024 secret key for KEM decapsulation.
    pub(super) kyber_prekey_private: ZeroizingKyberKey,

    /// Signed Kyber-1024 prekey, published to the Matrix homeserver.
    pub kyber_prekey: SignedKyberPrekey,

    // --- One-time keys ---

    /// One-time key storage: key ID → private key.
    ///
    /// Each key is consumed exactly once. Lookup and removal are O(1),
    /// matching the Matrix `/keys/claim` model.
    one_time_keys_storage: HashMap<String, Box<X25519ReusableSecret>>,
}

impl MatrixUser {
    /// Creates a new `MatrixUser` with a freshly generated PQXDH key set.
    ///
    /// Generates an Ed25519 signing key, an independent Curve25519 DH key with its
    /// cross-signature, signed X25519 and Kyber-1024 prekeys, and an initial batch
    /// of 10 one-time keys. Uses `OsRng` for entropy.
    pub fn new(user_id: String, device_id: String) -> Result<Self> {
        Self::new_with_rng(user_id, device_id, &mut OsRng)
    }

    /// Creates a new `MatrixUser` with a caller-supplied RNG.
    ///
    /// Prefer [`Self::new`] in production. This variant exists for deterministic
    /// testing and embedded environments without access to `OsRng`.
    pub fn new_with_rng<R: CryptoRng + RngCore>(
        user_id: String,
        device_id: String,
        rng: &mut R,
    ) -> Result<Self> {
        // 1. Ed25519 signing key (fingerprint key)
        let signing_key = Box::new(SigningKey::generate(&mut *rng));
        let signing_public_key = signing_key.verifying_key();

        // 2. Independent Curve25519 DH key (not derived from Ed25519, per vodozemac model)
        let diffie_hellman_key = Box::new(X25519StaticSecret::random_from_rng(&mut *rng));
        let dh_public_key = X25519PublicKey::from(&*diffie_hellman_key);

        // 3. Cross-signature: Ed25519 signing key signs the Curve25519 DH public key
        let dh_key_signature = signing_key.sign(dh_public_key.as_bytes());

        // 4. X25519 prekey
        let x25519_prekey_private = Box::new(X25519ReusableSecret::random_from_rng(&mut *rng));
        let x25519_public_key = X25519PublicKey::from(&*x25519_prekey_private);
        let x25519_signature = signing_key.sign(x25519_public_key.as_bytes());
        let x25519_prekey = SignedX25519Prekey {
            key_id: format!("x25519_prekey_1"),
            public_key: *x25519_public_key.as_bytes(),
            signature: x25519_signature.to_bytes(),
        };

        // 5. Kyber-1024 prekey
        let (kyber_public_key, kyber_private_key) = kyber1024::keypair();
        let kyber_private_key = ZeroizingKyberKey(kyber_private_key);
        let kyber_signature = signing_key.sign(kyber_public_key.as_bytes());
        let kyber_prekey = SignedKyberPrekey {
            key_id: format!("kyber_prekey_1"),
            public_key: kyber_public_key.as_bytes().to_vec(),
            signature: kyber_signature.to_bytes(),
        };

        // 6. Initial batch of 10 one-time keys
        let mut one_time_keys_storage = HashMap::new();
        for i in 0..10 {
            let private_key = X25519ReusableSecret::random_from_rng(&mut *rng);
            let key_id = format!("otk_{}", i);
            one_time_keys_storage.insert(key_id, Box::new(private_key));
        }

        Ok(MatrixUser {
            user_id,
            device_id,
            signing_key,
            signing_public_key,
            diffie_hellman_key,
            dh_public_key,
            dh_key_signature,
            x25519_prekey_private,
            x25519_prekey,
            kyber_prekey_private: kyber_private_key,
            kyber_prekey,
            one_time_keys_storage,
        })
    }

    /// Exports public keys for homeserver upload (Matrix `/keys/upload` format).
    ///
    /// Includes the Ed25519 signing key, the independent Curve25519 DH key with its
    /// cross-signature, signed prekeys, and one-time keys.
    /// Callers must verify the cross-signature before trusting the DH key.
    pub fn export_public_keys(&self) -> serde_json::Value {
        serde_json::json!({
            "user_id": self.user_id,
            "device_id": self.device_id,
            "keys": {
                "ed25519": B64.encode(self.signing_public_key.as_bytes()),
                "curve25519": B64.encode(self.dh_public_key.as_bytes()),
                "curve25519_signature": B64.encode(self.dh_key_signature.to_bytes()),
            },
            "signatures": {
                self.user_id.clone(): {
                    format!("ed25519:{}", self.device_id): B64.encode(self.x25519_prekey.signature)
                }
            },
            "unsigned": {
                "device_display_name": "Matrix PQC Device"
            },
            "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2", "m.pqxdh.v1.kyber1024-x25519-sha3"],
            "prekeys": {
                "x25519": self.x25519_prekey.clone(),
                "kyber1024": self.kyber_prekey.clone()
            },
            "one_time_keys": {
                "curve25519": self.one_time_keys_storage.iter()
                    .map(|(key_id, secret)| (
                        key_id.clone(),
                        serde_json::Value::String(B64.encode(X25519PublicKey::from(secret.as_ref()).as_bytes()))
                    ))
                    .collect::<serde_json::Map<String, serde_json::Value>>()
            }
        })
    }

    /// Removes and returns the private one-time key with the given ID.
    ///
    /// Returns `None` if the key does not exist or was already consumed.
    /// Each OTK can be used only once, ensuring forward secrecy.
    pub fn consume_one_time_key(&mut self, key_id: &str) -> Option<X25519ReusableSecret> {
        self.one_time_keys_storage
            .remove(key_id)
            .map(|boxed_key| *boxed_key)
    }

    /// Returns the public key bytes for a stored one-time key, without consuming it.
    pub fn get_one_time_key_public(&self, key_id: &str) -> Option<Vec<u8>> {
        self.one_time_keys_storage
            .get(key_id)
            .map(|secret| X25519PublicKey::from(secret.as_ref()).as_bytes().to_vec())
    }
}
