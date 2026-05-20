//! Hybrid Double Ratchet key pairs (X25519 + CRYSTALS-Kyber).

use crate::core::crypto::{CryptoError, KemAlgorithm};
use vodozemac::{Curve25519PublicKey, Curve25519SecretKey};
use hkdf::Hkdf;
use sha2::Sha256;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use pqcrypto_kyber::{kyber512, kyber768, kyber1024};
use pqcrypto_traits::kem::PublicKey;
use super::kem::{KemKeyPair, KemPublicKey};

/// Hybrid ratchet key pair combining X25519 ECDH and Kyber KEM.
///
/// Generated on every direction change (asymmetric advance). The sender calls
/// [`hybrid_dh_with_kem`] to produce a shared secret and a ciphertext; the receiver
/// calls [`hybrid_dh_with_decapsulate`] with that ciphertext to derive the same secret.
/// Both sides combine the results via HKDF-SHA-256 into the same root/chain key.
///
/// # Zeroization
/// X25519 key material is zeroized automatically by vodozemac. Kyber secret keys are
/// wrapped in `ZeroizingKyber*Key` types that overwrite memory on `Drop`. `Clone` is
/// intentionally not derived to prevent accidental key duplication.
pub struct PqcRatchetKeyPair {
    pub curve25519_secret: Curve25519SecretKey,
    pub curve25519_public: Curve25519PublicKey,
    pub kem_keypair: KemKeyPair,
    pub kem_algorithm: KemAlgorithm,
}

impl PqcRatchetKeyPair {
    /// Generates a new hybrid ratchet key pair
    pub fn generate(kem_algorithm: KemAlgorithm) -> Self {
        let curve25519_secret = Curve25519SecretKey::new();
        let curve25519_public = Curve25519PublicKey::from(&curve25519_secret);
        let kem_keypair = KemKeyPair::generate(kem_algorithm);
        Self {
            curve25519_secret,
            curve25519_public,
            kem_keypair,
            kem_algorithm,
        }
    }

    /// Exports the public keys
    pub fn public_keys(&self) -> PqcRatchetPublicKey {
        PqcRatchetPublicKey {
            curve25519_key: self.curve25519_public,
            kem_public_key: self.kem_keypair.public_key(),
            kem_algorithm: self.kem_algorithm,
        }
    }

    /// Performs a hybrid key agreement and encapsulation against `peer_public`.
    ///
    /// Returns `(combined_shared_secret, kem_ciphertext)`. The ciphertext must be
    /// transmitted to the peer so they can derive the same shared secret.
    pub fn hybrid_dh_with_kem(
        &self,
        peer_public: &PqcRatchetPublicKey,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        if self.kem_algorithm != peer_public.kem_algorithm {
            return Err(CryptoError::Protocol);
        }

        let classic_shared = self.curve25519_secret.diffie_hellman(&peer_public.curve25519_key);
        let (pqc_shared, kem_ciphertext) =
            self.kem_keypair.encapsulate_full(&peer_public.kem_public_key)?;

        let combined = hkdf_hybrid_ratchet(
            classic_shared.as_bytes(),
            &pqc_shared,
            format!("matrix-double-ratchet-{}", self.kem_algorithm.name()).as_bytes(),
        );

        Ok((combined.to_vec(), kem_ciphertext))
    }

    /// Performs a hybrid key agreement using a received KEM ciphertext (decapsulate).
    pub fn hybrid_dh_with_decapsulate(
        &self,
        peer_public: &PqcRatchetPublicKey,
        kem_ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if self.kem_algorithm != peer_public.kem_algorithm {
            return Err(CryptoError::Protocol);
        }

        let classic_shared = self.curve25519_secret.diffie_hellman(&peer_public.curve25519_key);
        let pqc_shared = self.kem_keypair.decapsulate(kem_ciphertext)?;

        let combined = hkdf_hybrid_ratchet(
            classic_shared.as_bytes(),
            &pqc_shared,
            format!("matrix-double-ratchet-{}", self.kem_algorithm.name()).as_bytes(),
        );

        Ok(combined.to_vec())
    }
}

/// Public half of a hybrid ratchet key pair (transmitted in every PQC message).
///
/// Holds the Curve25519 and Kyber public keys needed for the receiver to detect
/// direction changes and execute the KEM.
///
/// # Wire format
/// `[32 B Curve25519] [2 B kem_size LE] [kem_bytes] [1 B algorithm]`
/// — Base64-encoded for Matrix transmission.
/// Total sizes: ~835 B (Kyber-512), ~1219 B (Kyber-768), ~1603 B (Kyber-1024).
///
/// If the ratchet key in a received message differs from the stored peer key an
/// asymmetric advance is required and `kem_ciphertext` must be present; otherwise
/// only a symmetric chain-key advance is performed.
#[derive(Clone)]
pub struct PqcRatchetPublicKey {
    pub curve25519_key: Curve25519PublicKey,
    pub kem_public_key: KemPublicKey,
    pub kem_algorithm: KemAlgorithm,
}

/// Diagnostic/utility methods — public API without internal consumers
#[allow(dead_code)]
impl PqcRatchetPublicKey {
    /// Computes total size in bytes (dynamic)
    pub fn size_bytes(&self) -> usize {
        self.curve25519_key.as_bytes().len() + self.kem_public_key.size_bytes()
    }

    /// Detailed key information
    pub fn info(&self) -> String {
        format!(
            "PqcRatchetPublicKey: Curve25519 (32B) + {} ({}B) = {}B total",
            self.kem_algorithm.name(),
            self.kem_public_key.size_bytes(),
            self.size_bytes()
        )
    }

    /// Serializes to Base64 following the vodozemac convention
    pub fn to_base64(&self) -> String {
        B64.encode(&self.to_bytes())
    }

    /// Deserializes from Base64
    pub fn from_base64(b64: &str) -> Result<Self, CryptoError> {
        let bytes = B64.decode(b64).map_err(|_| CryptoError::Protocol)?;
        Self::from_bytes(&bytes)
    }
}

impl PqcRatchetPublicKey {
    /// Serializes to raw bytes (without Base64)
    /// Formato: [32B Curve25519] [2B kem_size] [kem_bytes] [1B algorithm]
    pub fn to_bytes(&self) -> Vec<u8> {
        let curve25519_bytes = self.curve25519_key.as_bytes();
        let kem_bytes = match &self.kem_public_key {
            KemPublicKey::Kyber512(k) => k.as_bytes().to_vec(),
            KemPublicKey::Kyber768(k) => k.as_bytes().to_vec(),
            KemPublicKey::Kyber1024(k) => k.as_bytes().to_vec(),
        };

        let algorithm_byte = match self.kem_algorithm {
            KemAlgorithm::Kyber512 => 0u8,
            KemAlgorithm::Kyber768 => 1u8,
            KemAlgorithm::Kyber1024 => 2u8,
        };

        let mut serialized = Vec::new();
        serialized.extend_from_slice(curve25519_bytes);
        serialized.extend_from_slice(&(kem_bytes.len() as u16).to_le_bytes());
        serialized.extend_from_slice(&kem_bytes);
        serialized.push(algorithm_byte);
        serialized
    }

    /// Deserializes from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 35 {
            // Minimum: 32 (Curve25519) + 2 (size) + 1 (algorithm)
            return Err(CryptoError::Protocol);
        }

        let curve25519_bytes: [u8; 32] = bytes[0..32]
            .try_into()
            .map_err(|_| CryptoError::Protocol)?;
        let curve25519_key = Curve25519PublicKey::from(curve25519_bytes);

        let kem_size = u16::from_le_bytes([bytes[32], bytes[33]]) as usize;

        if 32 + 2 + kem_size + 1 != bytes.len() {
            return Err(CryptoError::Protocol);
        }

        let algorithm_byte = bytes[32 + 2 + kem_size];
        let kem_algorithm = match algorithm_byte {
            0 => KemAlgorithm::Kyber512,
            1 => KemAlgorithm::Kyber768,
            2 => KemAlgorithm::Kyber1024,
            _ => return Err(CryptoError::Protocol),
        };

        let kem_bytes = &bytes[34..34 + kem_size];

        let kem_public_key = match kem_algorithm {
            KemAlgorithm::Kyber512 => {
                let key = kyber512::PublicKey::from_bytes(kem_bytes)
                    .map_err(|_| CryptoError::Protocol)?;
                KemPublicKey::Kyber512(key)
            }
            KemAlgorithm::Kyber768 => {
                let key = kyber768::PublicKey::from_bytes(kem_bytes)
                    .map_err(|_| CryptoError::Protocol)?;
                KemPublicKey::Kyber768(key)
            }
            KemAlgorithm::Kyber1024 => {
                let key = kyber1024::PublicKey::from_bytes(kem_bytes)
                    .map_err(|_| CryptoError::Protocol)?;
                KemPublicKey::Kyber1024(key)
            }
        };

        Ok(Self {
            curve25519_key,
            kem_public_key,
            kem_algorithm,
        })
    }
}

/// Hybrid HKDF-SHA-256 derivation combining a DH and a KEM shared secret.
///
/// Produces 64 bytes of keying material `[root_key(32) || chain_key(32)]`.
/// Security is `max(security_classic, security_pqc)` — an attacker must break
/// both primitives simultaneously to compromise the output.
fn hkdf_hybrid_ratchet(classic_shared: &[u8], pqc_shared: &[u8], context: &[u8]) -> Vec<u8> {
    let salt = b"matrix-hybrid-double-ratchet-v1";
    let hk = Hkdf::<Sha256>::new(Some(salt), &[classic_shared, pqc_shared].concat());

    const SHA256_SIZE: usize = 32;
    let mut output = vec![0u8; SHA256_SIZE * 2];
    hk.expand(context, &mut output)
        .expect("HKDF expand never fails with valid parameters");

    output
}
