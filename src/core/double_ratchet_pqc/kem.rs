//! Zeroizing wrappers and generic KEM types (Kyber-512/768/1024).

use crate::core::crypto::{CryptoError, KemAlgorithm};
use pqcrypto_kyber::{kyber512, kyber768, kyber1024};
use pqcrypto_traits::kem::{PublicKey, SharedSecret, Ciphertext};

/// Wrapper for Kyber512 SecretKey with manual zeroization on Drop.
///
/// Required because pqcrypto-kyber does not implement Zeroize natively.
/// Uses the same strategy as PQXDH: manual wrapper with Drop trait.
pub struct ZeroizingKyber512Key(pub(super) kyber512::SecretKey);

impl Drop for ZeroizingKyber512Key {
    fn drop(&mut self) {
        unsafe {
            let ptr = &mut self.0 as *mut kyber512::SecretKey as *mut u8;
            std::ptr::write_bytes(ptr, 0, std::mem::size_of::<kyber512::SecretKey>());
        }
    }
}

impl std::ops::Deref for ZeroizingKyber512Key {
    type Target = kyber512::SecretKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<kyber512::SecretKey> for ZeroizingKyber512Key {
    fn as_ref(&self) -> &kyber512::SecretKey {
        &self.0
    }
}

/// Wrapper for Kyber768 SecretKey with manual zeroization on Drop.
pub struct ZeroizingKyber768Key(pub(super) kyber768::SecretKey);

impl Drop for ZeroizingKyber768Key {
    fn drop(&mut self) {
        unsafe {
            let ptr = &mut self.0 as *mut kyber768::SecretKey as *mut u8;
            std::ptr::write_bytes(ptr, 0, std::mem::size_of::<kyber768::SecretKey>());
        }
    }
}

impl std::ops::Deref for ZeroizingKyber768Key {
    type Target = kyber768::SecretKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<kyber768::SecretKey> for ZeroizingKyber768Key {
    fn as_ref(&self) -> &kyber768::SecretKey {
        &self.0
    }
}

/// Wrapper for Kyber1024 SecretKey with manual zeroization on Drop.
pub struct ZeroizingKyber1024Key(pub(super) kyber1024::SecretKey);

impl Drop for ZeroizingKyber1024Key {
    fn drop(&mut self) {
        unsafe {
            let ptr = &mut self.0 as *mut kyber1024::SecretKey as *mut u8;
            std::ptr::write_bytes(ptr, 0, std::mem::size_of::<kyber1024::SecretKey>());
        }
    }
}

impl std::ops::Deref for ZeroizingKyber1024Key {
    type Target = kyber1024::SecretKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<kyber1024::SecretKey> for ZeroizingKyber1024Key {
    fn as_ref(&self) -> &kyber1024::SecretKey {
        &self.0
    }
}

/// Generic KEM key pair (supports Kyber-512/768/1024).
///
/// Private keys are protected by `ZeroizingKyber*Key` wrappers that implement
/// `Drop` for automatic memory zeroization. `Clone` is intentionally not
/// implemented to prevent multiple copies of private keys in memory.
pub enum KemKeyPair {
    Kyber512 {
        public: kyber512::PublicKey,
        secret: ZeroizingKyber512Key,
    },
    Kyber768 {
        public: kyber768::PublicKey,
        secret: ZeroizingKyber768Key,
    },
    Kyber1024 {
        public: kyber1024::PublicKey,
        secret: ZeroizingKyber1024Key,
    },
}

impl KemKeyPair {
    /// Generates a new KEM key pair
    pub fn generate(algorithm: KemAlgorithm) -> Self {
        match algorithm {
            KemAlgorithm::Kyber512 => {
                let (public, secret) = kyber512::keypair();
                KemKeyPair::Kyber512 {
                    public,
                    secret: ZeroizingKyber512Key(secret),
                }
            }
            KemAlgorithm::Kyber768 => {
                let (public, secret) = kyber768::keypair();
                KemKeyPair::Kyber768 {
                    public,
                    secret: ZeroizingKyber768Key(secret),
                }
            }
            KemAlgorithm::Kyber1024 => {
                let (public, secret) = kyber1024::keypair();
                KemKeyPair::Kyber1024 {
                    public,
                    secret: ZeroizingKyber1024Key(secret),
                }
            }
        }
    }

    /// Returns the public key
    pub fn public_key(&self) -> KemPublicKey {
        match self {
            KemKeyPair::Kyber512 { public, .. } => KemPublicKey::Kyber512(public.clone()),
            KemKeyPair::Kyber768 { public, .. } => KemPublicKey::Kyber768(public.clone()),
            KemKeyPair::Kyber1024 { public, .. } => KemPublicKey::Kyber1024(public.clone()),
        }
    }

    /// Encapsulates a shared secret against the peer's public key.
    /// Returns `(shared_secret, ciphertext)`; the ciphertext must be sent to the peer.
    pub fn encapsulate_full(&self, peer_public: &KemPublicKey) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        match (self, peer_public) {
            (KemKeyPair::Kyber512 { .. }, KemPublicKey::Kyber512(pk)) => {
                let (shared_secret, ciphertext) = kyber512::encapsulate(pk);
                Ok((shared_secret.as_bytes().to_vec(), ciphertext.as_bytes().to_vec()))
            }
            (KemKeyPair::Kyber768 { .. }, KemPublicKey::Kyber768(pk)) => {
                let (shared_secret, ciphertext) = kyber768::encapsulate(pk);
                Ok((shared_secret.as_bytes().to_vec(), ciphertext.as_bytes().to_vec()))
            }
            (KemKeyPair::Kyber1024 { .. }, KemPublicKey::Kyber1024(pk)) => {
                let (shared_secret, ciphertext) = kyber1024::encapsulate(pk);
                Ok((shared_secret.as_bytes().to_vec(), ciphertext.as_bytes().to_vec()))
            }
            _ => Err(CryptoError::Protocol),
        }
    }

    /// Decapsulates a shared secret using the received ciphertext.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            KemKeyPair::Kyber512 { secret, .. } => {
                let ct = kyber512::Ciphertext::from_bytes(ciphertext)
                    .map_err(|_| CryptoError::Protocol)?;
                let shared_secret = kyber512::decapsulate(&ct, secret);
                Ok(shared_secret.as_bytes().to_vec())
            }
            KemKeyPair::Kyber768 { secret, .. } => {
                let ct = kyber768::Ciphertext::from_bytes(ciphertext)
                    .map_err(|_| CryptoError::Protocol)?;
                let shared_secret = kyber768::decapsulate(&ct, secret);
                Ok(shared_secret.as_bytes().to_vec())
            }
            KemKeyPair::Kyber1024 { secret, .. } => {
                let ct = kyber1024::Ciphertext::from_bytes(ciphertext)
                    .map_err(|_| CryptoError::Protocol)?;
                let shared_secret = kyber1024::decapsulate(&ct, secret);
                Ok(shared_secret.as_bytes().to_vec())
            }
        }
    }
}

/// Generic KEM public keys
#[derive(Clone)]
pub enum KemPublicKey {
    Kyber512(kyber512::PublicKey),
    Kyber768(kyber768::PublicKey),
    Kyber1024(kyber1024::PublicKey),
}

#[allow(dead_code)]
impl KemPublicKey {
    /// Size in bytes of the public key
    pub fn size_bytes(&self) -> usize {
        match self {
            KemPublicKey::Kyber512(pk) => pk.as_bytes().len(),
            KemPublicKey::Kyber768(pk) => pk.as_bytes().len(),
            KemPublicKey::Kyber1024(pk) => pk.as_bytes().len(),
        }
    }
}
