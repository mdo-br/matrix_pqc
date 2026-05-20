//! Hybrid Double Ratchet with CRYSTALS-Kyber (NIST Round 3).
//!
//! Post-quantum extension of the vodozemac Double Ratchet with KEM ratcheting:
//! - Classical base: vodozemac Session (X25519 ECDH + AES-256-CBC + HMAC-SHA-256)
//! - PQC extension: X25519 + CRYSTALS-Kyber (512/768/1024) in parallel
//! - Hybrid derivation: HKDF-SHA-256 combines DH + KEM shared secrets
//! - Message format: Matrix-compatible JSON `{"type":2,"body":"..."}`
//!
//! Modules:
//! - `kem`:     ZeroizingKyber*Key wrappers + KemKeyPair + KemPublicKey
//! - `keys`:    PqcRatchetKeyPair + PqcRatchetPublicKey + hkdf_hybrid_ratchet
//! - `message`: PqcOlmMessage (JSON Matrix serialization/deserialization)
//! - `state`:   PqcRatchetState + PqcDoubleRatchetState + RatchetStats
//! - `session`: HybridOlmSession + SessionStats

// Public API re-exports — items may have no consumers within this binary crate.
#![allow(unused_imports)]

pub mod kem;
pub mod keys;
pub mod message;
pub mod session;
pub mod state;

pub use kem::{KemKeyPair, KemPublicKey};
pub use keys::{PqcRatchetKeyPair, PqcRatchetPublicKey};
pub use message::PqcOlmMessage;
pub use session::{HybridOlmSession, SessionStats};
pub use state::{PqcDoubleRatchetState, PqcRatchetState, RatchetStats};

#[cfg(test)]
mod tests;
