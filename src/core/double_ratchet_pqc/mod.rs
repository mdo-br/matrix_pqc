// Double Ratchet Híbrido com CRYSTALS-Kyber (NIST Round 3)
//
// Extensão pós-quântica do Double Ratchet vodozemac com ratcheting KEM:
//
// ARQUITETURA:
// - Base clássica: vodozemac Session (X25519 ECDH + AES-256-CBC + HMAC-SHA-256)
// - Extensão PQC: X25519 + CRYSTALS-Kyber (512/768/1024) em paralelo
// - Derivação híbrida: HKDF-SHA-256 combina segredos DH + KEM
// - Formato mensagem: JSON Matrix-compatível {"type":2,"body":"..."}
//
// Módulos:
// - kem:     Wrappers ZeroizingKyber*Key + KemKeyPair + KemPublicKey
// - keys:    PqcRatchetKeyPair + PqcRatchetPublicKey + hkdf_hybrid_ratchet
// - message: PqcOlmMessage (serialização/deserialização JSON Matrix)
// - state:   PqcRatchetState + PqcDoubleRatchetState + RatchetStats
// - session: HybridOlmSession + SessionStats

// Re-exports de API pública — itens podem não ter consumidores dentro deste crate binário.
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
