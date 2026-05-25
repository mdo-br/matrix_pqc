//! PQXDH Key Agreement Protocol for Matrix.
//!
//! Implements the PQXDH (Post-Quantum Extended Diffie-Hellman) protocol for
//! hybrid key establishment in the Matrix context.
//!
//! PQXDH extends Signal's X3DH with quantum resistance by integrating
//! CRYSTALS-Kyber (Round 3) KEM (Key Encapsulation Mechanism) algorithms.
//!
//! Submodules:
//! - `message`:  Data types (`ZeroizingKyberKey`, `SignedX25519Prekey`, `MatrixPqxdhInitMessage`, etc.)
//! - `user`:     `MatrixUser` struct and implementation.
//! - `protocol`: Protocol functions (`init_pqxdh`, `complete_pqxdh`).

// Public API re-exports — items may have no consumers within this binary crate.
#![allow(unused_imports)]

pub mod message;
pub mod protocol;
pub mod user;

pub use message::{MatrixPqxdhInitMessage, MatrixPqxdhOutput, SignedKyberPrekey, SignedX25519Prekey};
pub use protocol::{complete_pqxdh, init_pqxdh, init_pqxdh_with_rng};
pub use user::MatrixUser;
