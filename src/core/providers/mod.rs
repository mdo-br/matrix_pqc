//! Cryptographic provider implementations.
//!
//! Concrete implementations of the `CryptoProvider` trait:
//! - `classical`: pure vodozemac (Curve25519/Ed25519)
//! - `hybrid`: vodozemac + PQXDH + Double Ratchet PQC

pub mod classical;
pub mod hybrid;

