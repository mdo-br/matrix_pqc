//! Core hybrid PQC + classical cryptography for Matrix.
//!
//! Post-quantum extensions for the Matrix protocol, fully compatible with
//! the upstream vodozemac library.
//!
//! # Modules
//!
//! - `crypto`: Fundamental types, traits, and enums for crypto providers.
//! - `pqxdh`: Hybrid handshake protocol (X25519 × 4 + Kyber-1024 KEM).
//! - `double_ratchet_pqc`: Double Ratchet with automatic KEM ratcheting.
//! - `providers`: Concrete provider implementations (classical and hybrid).
//!
//! # Example
//!
//! ```rust,ignore
//! use matrix_pqc::core::VodoCryptoHybrid;
//!
//! let mut alice = VodoCryptoHybrid::account_new(KemChoice::Kyber768);
//! let alice_keys = alice.export_pqxdh_public_keys();
//! ```

pub mod crypto;
pub mod pqxdh;
pub mod double_ratchet_pqc;
pub mod providers;