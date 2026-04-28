//! Módulo Core - Criptografia Híbrida PQC + Clássica para Matrix
//!
//! Implementa extensões pós-quânticas para o protocolo Matrix mantendo
//! compatibilidade completa com a biblioteca vodozemac oficial.
//!
//! # Arquitetura
//! 
//! - `crypto`: Tipos fundamentais, traits e enums para provedores criptográficos
//! - `pqxdh`: Protocolo de handshake híbrido (X25519 + Kyber-1024)
//! - `double_ratchet_pqc`: Double Ratchet com ratcheting KEM automático
//! - `providers`: Implementações concretas (clássica e híbrida)
//!
//! # Uso
//!
//! ```rust,ignore
//! use matrix_pqc::core::VodoCryptoHybrid;
//! 
//! // Criar conta híbrida
//! let mut alice = VodoCryptoHybrid::account_new(KemChoice::Kyber768);
//! 
//! // Exportar chaves públicas PQXDH
//! let alice_keys = alice.export_pqxdh_public_keys();
//! ```

pub mod crypto;
pub mod pqxdh;
pub mod double_ratchet_pqc;
pub mod providers;