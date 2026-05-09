// Protocolo PQXDH para Acordo de Chaves Matrix Pós-Quântico
//
// Este módulo implementa o protocolo PQXDH (Post-Quantum Extended Diffie-Hellman)
// para estabelecimento de chaves híbridas no contexto Matrix.
//
// O PQXDH estende o protocolo X3DH do Signal com resistência quântica através
// de algoritmos KEM (Key Encapsulation Mechanism) CRYSTALS-Kyber (Round 3) integrados.
//
// Módulos:
// - message:  Tipos de dados (ZeroizingKyberKey, SignedX25519Prekey, MatrixPqxdhInitMessage, etc.)
// - user:     MatrixUser struct e implementação
// - protocol: Funções de protocolo (init_pqxdh, complete_pqxdh)

// Re-exports de API pública — itens podem não ter consumidores dentro deste crate binário.
#![allow(unused_imports)]

pub mod message;
pub mod protocol;
pub mod user;

pub use message::{MatrixPqxdhInitMessage, MatrixPqxdhOutput, SignedKyberPrekey, SignedX25519Prekey};
pub use protocol::{complete_pqxdh, init_pqxdh, init_pqxdh_with_rng};
pub use user::MatrixUser;
