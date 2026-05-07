// Biblioteca Matrix PQC CRYSTALS-Kyber (Round 3)
//
// CRYSTALS-Kyber Round 3 (pqcrypto-kyber 0.8)
//
// Expõe módulos públicos para testes de integração

pub mod utils {
    pub mod logging;
    pub mod serde_helpers;
}

pub mod tools {
    pub mod workload;
}

pub mod core {
    pub mod pqxdh {
        pub use crate::pqxdh::*;
    }
    
    pub mod crypto {
        pub use crate::crypto::*;
    }
    
    pub mod double_ratchet_pqc {
        pub use crate::double_ratchet::*;
    }
    
    pub mod providers {
        pub mod hybrid {
            pub use crate::providers::hybrid::*;
        }
        pub mod classical {
            pub use crate::providers::classical::*;
        }
    }
}

// Protocolos Matrix
pub mod protocols;

// Re-exportar módulos internos
#[path = "core/pqxdh.rs"]
mod pqxdh;

#[path = "core/crypto.rs"]
mod crypto;

#[path = "core/double_ratchet_pqc.rs"]
mod double_ratchet;

#[path = "core/providers/"]
mod providers {
    pub mod hybrid;
    pub mod classical;
}
