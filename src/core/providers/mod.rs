// Provedores Criptográficos
//
// Implementações da trait CryptoProvider:
// - classical: Vodozemac puro (Curve25519/Ed25519)
// - hybrid: Vodozemac + PQXDH + Double Ratchet PQC

pub mod classical;
pub mod hybrid;

