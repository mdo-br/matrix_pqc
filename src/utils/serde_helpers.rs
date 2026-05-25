//! Serde helpers for serializing and deserializing cryptographic material as
//! Base64 at the JSON boundary.
//!
//! Fields are bytes internally (`[u8; N]` or `Vec<u8>`); Base64 appears only
//! in the JSON format, never in internal module interfaces.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserializer, Serializer, Deserialize};

/// Serializes `[u8; 32]` as Base64 and deserializes Base64 back to `[u8; 32]`.
pub mod bytes_32 {
    use super::*;
    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = B64.decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into().map_err(|_| serde::de::Error::custom("tamanho inválido: esperado [u8; 32]"))
    }
}

/// Serializes `[u8; 64]` as Base64 and deserializes Base64 back to `[u8; 64]`.
pub mod bytes_64 {
    use super::*;
    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let v = B64.decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into().map_err(|_| serde::de::Error::custom("tamanho inválido: esperado [u8; 64]"))
    }
}

/// Serializes `Vec<u8>` as Base64 and deserializes Base64 back to `Vec<u8>`.
pub mod vec_bytes {
    use super::*;
    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(&s).map_err(serde::de::Error::custom)
    }
}
