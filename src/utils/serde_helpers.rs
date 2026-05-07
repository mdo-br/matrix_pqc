/// Helpers serde para serializar/desserializar material criptográfico como
/// Base64 na fronteira JSON.
///
/// Internamente os campos são bytes (`[u8; N]` ou `Vec<u8>`); Base64 aparece
/// apenas no wire format, nunca nas interfaces internas entre módulos.
///
/// Uso:
/// ```ignore
/// use crate::utils::serde_helpers;
///
/// #[derive(Serialize, Deserialize)]
/// struct MinhaChave {
///     #[serde(with = "serde_helpers::bytes_32")]
///     pub chave: [u8; 32],
/// }
/// ```
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserializer, Serializer, Deserialize};

/// Serializa `[u8; 32]` como Base64; desserializa Base64 → `[u8; 32]`.
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

/// Serializa `[u8; 64]` como Base64; desserializa Base64 → `[u8; 64]`.
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

/// Serializa `Vec<u8>` como Base64; desserializa Base64 → `Vec<u8>`.
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
