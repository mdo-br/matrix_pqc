// Tipos de dados do protocolo PQXDH: chaves, mensagens e wrappers de zeroização

use pqcrypto_kyber::kyber1024::SecretKey as KyberSecretKey;
use serde::{Serialize, Deserialize};
use crate::utils::serde_helpers;

/// Wrapper para KyberSecretKey com zeroização manual no Drop.
///
/// Necessário porque pqcrypto-kyber não implementa Zeroize nativamente,
/// diferente de x25519-dalek e ed25519-dalek que já possuem suporte built-in.
pub(super) struct ZeroizingKyberKey(pub(super) KyberSecretKey);

impl Drop for ZeroizingKyberKey {
    fn drop(&mut self) {
        unsafe {
            let ptr = &mut self.0 as *mut KyberSecretKey as *mut u8;
            std::ptr::write_bytes(ptr, 0, std::mem::size_of::<KyberSecretKey>());
        }
    }
}

impl std::ops::Deref for ZeroizingKyberKey {
    type Target = KyberSecretKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<KyberSecretKey> for ZeroizingKyberKey {
    fn as_ref(&self) -> &KyberSecretKey {
        &self.0
    }
}

/// Prekey X25519 assinada para Matrix
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedX25519Prekey {
    pub key_id: String,
    #[serde(with = "serde_helpers::bytes_32")]
    pub public_key: [u8; 32],
    #[serde(with = "serde_helpers::bytes_64")]
    pub signature: [u8; 64],
}

/// Prekey CRYSTALS-Kyber assinada para Matrix
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedKyberPrekey {
    pub key_id: String,
    #[serde(with = "serde_helpers::vec_bytes")]
    pub public_key: Vec<u8>,
    #[serde(with = "serde_helpers::bytes_64")]
    pub signature: [u8; 64],
}

/// Mensagem de inicialização PQXDH
///
/// Transporta todos os dados necessários para completar o acordo de chaves,
/// incluindo chaves efêmeras, ciphertext KEM e metadados de contexto.
///
/// Inclui DUAS chaves de identidade do remetente (modelo vodozemac):
/// - `sender_signing_key`: Ed25519 para verificação de assinaturas
/// - `sender_dh_public_key`: Curve25519 independente para operações DH
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixPqxdhInitMessage {
    pub sender_user_id: String,
    #[serde(with = "serde_helpers::bytes_32")]
    pub sender_signing_key: [u8; 32],
    #[serde(with = "serde_helpers::bytes_32")]
    pub sender_dh_public_key: [u8; 32],
    #[serde(with = "serde_helpers::bytes_64")]
    pub sender_dh_key_signature: [u8; 64],
    #[serde(with = "serde_helpers::bytes_32")]
    pub ephemeral_key: [u8; 32],
    #[serde(with = "serde_helpers::vec_bytes")]
    pub kyber_ciphertext: Vec<u8>,
    pub used_x25519_prekey_id: String,
    pub used_kyber_prekey_id: String,
    pub used_one_time_key_id: Option<String>,
}

/// Resultado da inicialização PQXDH (chave de sessão + mensagem para o destinatário)
pub struct MatrixPqxdhOutput {
    pub session_key: [u8; 32],
    pub init_message: MatrixPqxdhInitMessage,
}
