// Pares de chaves do Double Ratchet híbrido (X25519 + CRYSTALS-Kyber)

use crate::core::crypto::{CryptoError, KemAlgorithm};
use vodozemac::{Curve25519PublicKey, Curve25519SecretKey};
use hkdf::Hkdf;
use sha2::Sha256;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use pqcrypto_kyber::{kyber512, kyber768, kyber1024};
use pqcrypto_traits::kem::PublicKey;
use super::kem::{KemKeyPair, KemPublicKey};

/// Par de chaves de ratchet híbrido (X25519 + CRYSTALS-Kyber)
///
/// Combina criptografia clássica (X25519 ECDH) e pós-quântica (Kyber KEM)
/// em um único par de chaves para uso no Double Ratchet híbrido.
///
/// # Componentes
/// - `curve25519_secret/public`: Par de chaves X25519 para acordos Diffie-Hellman
/// - `kem_keypair`: Par de chaves Kyber (512/768/1024) para Key Encapsulation
/// - `kem_algorithm`: Identifica qual variante Kyber está ativa
///
/// # Segurança (Zeroização)
/// - X25519: Zeroização automática via vodozemac (implementa Zeroize trait)
/// - Kyber: Zeroização manual via wrappers ZeroizingKyber*Key com Drop trait
/// - Sem Clone: Previne múltiplas cópias de chaves privadas na memória
///
/// # Uso no Double Ratchet
/// - Gerado a cada mudança de direção (avanço assimétrico)
/// - Sender: `hybrid_dh_with_kem()` → gera shared_secret + kem_ciphertext
/// - Receiver: `hybrid_dh_with_decapsulate(kem_ciphertext)` → reconstrói shared_secret
/// - Ambos combinam via HKDF-SHA-256 → mesma root_key e chain_key
pub struct PqcRatchetKeyPair {
    pub curve25519_secret: Curve25519SecretKey,
    pub curve25519_public: Curve25519PublicKey,
    pub kem_keypair: KemKeyPair,
    pub kem_algorithm: KemAlgorithm,
}

impl PqcRatchetKeyPair {
    /// Gera novo par de chaves de ratchet híbrido
    pub fn generate(kem_algorithm: KemAlgorithm) -> Self {
        let curve25519_secret = Curve25519SecretKey::new();
        let curve25519_public = Curve25519PublicKey::from(&curve25519_secret);
        let kem_keypair = KemKeyPair::generate(kem_algorithm);
        Self {
            curve25519_secret,
            curve25519_public,
            kem_keypair,
            kem_algorithm,
        }
    }

    /// Exporta chaves públicas
    pub fn public_keys(&self) -> PqcRatchetPublicKey {
        PqcRatchetPublicKey {
            curve25519_key: self.curve25519_public,
            kem_public_key: self.kem_keypair.public_key(),
            kem_algorithm: self.kem_algorithm,
        }
    }

    /// Executa acordo híbrido COM ciphertext KEM (encapsulate)
    /// Retorna: (combined_shared_secret, kem_ciphertext)
    /// O ciphertext DEVE ser enviado ao peer para que ele possa derivar o mesmo SS
    pub fn hybrid_dh_with_kem(
        &self,
        peer_public: &PqcRatchetPublicKey,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        if self.kem_algorithm != peer_public.kem_algorithm {
            return Err(CryptoError::Protocol);
        }

        let classic_shared = self.curve25519_secret.diffie_hellman(&peer_public.curve25519_key);
        let (pqc_shared, kem_ciphertext) =
            self.kem_keypair.encapsulate_full(&peer_public.kem_public_key)?;

        let combined = hkdf_hybrid_ratchet(
            classic_shared.as_bytes(),
            &pqc_shared,
            format!("matrix-double-ratchet-{}", self.kem_algorithm.name()).as_bytes(),
        );

        Ok((combined.to_vec(), kem_ciphertext))
    }

    /// Executa acordo híbrido usando ciphertext KEM recebido (decapsulate)
    /// Peer usa isso quando recebe uma mensagem com kem_ciphertext
    pub fn hybrid_dh_with_decapsulate(
        &self,
        peer_public: &PqcRatchetPublicKey,
        kem_ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if self.kem_algorithm != peer_public.kem_algorithm {
            return Err(CryptoError::Protocol);
        }

        let classic_shared = self.curve25519_secret.diffie_hellman(&peer_public.curve25519_key);
        let pqc_shared = self.kem_keypair.decapsulate(kem_ciphertext)?;

        let combined = hkdf_hybrid_ratchet(
            classic_shared.as_bytes(),
            &pqc_shared,
            format!("matrix-double-ratchet-{}", self.kem_algorithm.name()).as_bytes(),
        );

        Ok(combined.to_vec())
    }
}

/// Chave pública de ratchet híbrida (transmitida em mensagens PQC)
///
/// Contém componentes públicos do par de chaves híbrido que são enviados
/// em cada mensagem do Double Ratchet PQC para permitir avanço assimétrico.
///
/// # Estrutura
/// - `curve25519_key`: Chave pública X25519 (32 bytes fixos)
/// - `kem_public_key`: Chave pública Kyber (tamanho variável: 800/1184/1568 bytes)
/// - `kem_algorithm`: Identificador do algoritmo (Kyber512/768/1024)
///
/// # Serialização Binária Otimizada
/// Formato: [32B Curve25519] [2B kem_size] [kem_bytes] [1B algorithm]
/// - Minimiza overhead comparado a JSON
/// - Compatível com Base64 para transmissão Matrix
/// - Tamanho total: ~835B (Kyber512), ~1219B (Kyber768), ~1603B (Kyber1024)
///
/// # Uso no Protocolo
/// Enviada em TODAS as mensagens PQC (padrão Matrix/vodozemac):
/// - Permite que receiver detecte mudanças de direção
/// - Comparação de bytes identifica se houve avanço assimétrico
/// - Se chave mudou: executar KEM com kem_ciphertext
/// - Se chave igual: avanço simétrico (sem KEM)
#[derive(Clone)]
pub struct PqcRatchetPublicKey {
    pub curve25519_key: Curve25519PublicKey,
    pub kem_public_key: KemPublicKey,
    pub kem_algorithm: KemAlgorithm,
}

/// Métodos de diagnóstico/utilidade — API pública sem consumidores internos
#[allow(dead_code)]
impl PqcRatchetPublicKey {
    /// Calcula tamanho total em bytes (dinâmico)
    pub fn size_bytes(&self) -> usize {
        self.curve25519_key.as_bytes().len() + self.kem_public_key.size_bytes()
    }

    /// Informações detalhadas da chave
    pub fn info(&self) -> String {
        format!(
            "PqcRatchetPublicKey: Curve25519 (32B) + {} ({}B) = {}B total",
            self.kem_algorithm.name(),
            self.kem_public_key.size_bytes(),
            self.size_bytes()
        )
    }

    /// Serializa para Base64 seguindo padrão vodozemac
    pub fn to_base64(&self) -> String {
        B64.encode(&self.to_bytes())
    }

    /// Desserializa de Base64
    pub fn from_base64(b64: &str) -> Result<Self, CryptoError> {
        let bytes = B64.decode(b64).map_err(|_| CryptoError::Protocol)?;
        Self::from_bytes(&bytes)
    }
}

impl PqcRatchetPublicKey {
    /// Serializa para bytes brutos (sem Base64)
    /// Formato: [32B Curve25519] [2B kem_size] [kem_bytes] [1B algorithm]
    pub fn to_bytes(&self) -> Vec<u8> {
        let curve25519_bytes = self.curve25519_key.as_bytes();
        let kem_bytes = match &self.kem_public_key {
            KemPublicKey::Kyber512(k) => k.as_bytes().to_vec(),
            KemPublicKey::Kyber768(k) => k.as_bytes().to_vec(),
            KemPublicKey::Kyber1024(k) => k.as_bytes().to_vec(),
        };

        let algorithm_byte = match self.kem_algorithm {
            KemAlgorithm::Kyber512 => 0u8,
            KemAlgorithm::Kyber768 => 1u8,
            KemAlgorithm::Kyber1024 => 2u8,
        };

        let mut serialized = Vec::new();
        serialized.extend_from_slice(curve25519_bytes);
        serialized.extend_from_slice(&(kem_bytes.len() as u16).to_le_bytes());
        serialized.extend_from_slice(&kem_bytes);
        serialized.push(algorithm_byte);
        serialized
    }

    /// Desserializa de bytes brutos
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 35 {
            // Mínimo: 32 (Curve25519) + 2 (size) + 1 (algorithm)
            return Err(CryptoError::Protocol);
        }

        let curve25519_bytes: [u8; 32] = bytes[0..32]
            .try_into()
            .map_err(|_| CryptoError::Protocol)?;
        let curve25519_key = Curve25519PublicKey::from(curve25519_bytes);

        let kem_size = u16::from_le_bytes([bytes[32], bytes[33]]) as usize;

        if 32 + 2 + kem_size + 1 != bytes.len() {
            return Err(CryptoError::Protocol);
        }

        let algorithm_byte = bytes[32 + 2 + kem_size];
        let kem_algorithm = match algorithm_byte {
            0 => KemAlgorithm::Kyber512,
            1 => KemAlgorithm::Kyber768,
            2 => KemAlgorithm::Kyber1024,
            _ => return Err(CryptoError::Protocol),
        };

        let kem_bytes = &bytes[34..34 + kem_size];

        let kem_public_key = match kem_algorithm {
            KemAlgorithm::Kyber512 => {
                let key = kyber512::PublicKey::from_bytes(kem_bytes)
                    .map_err(|_| CryptoError::Protocol)?;
                KemPublicKey::Kyber512(key)
            }
            KemAlgorithm::Kyber768 => {
                let key = kyber768::PublicKey::from_bytes(kem_bytes)
                    .map_err(|_| CryptoError::Protocol)?;
                KemPublicKey::Kyber768(key)
            }
            KemAlgorithm::Kyber1024 => {
                let key = kyber1024::PublicKey::from_bytes(kem_bytes)
                    .map_err(|_| CryptoError::Protocol)?;
                KemPublicKey::Kyber1024(key)
            }
        };

        Ok(Self {
            curve25519_key,
            kem_public_key,
            kem_algorithm,
        })
    }
}

/// Derivação híbrida HKDF-SHA-256 para combinação de segredos DH + KEM
///
/// Combina segredos clássico (X25519) e pós-quântico (Kyber KEM) para produzir
/// 64 bytes de material de chaveamento: [root_key(32) || chain_key(32)]
///
/// # Segurança Híbrida
/// Security = max(security_classic, security_pqc) — ambos devem ser quebrados
/// simultaneamente para comprometer o protocolo.
fn hkdf_hybrid_ratchet(classic_shared: &[u8], pqc_shared: &[u8], context: &[u8]) -> Vec<u8> {
    let salt = b"matrix-hybrid-double-ratchet-v1";
    let hk = Hkdf::<Sha256>::new(Some(salt), &[classic_shared, pqc_shared].concat());

    const SHA256_SIZE: usize = 32;
    let mut output = vec![0u8; SHA256_SIZE * 2];
    hk.expand(context, &mut output)
        .expect("HKDF expand never fails with valid parameters");

    output
}
