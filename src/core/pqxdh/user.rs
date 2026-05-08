// MatrixUser: struct e implementação completa do usuário PQXDH

use anyhow::Result;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, Signer};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret, ReusableSecret as X25519ReusableSecret};
use pqcrypto_kyber::kyber1024::{self};
use pqcrypto_traits::kem::PublicKey;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::{rngs::OsRng, CryptoRng, RngCore};
use std::collections::HashMap;
use super::message::{ZeroizingKyberKey, SignedX25519Prekey, SignedKyberPrekey};

/// Usuário Matrix com capacidades PQXDH
///
/// Representa um usuário Matrix completo com todas as chaves necessárias
/// para participar de acordos de chave PQXDH resistentes a computadores quânticos.
///
/// Hierarquia de chaves (seguindo modelo vodozemac oficial):
///
/// IDENTIDADES DE LONGO PRAZO (permanentes, não rotacionadas):
/// - Chave de assinatura: Ed25519 (fingerprint key)
///   * Usada APENAS para assinar prekeys e mensagens
///   * NÃO usada em operações DH
/// - Chave de identidade DH: Curve25519 INDEPENDENTE (identity key)
///   * Gerada separadamente (NÃO convertida de Ed25519)
///   * Usada em acordos Diffie-Hellman
///   * Assinada pela Ed25519 (cross-signature)
///
/// PREKEYS DE MÉDIO PRAZO (rotacionadas periodicamente):
/// - X25519 prekey: Para acordos DH ephemeral
/// - Kyber-1024 prekey: Para encapsulamento KEM pós-quântico
/// - Ambas assinadas pela Ed25519 signing_key
///
/// CHAVES ONE-TIME (curto prazo, uso único):
/// - X25519 OTK: Consumidas uma vez, garantem forward secrecy
///
/// IMPORTANTE: Diferente do Signal/X3DH, seguimos o modelo Matrix/vodozemac
/// onde as chaves Ed25519 e Curve25519 são INDEPENDENTES (não convertidas).
/// Isso permite rotação independente e isolamento de domínios.
///
/// Estratégia de zeroização (seguindo vodozemac oficial):
/// - Ed25519 e X25519: Dependem de zeroize built-in das bibliotecas dalek
/// - Kyber: Wrapper manual ZeroizingKyberKey (pqcrypto não suporta zeroize)
pub struct MatrixUser {
    /// ID do usuário Matrix (ex.: "@alice:matrix.org")
    /// Usado na derivação de chaves para binding contextual
    pub user_id: String,

    /// ID do dispositivo Matrix para este usuário
    /// Permite múltiplos dispositivos por usuário
    pub device_id: String,

    // === CHAVES DE ASSINATURA (Ed25519) ===

    /// Chave de assinatura Ed25519 privada (permanente)
    /// Usada exclusivamente para assinatura de prekeys e mensagens
    /// Também conhecida como "fingerprint key" no Matrix
    /// ZEROIZED: ed25519-dalek implementa ZeroizeOnDrop automaticamente
    #[allow(dead_code)]
    signing_key: Box<SigningKey>,

    /// Chave de assinatura Ed25519 pública (permanente)
    /// Publicada no servidor Matrix para verificação de assinaturas
    pub signing_public_key: VerifyingKey,

    // === CHAVES DE IDENTIDADE DH (Curve25519) ===

    /// Chave de identidade Curve25519 privada (permanente, INDEPENDENTE)
    /// Usada para acordos Diffie-Hellman (DH1 no PQXDH)
    /// Também conhecida como "sender key" ou "identity key" no Matrix
    /// NOTA: Esta chave é GERADA INDEPENDENTEMENTE (não convertida de Ed25519)
    /// ZEROIZED: x25519-dalek implementa Zeroize automaticamente
    pub(super) diffie_hellman_key: Box<X25519StaticSecret>,

    /// Chave de identidade Curve25519 pública (permanente)
    /// Publicada no servidor Matrix, usada por peers para DH
    pub dh_public_key: X25519PublicKey,

    /// Assinatura cross-key: signing_key assina dh_public_key
    /// Garante binding criptográfico entre as duas identidades
    /// Previne ataques onde adversário substitui uma das chaves
    pub(super) dh_key_signature: Signature,

    // === PREKEYS (médio prazo) ===

    /// Chave privada X25519 para prekey (médio prazo)
    /// Rotacionada periodicamente para sigilo progressivo
    /// ZEROIZED: x25519-dalek implementa Zeroize automaticamente
    pub(super) x25519_prekey_private: Box<X25519ReusableSecret>,

    /// Prekey X25519 assinada exportável (médio prazo)
    /// Publicada no servidor com assinatura Ed25519
    pub x25519_prekey: SignedX25519Prekey,

    /// Chave privada Kyber para prekey (médio prazo)
    /// Usada para desencapsulamento KEM
    /// ZEROIZED: Wrapper manual com Drop (pqcrypto não tem suporte nativo)
    pub(super) kyber_prekey_private: ZeroizingKyberKey,

    /// Prekey Kyber assinada exportável (médio prazo)
    /// Publicada no servidor com assinatura Ed25519
    pub kyber_prekey: SignedKyberPrekey,

    // === ONE-TIME KEYS (curto prazo) ===

    /// Storage de one-time keys: mapeamento de ID → chave privada
    ///
    /// Implementa o modelo Matrix de OTK com identificação por ID arbitrário.
    /// Cada chave é consumida uma única vez para garantir forward secrecy.
    ///
    /// Vantagens deste design:
    /// - Recuperação O(1) por ID sem busca linear
    /// - Remoção sem efeitos colaterais (sem reindexação)
    /// - Compatível com `/keys/claim` do protocolo Matrix
    /// - Desacoplamento entre ID e estrutura de dados interna
    ///
    /// ZEROIZED: x25519-dalek implementa Zeroize automaticamente via trait
    one_time_keys_storage: HashMap<String, Box<X25519ReusableSecret>>,
}

impl MatrixUser {
    /// Cria novo usuário Matrix com capacidades PQXDH
    ///
    /// Gera todas as chaves criptográficas necessárias para participar
    /// de acordos de chave PQXDH, incluindo:
    /// - Par de chaves Ed25519 para assinatura (fingerprint key)
    /// - Par de chaves Curve25519 INDEPENDENTE para DH (identity key)
    /// - Cross-signature: Ed25519 assina Curve25519
    /// - Par de prekeys X25519 e Kyber assinadas
    /// - Lote inicial de 10 chaves one-time X25519
    ///
    /// # Parâmetros
    /// * `user_id` - ID Matrix do usuário (ex.: "@alice:matrix.org")
    /// * `device_id` - ID único do dispositivo
    ///
    /// # Modelo vodozemac
    /// Segue fielmente o modelo Matrix/vodozemac oficial onde:
    /// - Ed25519 (signing_key) é gerada independentemente para assinatura
    /// - Curve25519 (diffie_hellman_key) é gerada independentemente para DH
    /// - NÃO há conversão entre elas (diferente do Signal)
    /// - Cross-signature garante binding entre as duas identidades
    ///
    /// # Segurança
    /// Usa OsRng (Operating System Random Number Generator) que fornece
    /// entropia criptográfica diretamente do SO.
    /// As prekeys são imediatamente assinadas pela chave de assinatura para autenticidade.
    pub fn new(user_id: String, device_id: String) -> Result<Self> {
        Self::new_with_rng(user_id, device_id, &mut OsRng)
    }

    /// Cria novo usuário Matrix com RNG customizável (para testes ou casos especiais)
    ///
    /// Permite injeção de RNG para:
    /// - Testes determinísticos
    /// - Ambientes embedded sem acesso a OsRng
    /// - Casos especiais de auditoria
    ///
    /// # Parâmetros
    /// * `user_id` - ID Matrix do usuário
    /// * `device_id` - ID único do dispositivo
    /// * `rng` - Gerador de números aleatórios que implementa CryptoRng + RngCore
    ///
    /// # Segurança
    /// O RNG fornecido DEVE ser criptograficamente seguro (CryptoRng).
    /// Para produção, use `new()` que utiliza OsRng automaticamente.
    pub fn new_with_rng<R: CryptoRng + RngCore>(
        user_id: String,
        device_id: String,
        rng: &mut R,
    ) -> Result<Self> {
        // === GERAR CHAVE DE ASSINATURA (Ed25519) ===
        // Usada para assinar prekeys e estabelecer identidade
        let signing_key = Box::new(SigningKey::generate(&mut *rng));
        let signing_public_key = signing_key.verifying_key();

        // === GERAR CHAVE DE IDENTIDADE DH (Curve25519 INDEPENDENTE) ===
        // Modelo vodozemac: NÃO converter de Ed25519, gerar separadamente
        let diffie_hellman_key = Box::new(X25519StaticSecret::random_from_rng(&mut *rng));
        let dh_public_key = X25519PublicKey::from(&*diffie_hellman_key);

        // === CROSS-SIGNATURE: Ed25519 assina Curve25519 ===
        // Garante binding criptográfico entre as duas identidades
        // Previne ataques onde adversário substitui uma das chaves
        let dh_key_signature = signing_key.sign(dh_public_key.as_bytes());

        // === GERAR PREKEY X25519 ===
        let x25519_prekey_private = Box::new(X25519ReusableSecret::random_from_rng(&mut *rng));
        let x25519_public_key = X25519PublicKey::from(&*x25519_prekey_private);
        let x25519_signature = signing_key.sign(x25519_public_key.as_bytes());
        let x25519_prekey = SignedX25519Prekey {
            key_id: format!("x25519_prekey_1"),
            public_key: *x25519_public_key.as_bytes(),
            signature: x25519_signature.to_bytes(),
        };

        // === GERAR PREKEY KYBER ===
        let (kyber_public_key, kyber_private_key) = kyber1024::keypair();
        let kyber_private_key = ZeroizingKyberKey(kyber_private_key);
        let kyber_signature = signing_key.sign(kyber_public_key.as_bytes());
        let kyber_prekey = SignedKyberPrekey {
            key_id: format!("kyber_prekey_1"),
            public_key: kyber_public_key.as_bytes().to_vec(),
            signature: kyber_signature.to_bytes(),
        };

        // === GERAR CHAVES ONE-TIME ===
        let mut one_time_keys_storage = HashMap::new();
        for i in 0..10 {
            let private_key = X25519ReusableSecret::random_from_rng(&mut *rng);
            let key_id = format!("otk_{}", i);
            // Box para zeroização automática via x25519-dalek
            one_time_keys_storage.insert(key_id, Box::new(private_key));
        }

        Ok(MatrixUser {
            user_id,
            device_id,
            signing_key,
            signing_public_key,
            diffie_hellman_key,
            dh_public_key,
            dh_key_signature,
            x25519_prekey_private,
            x25519_prekey,
            kyber_prekey_private: kyber_private_key,
            kyber_prekey,
            one_time_keys_storage,
        })
    }

    /// Exporta chaves públicas para distribuição (similar ao Matrix /keys/upload)
    ///
    /// # Formato vodozemac
    /// Inclui:
    /// - Ed25519 signing_key (chave de assinatura)
    /// - Curve25519 diffie_hellman_key (INDEPENDENTE, não convertida)
    /// - Cross-signature: Ed25519 assina Curve25519 para binding
    /// - Prekeys X25519/Kyber assinadas
    /// - One-time keys
    ///
    /// Clientes DEVEM validar a cross-signature antes de confiar na DH key.
    pub fn export_public_keys(&self) -> serde_json::Value {
        serde_json::json!({
            "user_id": self.user_id,
            "device_id": self.device_id,
            "keys": {
                "ed25519": B64.encode(self.signing_public_key.as_bytes()),
                "curve25519": B64.encode(self.dh_public_key.as_bytes()),
                "curve25519_signature": B64.encode(self.dh_key_signature.to_bytes()),
            },
            "signatures": {
                self.user_id.clone(): {
                    format!("ed25519:{}", self.device_id): B64.encode(self.x25519_prekey.signature)
                }
            },
            "unsigned": {
                "device_display_name": "Matrix PQC Device"
            },
            "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2", "m.pqxdh.v1.kyber1024-x25519-sha3"],
            "prekeys": {
                "x25519": self.x25519_prekey.clone(),
                "kyber1024": self.kyber_prekey.clone()
            },
            "one_time_keys": {
                "curve25519": self.one_time_keys_storage.iter()
                    .map(|(key_id, secret)| (
                        key_id.clone(),
                        serde_json::Value::String(B64.encode(X25519PublicKey::from(secret.as_ref()).as_bytes()))
                    ))
                    .collect::<serde_json::Map<String, serde_json::Value>>()
            }
        })
    }

    /// Consome uma chave one-time (simula comportamento do servidor Matrix)
    ///
    /// Remove e retorna a chave privada para uso imediato.
    /// A chave é removida atomicamente do storage, garantindo uso único.
    ///
    /// # Parâmetros
    /// * `key_id` - ID da chave one-time a ser consumida
    ///
    /// # Retorno
    /// * `Some(key)` - Chave privada se encontrada (com zeroização x25519-dalek)
    /// * `None` - Se key_id não existe ou já foi consumida
    ///
    /// # Segurança
    /// Garante forward secrecy: cada OTK só pode ser usada uma vez.
    /// A remoção do HashMap é O(1) e não afeta outras chaves.
    pub fn consume_one_time_key(&mut self, key_id: &str) -> Option<X25519ReusableSecret> {
        // Remove a chave do storage (x25519-dalek zeroiza automaticamente quando Box é dropped)
        self.one_time_keys_storage
            .remove(key_id)
            .map(|boxed_key| *boxed_key)
    }

    /// Obtém a chave pública de uma OTK usando seu ID
    /// Usado pelo destinatário para recuperar a OTK para o KDF
    pub fn get_one_time_key_public(&self, key_id: &str) -> Option<Vec<u8>> {
        self.one_time_keys_storage
            .get(key_id)
            .map(|secret| X25519PublicKey::from(secret.as_ref()).as_bytes().to_vec())
    }
}
