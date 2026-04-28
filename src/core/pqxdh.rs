// Protocolo PQXDH para Acordo de Chaves Matrix Pós-Quântico
//
// Este módulo implementa o protocolo PQXDH (Post-Quantum Extended Diffie-Hellman)
// para estabelecimento de chaves híbridas no contexto Matrix.
//
// O PQXDH estende o protocolo X3DH do Signal com resistência quântica através
// de algoritmos KEM (Key Encapsulation Mechanism) CRYSTALS-Kyber (Round 3) integrados.
//
// Principais adaptações para o Matrix:
// - Formatos de identidade e prekey compatíveis com Matrix
// - Integração com gerenciamento de chaves do vodozemac
// - Suporte a contextos de sala Matrix e IDs de usuário
// - Derivação de chaves híbrida compatível com sessões Olm
// - Verificação de assinaturas Ed25519 para autenticidade
//
// Fluxo do protocolo:
// 1. Geração de chaves de identidade de longo prazo:
//    - Ed25519 (signing_key) para assinaturas
//    - Curve25519 (diffie_hellman_key) INDEPENDENTE para acordos DH
//    - Cross-signature: Ed25519 assina Curve25519
// 2. Geração de prekeys de médio prazo assinadas:
//    - X25519 para DH ephemeral
//    - Kyber-1024 para KEM pós-quântico
// 3. Geração de chaves one-time X25519 (curto prazo)
// 4. Execução de 3-4 acordos DH (dependendo de OTK) + 1 encapsulamento KEM
// 5. Derivação de chave de sessão usando HKDF-SHA-256
//
// Segurança de RNG:
// - Produção: Usa OsRng (Operating System RNG) por padrão
//   * Backed pelo kernel do SO (/dev/urandom no Linux)
//   * Adequado para uso criptográfico
// - Testes: API _with_rng() permite injeção de RNG customizado
//   * Permite testes determinísticos
//   * Útil para ambientes embedded sem OsRng

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, Signer};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret, ReusableSecret as X25519ReusableSecret};
use pqcrypto_kyber::kyber1024::{self, PublicKey as KyberPublicKey, SecretKey as KyberSecretKey, Ciphertext as KyberCiphertext};
use pqcrypto_traits::kem::{PublicKey, Ciphertext, SharedSecret};
use hkdf::Hkdf;
use sha2::Sha256;
use serde::{Serialize, Deserialize};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::{rngs::OsRng, CryptoRng, RngCore};
use std::collections::HashMap;
use crate::utils::logging::VerbosityLevel;
use crate::vlog;

/// Wrapper para KyberSecretKey que implementa Drop para zeroização.
/// 
/// Necessário porque pqcrypto-kyber não implementa Zeroize nativamente,
/// diferente de x25519-dalek e ed25519-dalek que já possuem suporte built-in.
/// 
/// Segue a estratégia da vodozemac oficial: delega zeroização às bibliotecas
/// quando possível, implementa manualmente apenas quando necessário.
struct ZeroizingKyberKey(KyberSecretKey);

impl Drop for ZeroizingKyberKey {
    fn drop(&mut self) {
        // Zeroizar bytes da chave privada Kyber
        // Kyber-1024 SecretKey é opaco, então zeramos a struct inteira
        unsafe {
            let ptr = &mut self.0 as *mut KyberSecretKey as *mut u8;
            std::ptr::write_bytes(ptr, 0, std::mem::size_of::<KyberSecretKey>());
        }
    }
}

// Implementar Deref e AsRef para facilitar acesso à chave interna
impl std::ops::Deref for ZeroizingKyberKey {
    type Target = KyberSecretKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Implementar AsRef para facilitar acesso à chave interna
impl AsRef<KyberSecretKey> for ZeroizingKyberKey {
    fn as_ref(&self) -> &KyberSecretKey {
        &self.0
    }
}

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
    diffie_hellman_key: Box<X25519StaticSecret>,
    
    /// Chave de identidade Curve25519 pública (permanente)
    /// Publicada no servidor Matrix, usada por peers para DH
    pub dh_public_key: X25519PublicKey,
    
    /// Assinatura cross-key: signing_key assina dh_public_key
    /// Garante binding criptográfico entre as duas identidades
    /// Previne ataques onde adversário substitui uma das chaves
    dh_key_signature: Signature,
    
    // === PREKEYS (médio prazo) ===
    
    /// Chave privada X25519 para prekey (médio prazo)
    /// Rotacionada periodicamente para sigilo progressivo
    /// ZEROIZED: x25519-dalek implementa Zeroize automaticamente
    x25519_prekey_private: Box<X25519ReusableSecret>,
    
    /// Prekey X25519 assinada exportável (médio prazo)
    /// Publicada no servidor com assinatura Ed25519
    pub x25519_prekey: SignedX25519Prekey,
    
    /// Chave privada Kyber para prekey (médio prazo)
    /// Usada para desencapsulamento KEM
    /// ZEROIZED: Wrapper manual com Drop (pqcrypto não tem suporte nativo)
    kyber_prekey_private: ZeroizingKyberKey,
    
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

/// Prekey X25519 assinada para Matrix
/// 
/// Contém uma chave pública X25519 de médio prazo com assinatura Ed25519
/// para garantir autenticidade. Rotacionada periodicamente para manter
/// sigilo progressivo sem comprometer usabilidade.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedX25519Prekey {
    /// Identificador único da prekey no servidor
    pub key_id: String,
    /// Chave pública X25519 codificada em Base64 (tamanho padrão X25519)
    pub public_key: String,
    /// Assinatura Ed25519 da chave pública codificada em Base64 (tamanho padrão Ed25519)
    /// Produzida pela chave de identidade para garantir autenticidade
    pub signature: String,
}

/// Prekey Kyber assinada para Matrix
/// 
/// Contém uma chave pública CRYSTALS-Kyber (Round 3) com assinatura Ed25519 para
/// garantir integridade. Usada para encapsulamento KEM no PQXDH.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedKyberPrekey {
    /// Identificador único da prekey Kyber no servidor
    pub key_id: String,
    /// Chave pública Kyber codificada em Base64 (tamanho varia conforme algoritmo selecionado)
    /// exemplos: 1568 bytes para Kyber-1024, 1088 bytes para Kyber-768 e 736 bytes para Kyber-512
    pub public_key: String,
    /// Assinatura Ed25519 da chave pública codificada em Base64 (tamanho padrão Ed25519)
    /// Produzida pela chave de identidade para garantir autenticidade
    pub signature: String,
}

/// Mensagem de inicialização PQXDH para Matrix
/// 
/// Transporta todos os dados necessários para completar o acordo de chaves
/// PQXDH, incluindo chaves efêmeras, ciphertext KEM e metadados de contexto.
/// 
/// Modelo vodozemac: inclui DUAS chaves de identidade do remetente:
/// - sender_signing_key: Ed25519 para verificação de assinaturas
/// - sender_dh_public_key: Curve25519 INDEPENDENTE para operações DH
#[derive(Debug, Serialize, Deserialize)]
#[derive(Clone)]
pub struct MatrixPqxdhInitMessage {
    /// ID do usuário remetente (usado na derivação de chaves KDF)
    /// Fornece binding contextual específico do Matrix
    pub sender_user_id: String,
    
    /// Chave pública de assinatura do remetente (Ed25519 em Base64)
    /// Usada apenas para verificação de assinaturas, NÃO para operações DH
    pub sender_signing_key: String,
    
    /// Chave pública de identidade DH do remetente (Curve25519 em Base64)
    /// INDEPENDENTE da signing_key, gerada separadamente no modelo vodozemac
    /// Usada no primeiro acordo DH (dh1)
    pub sender_dh_public_key: String,
    
    /// Assinatura cross-key da chave DH do remetente (Ed25519 em Base64)
    /// A signing_key Ed25519 assina a diffie_hellman_key Curve25519
    /// Garante binding criptográfico entre as duas identidades do remetente
    /// Previne ataques de substituição de chaves
    pub sender_dh_key_signature: String,
    
    /// Chave pública X25519 efêmera (Base64)
    /// Gerada especificamente para este acordo de chaves
    pub ephemeral_key: String,
    /// Ciphertext Kyber resultante do encapsulamento (Base64)
    /// Contém segredo compartilhado encapsulado com a prekey Kyber do destinatário
    pub kyber_ciphertext: String,
    /// ID da prekey X25519 utilizada do destinatário
    /// Permite ao destinatário localizar a chave privada correta
    pub used_x25519_prekey_id: String,
    /// ID da prekey Kyber utilizada do destinatário
    /// Permite ao destinatário localizar a chave privada KEM correta
    pub used_kyber_prekey_id: String,
    /// ID da chave one-time utilizada (opcional)
    /// None se nenhuma OTK estava disponível
    /// Destinatário usa este ID para recuperar a chave pública do seu storage
    pub used_one_time_key_id: Option<String>,
}

/// Resultado da inicialização PQXDH
/// 
/// Contém a chave de sessão derivada e a mensagem de inicialização
/// para transmissão ao destinatário.
pub struct MatrixPqxdhOutput {
    /// Chave de sessão derivada do acordo PQXDH (tamanho padrão do protocolo)
    /// Usada como chave raiz para protocolos Olm/Megolm
    pub session_key: [u8; 32],
    /// Mensagem de inicialização para envio ao destinatário
    /// Contém todos os dados necessários para completar o acordo
    pub init_message: MatrixPqxdhInitMessage,
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
        rng: &mut R
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
            public_key: B64.encode(x25519_public_key.as_bytes()),
            signature: B64.encode(x25519_signature.to_bytes()),
        };
        
        // === GERAR PREKEY KYBER ===
        let (kyber_public_key, kyber_private_key) = kyber1024::keypair();
        let kyber_private_key = ZeroizingKyberKey(kyber_private_key);
        let kyber_signature = signing_key.sign(kyber_public_key.as_bytes());
        let kyber_prekey = SignedKyberPrekey {
            key_id: format!("kyber_prekey_1"),
            public_key: B64.encode(kyber_public_key.as_bytes()),
            signature: B64.encode(kyber_signature.to_bytes()),
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
                    format!("ed25519:{}", self.device_id): self.x25519_prekey.signature.clone()
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

/// Inicializa acordo de chaves PQXDH (lado remetente)
/// 
/// Executa a primeira fase do protocolo PQXDH, realizando:
/// 1. Verificação de assinaturas das prekeys do destinatário
/// 2. Seleção e consumo de uma chave one-time (se disponível)
/// 3. Geração de chave efêmera X25519
/// 4. Encapsulamento KEM com prekey Kyber do destinatário
/// 5. Execução de 3-4 acordos Diffie-Hellman usando chaves Curve25519:
///    - DH1: alice.diffie_hellman_key × bob.x25519_prekey
///    - DH2: alice.ephemeral × bob.diffie_hellman_key  
///    - DH3: alice.ephemeral × bob.x25519_prekey
///    - DH4: alice.ephemeral × bob.otk (opcional, se disponível)
/// 6. Derivação de chave de sessão usando HKDF-SHA-256 com Associated Data
/// 
/// # Parâmetros
/// * `alice` - Usuário remetente iniciando o acordo
/// * `bob_public_keys` - Bundle de chaves públicas do destinatário
/// 
/// # Retorno
/// Resultado contendo chave de sessão derivada e mensagem de inicialização
/// 
/// # Segurança
/// Verifica todas as assinaturas Ed25519 antes de usar as chaves.
/// Combina segredos clássicos (DH) com segredos pós-quânticos (KEM).
/// Usa OsRng para geração da chave efêmera.
pub fn init_pqxdh(alice: &MatrixUser, bob_public_keys: &serde_json::Value) -> Result<MatrixPqxdhOutput> {
    init_pqxdh_with_rng(alice, bob_public_keys, &mut OsRng)
}

/// Inicializa acordo PQXDH com RNG customizável
/// 
/// Versão parametrizável para testes ou casos especiais.
/// Para produção, use `init_pqxdh()` que utiliza OsRng.
pub fn init_pqxdh_with_rng<R: CryptoRng + RngCore>(
    alice: &MatrixUser,
    bob_public_keys: &serde_json::Value,
    rng: &mut R
) -> Result<MatrixPqxdhOutput> {
    
    // Analisar chaves públicas do Bob no modelo vodozemac
    // Bob possui duas chaves independentes:
    // - Ed25519 signing_key (para verificação de assinaturas)
    // - Curve25519 diffie_hellman_key (para operações DH)
    
    let bob_signing_key = {
        let key_b64 = bob_public_keys["keys"]["ed25519"].as_str()
            .context("Missing Bob's signing key")?;
        let key_bytes = B64.decode(key_b64)?;
        VerifyingKey::from_bytes(&key_bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid key length"))?)?
    };
    
    let bob_identity_key = {
        let key_b64 = bob_public_keys["keys"]["curve25519"].as_str()
            .context("Missing Bob's DH identity key")?;
        let key_bytes = B64.decode(key_b64)?;
        
        // Verificar cross-signature: Ed25519 assina Curve25519
        let sig_b64 = bob_public_keys["keys"]["curve25519_signature"].as_str()
            .context("Missing DH key signature")?;
        let sig_bytes = B64.decode(sig_b64)?;
        let signature = Signature::from_bytes(&sig_bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid signature"))?);
        bob_signing_key.verify_strict(&key_bytes, &signature)?;
        
        let key_array: [u8; 32] = key_bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid Curve25519 key length"))?;
        X25519PublicKey::from(key_array)
    };
    
    let bob_x25519_prekey = {
        let prekey_data = &bob_public_keys["prekeys"]["x25519"];
        let key_b64 = prekey_data["public_key"].as_str().context("Missing X25519 prekey")?;
        let sig_b64 = prekey_data["signature"].as_str().context("Missing X25519 signature")?;
        
        // Verificar assinatura (assinada pela signing_key Ed25519)
        let key_bytes = B64.decode(key_b64)?;
        let sig_bytes = B64.decode(sig_b64)?;
        let signature = Signature::from_bytes(&sig_bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid signature"))?);
        bob_signing_key.verify_strict(&key_bytes, &signature)?;
        
        let key_array: [u8; 32] = key_bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid X25519 key length"))?;
        X25519PublicKey::from(key_array)
    };
    
    let bob_kyber_prekey = {
        let prekey_data = &bob_public_keys["prekeys"]["kyber1024"];
        let key_b64 = prekey_data["public_key"].as_str().context("Missing Kyber prekey")?;
        let sig_b64 = prekey_data["signature"].as_str().context("Missing Kyber signature")?;
        
        // Verificar assinatura (assinada pela signing_key Ed25519)
        let key_bytes = B64.decode(key_b64)?;
        let sig_bytes = B64.decode(sig_b64)?;
        let signature = Signature::from_bytes(&sig_bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid signature"))?);
        bob_signing_key.verify_strict(&key_bytes, &signature)?;
        
        KyberPublicKey::from_bytes(&key_bytes).map_err(|_| anyhow::anyhow!("Invalid Kyber public key"))?
    };
    
    // Selecionar uma chave one-time do Bob (se disponível)
    let (bob_one_time_key, used_otk_id) = {
        let otk_map = &bob_public_keys["one_time_keys"]["curve25519"];
        if let Some(otk_map) = otk_map.as_object() {
            if let Some((key_id, key_value)) = otk_map.iter().next() {
                let key_b64 = key_value.as_str().context("Invalid OTK format")?;
                let key_bytes = B64.decode(key_b64)?;
                let key_array: [u8; 32] = key_bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid OTK length"))?;
                (Some(X25519PublicKey::from(key_array)), Some(key_id.clone()))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        }
    };

    // Gerar chave efêmera X25519
    let ephemeral_private = X25519ReusableSecret::random_from_rng(&mut *rng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_private);
    
    // Realizar encapsulamento Kyber
    // NOTA: pqcrypto-kyber retorna (SharedSecret, Ciphertext) - ordem NÃO-padrão!
    // Diferente da spec NIST que define encap() -> (ct, ss)
    let (shared_secret_kyber, ciphertext) = kyber1024::encapsulate(&bob_kyber_prekey);
    
    // Modelo vodozemac: usar DH key diretamente (NÃO converter de Ed25519)
    // Alice usa sua diffie_hellman_key independente
    let bob_identity_x25519 = bob_identity_key; // Já é Curve25519 no modelo vodozemac
    
    // Realizar as trocas Diffie-Hellman (3 ou 4 dependendo da disponibilidade de OTK)
    let dh1 = alice.diffie_hellman_key.diffie_hellman(&bob_x25519_prekey);
    let dh2 = ephemeral_private.diffie_hellman(&bob_identity_x25519);
    let dh3 = ephemeral_private.diffie_hellman(&bob_x25519_prekey);
    let dh4 = bob_one_time_key.map(|otk| ephemeral_private.diffie_hellman(&otk));
    
    // Derivar chave de sessão usando KDF compatível com Matrix
    // Incluir Associated Data (todas as chaves públicas)
    // Previne Key Compromise Impersonation (KCI) attacks
    let session_key = matrix_pqxdh_kdf(
        // Segredos compartilhados (DH + KEM)
        dh1.as_bytes(),
        dh2.as_bytes(), 
        dh3.as_bytes(),
        dh4.as_ref().map(|dh| dh.as_bytes() as &[u8]),
        shared_secret_kyber.as_bytes(),
        // Associated Data - binding criptográfico de chaves públicas
        // IMPORTANTE: Usar DH public keys (Curve25519), não signing keys (Ed25519)
        alice.dh_public_key.as_bytes(),  // Chave DH de Alice (Curve25519)
        bob_identity_key.as_bytes(),      // Chave DH de Bob (Curve25519)
        bob_x25519_prekey.as_bytes(),
        bob_kyber_prekey.as_bytes(),
        bob_one_time_key.as_ref().map(|otk| otk.as_bytes() as &[u8]),
        ephemeral_public.as_bytes(),
        // Contexto Matrix
        &alice.user_id,
        &bob_public_keys["user_id"].as_str().unwrap_or("@unknown:matrix.org")
    );
    
    let init_message = MatrixPqxdhInitMessage {
        sender_user_id: alice.user_id.clone(),
        sender_signing_key: B64.encode(alice.signing_public_key.as_bytes()),
        sender_dh_public_key: B64.encode(alice.dh_public_key.as_bytes()),
        sender_dh_key_signature: B64.encode(alice.dh_key_signature.to_bytes()),
        ephemeral_key: B64.encode(ephemeral_public.as_bytes()),
        kyber_ciphertext: B64.encode(ciphertext.as_bytes()),
        used_x25519_prekey_id: bob_public_keys["prekeys"]["x25519"]["key_id"].as_str().unwrap_or("unknown").to_string(),
        used_kyber_prekey_id: bob_public_keys["prekeys"]["kyber1024"]["key_id"].as_str().unwrap_or("unknown").to_string(),
        used_one_time_key_id: used_otk_id.clone(),
    };
    
    Ok(MatrixPqxdhOutput {
        session_key,
        init_message,
    })
}

/// Completa acordo de chaves PQXDH (lado destinatário)
/// 
/// Executa a segunda fase do protocolo PQXDH, realizando:
/// 1. Parsing e validação da chave de identidade do remetente (alice.signing_key e alice.diffie_hellman_key)
/// 2. Verificação da cross-signature (Ed25519 → Curve25519 binding) para garantir autenticidade
/// 3. Parsing da chave efêmera X25519 (alice.ephemeral)
/// 4. Consumo da chave one-time usada (se aplicável) - obtém pública primeiro, depois consome privada
/// 5. Desencapsulamento do ciphertext Kyber usando bob.kyber_prekey_private
/// 6. Execução dos mesmos 3-4 acordos DH na ordem correta usando chaves Curve25519:
///    - DH1: bob.x25519_prekey_private × alice.diffie_hellman_key (recebida em sender_dh_public_key)
///    - DH2: bob.diffie_hellman_key × alice.ephemeral
///    - DH3: bob.x25519_prekey_private × alice.ephemeral
///    - DH4: bob.otk × alice.ephemeral (opcional, se disponível)
/// 7. Derivação da mesma chave de sessão usando HKDF-SHA-256 com Associated Data
/// 
/// # Parâmetros
/// * `bob` - Usuário destinatário completando o acordo
/// * `init_message` - Mensagem de inicialização recebida do remetente
/// 
/// # Retorno
/// Chave de sessão idêntica à derivada pelo remetente (tamanho padrão do protocolo)
/// 
/// # Efeitos Colaterais
/// Remove e consome a chave one-time usada para garantir uso único
/// 
/// # Segurança
/// - Cross-signature validation previne ataques de substituição de chaves
/// - Derivação de chave determinística garante acordo bilateral
/// - Forward secrecy garantida pelo consumo de OTKs
pub fn complete_pqxdh(bob: &mut MatrixUser, init_message: &MatrixPqxdhInitMessage) -> Result<[u8; 32]> {
    // Analisar chave de assinatura da Alice (Ed25519)
    let alice_signing_key = {
        let key_bytes = B64.decode(&init_message.sender_signing_key)?;
        VerifyingKey::from_bytes(&key_bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid key length"))?)?
    };
    
    // Analisar chave DH de identidade da Alice (Curve25519 INDEPENDENTE)
    let alice_dh_public_key = {
        let key_bytes = B64.decode(&init_message.sender_dh_public_key)?;
        let key_array: [u8; 32] = key_bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid key length"))?;
        X25519PublicKey::from(key_array)
    };
    
    // VALIDAÇÃO: Verificar cross-signature da chave DH
    // A Alice deve ter assinado sua chave DH (Curve25519) com sua signing key (Ed25519)
    // Isso garante binding criptográfico entre as duas chaves de identidade
    // e previne ataques onde adversário substitui a chave DH mantendo a signing key legítima
    let dh_sig_bytes = B64.decode(&init_message.sender_dh_key_signature)?;
    let dh_sig_array: [u8; 64] = dh_sig_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Invalid signature length"))?;
    let dh_signature = Signature::from_bytes(&dh_sig_array);
    
    match alice_signing_key.verify_strict(alice_dh_public_key.as_bytes(), &dh_signature) {
        Ok(_) => {
            vlog!(VerbosityLevel::Debug, "[PQXDH] Cross-signature validada com sucesso");
            vlog!(VerbosityLevel::Verbose, "[PQXDH]   Ed25519 signing_key verificou assinatura da Curve25519 diffie_hellman_key");
        }
        Err(e) => {
            vlog!(VerbosityLevel::Normal, "[PQXDH] FALHA na validacao de cross-signature: {:?}", e);
            return Err(anyhow::anyhow!("Cross-signature validation failed: Alice's DH key not signed by her signing key"));
        }
    }
    
    // Analisar chave efêmera
    let ephemeral_key = {
        let key_bytes = B64.decode(&init_message.ephemeral_key)?;
        let key_array: [u8; 32] = key_bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid key length"))?;
        X25519PublicKey::from(key_array)
    };
    
    // Obter OTK pública do storage ANTES de consumir (para o KDF)
    let bob_otk_bytes = init_message.used_one_time_key_id
        .as_ref()
        .and_then(|otk_id| bob.get_one_time_key_public(otk_id));
    
    // Lidar com chave one-time se usada (consumir a chave privada)
    let otk_private = if let Some(ref otk_id) = init_message.used_one_time_key_id {
        bob.consume_one_time_key(otk_id)
    } else {
        None
    };

    // Desencapsular ciphertext Kyber
    let ciphertext_bytes = B64.decode(&init_message.kyber_ciphertext)?;
    let ciphertext = KyberCiphertext::from_bytes(&ciphertext_bytes)
        .map_err(|_| anyhow::anyhow!("Invalid Kyber ciphertext"))?;
    
    let shared_secret_kyber = kyber1024::decapsulate(&ciphertext, &bob.kyber_prekey_private);
    
    // Modelo vodozemac: usar DH keys diretamente
    // Alice enviou sua diffie_hellman_key pública (Curve25519 independente)
    // Bob usa sua própria diffie_hellman_key privada
    
    // Realizar as trocas Diffie-Hellman (3 ou 4 dependendo do uso de OTK)
    // dh1: Bob's X25519 prekey private × Alice's identity DH public
    // dh2: Bob's identity DH private × Alice's ephemeral public
    // dh3: Bob's X25519 prekey private × Alice's ephemeral public
    // dh4: Bob's OTK private × Alice's ephemeral public (se OTK usado)
    let dh1 = bob.x25519_prekey_private.diffie_hellman(&alice_dh_public_key);
    let dh2 = bob.diffie_hellman_key.diffie_hellman(&ephemeral_key);
    let dh3 = bob.x25519_prekey_private.diffie_hellman(&ephemeral_key);
    let dh4 = otk_private.as_ref().map(|otk| otk.diffie_hellman(&ephemeral_key));
    
    // Derivar chave de sessão com Associated Data completo
    // Decodificar chaves públicas de Bob para binding
    let bob_x25519_prekey_bytes = B64.decode(&bob.x25519_prekey.public_key)?;
    let bob_kyber_prekey_bytes = B64.decode(&bob.kyber_prekey.public_key)?;
    
    let session_key = matrix_pqxdh_kdf(
        // Segredos compartilhados
        dh1.as_bytes(),
        dh2.as_bytes(),
        dh3.as_bytes(),
        dh4.as_ref().map(|dh| dh.as_bytes() as &[u8]),
        shared_secret_kyber.as_bytes(),
        // Associated Data - binding de chaves públicas
        // IMPORTANTE: Usar DH public keys (Curve25519), não signing keys (Ed25519)
        alice_dh_public_key.as_bytes(),  // Chave DH de Alice (Curve25519)
        bob.dh_public_key.as_bytes(),     // Chave DH de Bob (Curve25519)
        &bob_x25519_prekey_bytes,
        &bob_kyber_prekey_bytes,
        bob_otk_bytes.as_ref().map(|b| b.as_slice()),
        ephemeral_key.as_bytes(),
        // Contexto Matrix
        &init_message.sender_user_id,
        &bob.user_id
    );
    
    Ok(session_key)
}

/// FUNÇÃO DE DERIVAÇÃO DE CHAVES PQXDH com ASSOCIATED DATA
/// 
/// Implementa derivação de chaves híbrida usando HKDF-SHA-256 para combinar:
/// - 3-4 segredos compartilhados de acordos Diffie-Hellman clássicos
/// - 1 segredo compartilhado de encapsulamento KEM pós-quântico
/// - Associated Data: TODAS as chaves públicas envolvidas (previne KCI)
/// - Contexto específico do Matrix (IDs de usuário)
/// 
/// # Estrutura da Derivação (Conforme PQXDH Spec)
/// 1. Concatenação de todos os segredos compartilhados (DH + KEM) como IKM
/// 2. Separação de domínio para Curve25519 (0xFF * 32)
/// 3. Associated Data como Info do HKDF:
///    - alice_identity_key (Curve25519 DH, longo prazo)
///    - bob_identity_key (Curve25519 DH, longo prazo)
///    - bob_x25519_prekey (médio prazo)
///    - bob_kyber_prekey (KEM médio prazo, NÃO identidade)
///    - bob_one_time_key (curto prazo, opcional)
///    - ephemeral_key (X25519 ephemeral)
/// 4. Contexto Matrix (user IDs)
/// 5. Extração e expansão HKDF-SHA-256
/// 
/// # Parâmetros
/// Segredos Compartilhados
/// * `dh1-dh3` - Segredos DH obrigatórios
/// * `dh4` - Segredo DH opcional (se OTK usada)
/// * `kyber_ss` - Segredo compartilhado KEM
/// 
/// Associated Data (Chaves Públicas)
/// * `alice_identity` - Chave identidade DH Curve25519 de Alice
/// * `bob_identity` - Chave identidade DH Curve25519 de Bob
/// * `bob_x25519_prekey` - Prekey X25519 de Bob
/// * `bob_kyber_prekey` - Prekey Kyber de Bob (médio prazo, não identidade)
/// * `bob_one_time_key` - OTK de Bob (opcional)
/// * `ephemeral_key` - Chave efêmera X25519 de Alice
/// 
/// ## Contexto
/// * `alice_user_id`, `bob_user_id` - IDs Matrix
/// 
/// # Segurança
/// - Previne Key Compromise Impersonation (KCI) attacks
/// - Binding criptográfico de todas as chaves públicas
/// - Conforme especificação PQXDH do Signal
/// - HKDF-SHA-256 fornece derivação segura conforme RFC 5869
fn matrix_pqxdh_kdf(
    // Segredos compartilhados
    dh1: &[u8],
    dh2: &[u8], 
    dh3: &[u8],
    dh4: Option<&[u8]>,
    kyber_ss: &[u8],
    // Associated Data (chaves públicas)
    alice_identity: &[u8],
    bob_identity: &[u8],
    bob_x25519_prekey: &[u8],
    bob_kyber_prekey: &[u8],
    bob_one_time_key: Option<&[u8]>,
    ephemeral_key: &[u8],
    // Contexto Matrix
    alice_user_id: &str,
    bob_user_id: &str
) -> [u8; 32] {
    // 1. Concatenar todos os segredos compartilhados como Input Key Material (IKM)
    let mut ikm = Vec::new();
    
    // Separação de domínio para Curve25519 (0xFF * 32)
    ikm.extend_from_slice(&[0xffu8; 32]);
    
    // Segredos DH
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    if let Some(dh4_bytes) = dh4 {
        ikm.extend_from_slice(dh4_bytes);
    }
    
    // Segredo KEM
    ikm.extend_from_slice(kyber_ss);
    
    // 2. Construir Info com Associated Data (binding de chaves públicas)
    let mut info = Vec::new();
    
    // Label de domínio
    info.extend_from_slice(b"MATRIX_PQXDH_KDF_v1");
    
    // Chaves públicas (previne KCI)
    info.extend_from_slice(alice_identity);
    info.extend_from_slice(bob_identity);
    info.extend_from_slice(bob_x25519_prekey);
    info.extend_from_slice(bob_kyber_prekey);
    if let Some(otk) = bob_one_time_key {
        info.extend_from_slice(otk);
    }
    info.extend_from_slice(ephemeral_key);
    
    // Contexto Matrix
    let context = format!("{}|{}", alice_user_id, bob_user_id);
    info.extend_from_slice(context.as_bytes());
    
    // 3. Executar HKDF-SHA-256 (Extract-then-Expand)
    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut output = [0u8; 32];
    hkdf.expand(&info, &mut output)
        .expect("HKDF-SHA-256 expand failed - info too long");
    
    output
}
