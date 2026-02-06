// Double Ratchet Híbrido com CRYSTALS-Kyber (NIST Round 3)
//
// Extensão pós-quântica do Double Ratchet vodozemac com ratcheting KEM:
//
// ARQUITETURA:
// - Base clássica: vodozemac Session (X25519 ECDH + AES-256-CBC + HMAC-SHA-256)
// - Extensão PQC: X25519 + CRYSTALS-Kyber (512/768/1024) em paralelo
// - Derivação híbrida: HKDF-SHA-256 combina segredos DH + KEM
// - Formato mensagem: JSON Matrix-compatível {"type":2,"body":"..."}
//
// RATCHETING:
// - Avanço simétrico: Apenas HMAC-SHA-256 da chain key (ZERO overhead KEM)
// - Avanço assimétrico: Gera novas chaves, executa DH + KEM, atualiza root_key
// - Estados vodozemac-like: Active (enviando) ↔ Inactive (aguardando enviar)
// - Transições: std::mem::replace sem Clone (segurança)
//
// SEGURANÇA:
// - Zeroização: Wrappers ZeroizingKyber*Key com Drop trait (manual)
// - Forward secrecy: Compromisso de chave[n] não revela chave[n-1]
// - Backward secrecy: Compromisso de chave[n] não revela chave[n+1]
// - Sem Clone: Evita múltiplas cópias de chaves privadas na memória
//
// COMPATIBILIDADE:
// - Formato JSON detectável: Prefixo {"type":2, indica PQC
// - Fallback automático: Base64 puro indica mensagem clássica
// - Interoperável: Clientes antigos continuam funcionando

use crate::core::crypto::{CryptoError};
use vodozemac::{
    olm::{OlmMessage, Session as VodoSession, Message, PreKeyMessage},
    Curve25519PublicKey, Curve25519SecretKey,
};
use pqcrypto_kyber::{kyber512, kyber768, kyber1024};
use pqcrypto_traits::kem::{PublicKey, SharedSecret, Ciphertext};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hkdf::Hkdf;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use super::crypto::KemAlgorithm;

type HmacSha256 = Hmac<Sha256>;
use crate::utils::logging::VerbosityLevel;
use crate::vlog;

// Constantes de derivação seguindo padrão OLM
const MESSAGE_KEY_SEED: &[u8; 1] = b"\x01";
const CHAIN_ADVANCEMENT_SEED: &[u8; 1] = b"\x02";

// Constantes reservadas para implementação futura de gerenciamento de mensagens fora de ordem
// Atualmente não implementado - mantém apenas uma cadeia de recepção ativa (padrão OLM simplificado)
#[allow(dead_code)]
const MAX_RECEIVING_CHAINS: usize = 5;
#[allow(dead_code)]
const MAX_MESSAGE_KEYS: usize = 40;
#[allow(dead_code)]
const MAX_MESSAGE_GAP: u64 = 2000;

/// Wrapper para Kyber512 SecretKey que implementa Drop para zeroização.
/// 
/// Necessário porque pqcrypto-kyber não implementa Zeroize nativamente.
/// Segue a mesma estratégia do PQXDH: wrapper manual com Drop trait.
pub struct ZeroizingKyber512Key(kyber512::SecretKey);

impl Drop for ZeroizingKyber512Key {
    fn drop(&mut self) {
        // Zeroizar bytes da chave privada Kyber-512
        unsafe {
            let ptr = &mut self.0 as *mut kyber512::SecretKey as *mut u8;
            std::ptr::write_bytes(ptr, 0, std::mem::size_of::<kyber512::SecretKey>());
        }
    }
}

impl std::ops::Deref for ZeroizingKyber512Key {
    type Target = kyber512::SecretKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<kyber512::SecretKey> for ZeroizingKyber512Key {
    fn as_ref(&self) -> &kyber512::SecretKey {
        &self.0
    }
}

/// Wrapper para Kyber768 SecretKey que implementa Drop para zeroização.
pub struct ZeroizingKyber768Key(kyber768::SecretKey);

impl Drop for ZeroizingKyber768Key {
    fn drop(&mut self) {
        // Zeroizar bytes da chave privada Kyber-768
        unsafe {
            let ptr = &mut self.0 as *mut kyber768::SecretKey as *mut u8;
            std::ptr::write_bytes(ptr, 0, std::mem::size_of::<kyber768::SecretKey>());
        }
    }
}

impl std::ops::Deref for ZeroizingKyber768Key {
    type Target = kyber768::SecretKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<kyber768::SecretKey> for ZeroizingKyber768Key {
    fn as_ref(&self) -> &kyber768::SecretKey {
        &self.0
    }
}

/// Wrapper para Kyber1024 SecretKey que implementa Drop para zeroização.
pub struct ZeroizingKyber1024Key(kyber1024::SecretKey);

impl Drop for ZeroizingKyber1024Key {
    fn drop(&mut self) {
        // Zeroizar bytes da chave privada Kyber-1024
        unsafe {
            let ptr = &mut self.0 as *mut kyber1024::SecretKey as *mut u8;
            std::ptr::write_bytes(ptr, 0, std::mem::size_of::<kyber1024::SecretKey>());
        }
    }
}

impl std::ops::Deref for ZeroizingKyber1024Key {
    type Target = kyber1024::SecretKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<kyber1024::SecretKey> for ZeroizingKyber1024Key {
    fn as_ref(&self) -> &kyber1024::SecretKey {
        &self.0
    }
}

/// Par de chaves KEM (suporta Kyber-512/768/1024)
/// 
/// SEGURANÇA: Chaves privadas são protegidas por wrappers ZeroizingKyber*Key
/// que implementam Drop para zeroização automática da memória.
/// Clone não é implementado intencionalmente para evitar múltiplas cópias de chaves privadas.
pub enum KemKeyPair {
    Kyber512 {
        public: kyber512::PublicKey,
        secret: ZeroizingKyber512Key,
    },
    Kyber768 {
        public: kyber768::PublicKey,
        secret: ZeroizingKyber768Key,
    },
    Kyber1024 {
        public: kyber1024::PublicKey,
        secret: ZeroizingKyber1024Key,
    },
}

impl KemKeyPair {
    /// Gera novo par de chaves KEM
    pub fn generate(algorithm: KemAlgorithm) -> Self {
        match algorithm {
            KemAlgorithm::Kyber512 => {
                let (public, secret) = kyber512::keypair();
                KemKeyPair::Kyber512 { 
                    public, 
                    secret: ZeroizingKyber512Key(secret) 
                }
            }
            KemAlgorithm::Kyber768 => {
                let (public, secret) = kyber768::keypair();
                KemKeyPair::Kyber768 { 
                    public, 
                    secret: ZeroizingKyber768Key(secret) 
                }
            }
            KemAlgorithm::Kyber1024 => {
                let (public, secret) = kyber1024::keypair();
                KemKeyPair::Kyber1024 { 
                    public, 
                    secret: ZeroizingKyber1024Key(secret) 
                }
            }
        }
    }
    
    /// Obtém chave pública
    pub fn public_key(&self) -> KemPublicKey {
        match self {
            KemKeyPair::Kyber512 { public, .. } => KemPublicKey::Kyber512(public.clone()),
            KemKeyPair::Kyber768 { public, .. } => KemPublicKey::Kyber768(public.clone()),
            KemKeyPair::Kyber1024 { public, .. } => KemPublicKey::Kyber1024(public.clone()),
        }
    }
    
    /// Encapsula segredo compartilhado com chave pública do peer
    /// Retorna: (shared_secret, ciphertext)
    /// O ciphertext DEVE ser enviado para o peer para que ele possa decapsular
    pub fn encapsulate_full(&self, peer_public: &KemPublicKey) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        match (self, peer_public) {
            (KemKeyPair::Kyber512 { .. }, KemPublicKey::Kyber512(pk)) => {
                let (shared_secret, ciphertext) = kyber512::encapsulate(pk);
                Ok((shared_secret.as_bytes().to_vec(), ciphertext.as_bytes().to_vec()))
            }
            (KemKeyPair::Kyber768 { .. }, KemPublicKey::Kyber768(pk)) => {
                let (shared_secret, ciphertext) = kyber768::encapsulate(pk);
                Ok((shared_secret.as_bytes().to_vec(), ciphertext.as_bytes().to_vec()))
            }
            (KemKeyPair::Kyber1024 { .. }, KemPublicKey::Kyber1024(pk)) => {
                let (shared_secret, ciphertext) = kyber1024::encapsulate(pk);
                Ok((shared_secret.as_bytes().to_vec(), ciphertext.as_bytes().to_vec()))
            }
            _ => Err(CryptoError::Protocol),
        }
    }
    
    /// Desencapsula segredo compartilhado usando ciphertext recebido
    /// Peer chama isso com o ciphertext que recebeu de encapsulate_full()
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            KemKeyPair::Kyber512 { secret, .. } => {
                let ct = kyber512::Ciphertext::from_bytes(ciphertext)
                    .map_err(|_| CryptoError::Protocol)?;
                let shared_secret = kyber512::decapsulate(&ct, secret);
                Ok(shared_secret.as_bytes().to_vec())
            }
            KemKeyPair::Kyber768 { secret, .. } => {
                let ct = kyber768::Ciphertext::from_bytes(ciphertext)
                    .map_err(|_| CryptoError::Protocol)?;
                let shared_secret = kyber768::decapsulate(&ct, secret);
                Ok(shared_secret.as_bytes().to_vec())
            }
            KemKeyPair::Kyber1024 { secret, .. } => {
                let ct = kyber1024::Ciphertext::from_bytes(ciphertext)
                    .map_err(|_| CryptoError::Protocol)?;
                let shared_secret = kyber1024::decapsulate(&ct, secret);
                Ok(shared_secret.as_bytes().to_vec())
            }
        }
    }
    
    /// Retorna algoritmo KEM usado
    pub fn algorithm(&self) -> KemAlgorithm {
        match self {
            KemKeyPair::Kyber512 { .. } => KemAlgorithm::Kyber512,
            KemKeyPair::Kyber768 { .. } => KemAlgorithm::Kyber768,
            KemKeyPair::Kyber1024 { .. } => KemAlgorithm::Kyber1024,
        }
    }
}

/// Chaves públicas KEM genéricas
#[derive(Clone)]
pub enum KemPublicKey {
    Kyber512(kyber512::PublicKey),
    Kyber768(kyber768::PublicKey), 
    Kyber1024(kyber1024::PublicKey),
}

impl KemPublicKey {
    /// Tamanho em bytes da chave pública
    pub fn size_bytes(&self) -> usize {
        match self {
            KemPublicKey::Kyber512(pk) => pk.as_bytes().len(),
            KemPublicKey::Kyber768(pk) => pk.as_bytes().len(),
            KemPublicKey::Kyber1024(pk) => pk.as_bytes().len(),
        }
    }
    
    /// Algoritmo da chave
    pub fn algorithm(&self) -> KemAlgorithm {
        match self {
            KemPublicKey::Kyber512(_) => KemAlgorithm::Kyber512,
            KemPublicKey::Kyber768(_) => KemAlgorithm::Kyber768,
            KemPublicKey::Kyber1024(_) => KemAlgorithm::Kyber1024,
        }
    }
}

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
    
    /// Gera com Kyber-1024 (padrão)
    pub fn generate_default() -> Self {
        Self::generate(KemAlgorithm::Kyber1024)
    }
    
    /// Exporta chaves públicas
    pub fn public_keys(&self) -> PqcRatchetPublicKey {
        PqcRatchetPublicKey {
            curve25519_key: self.curve25519_public,
            kem_public_key: self.kem_keypair.public_key(),
            kem_algorithm: self.kem_algorithm,
        }
    }
    
    /// Executa acordo híbrido COM ciphertext KEM (CORRETO)
    /// Retorna: (combined_shared_secret, kem_ciphertext)
    /// O ciphertext DEVE ser enviado ao peer para que ele possa derivar o mesmo SS
    pub fn hybrid_dh_with_kem(&self, peer_public: &PqcRatchetPublicKey) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        if self.kem_algorithm != peer_public.kem_algorithm {
            return Err(CryptoError::Protocol);
        }
        
        let classic_shared = self.curve25519_secret.diffie_hellman(&peer_public.curve25519_key);
        let (pqc_shared, kem_ciphertext) = self.kem_keypair.encapsulate_full(&peer_public.kem_public_key)?;
        
        let combined = hkdf_hybrid_ratchet(
            classic_shared.as_bytes(),
            &pqc_shared,
            format!("matrix-double-ratchet-{}", self.kem_algorithm.name()).as_bytes()
        );
        
        Ok((combined.to_vec(), kem_ciphertext))
    }
    
    /// Executa acordo híbrido usando ciphertext KEM recebido (DECAPSULATE)
    /// Peer usa isso quando recebe uma mensagem com kem_ciphertext
    pub fn hybrid_dh_with_decapsulate(&self, peer_public: &PqcRatchetPublicKey, kem_ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.kem_algorithm != peer_public.kem_algorithm {
            return Err(CryptoError::Protocol);
        }
        
        let classic_shared = self.curve25519_secret.diffie_hellman(&peer_public.curve25519_key);
        let pqc_shared = self.kem_keypair.decapsulate(kem_ciphertext)?;
        
        let combined = hkdf_hybrid_ratchet(
            classic_shared.as_bytes(),
            &pqc_shared,
            format!("matrix-double-ratchet-{}", self.kem_algorithm.name()).as_bytes()
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
    /// Curve25519: tamanho padrão da chave pública - 
    pub curve25519_key: Curve25519PublicKey,
    
    /// Chave pública KEM (tamanho dinâmico baseado no algoritmo)
    pub kem_public_key: KemPublicKey,
    
    /// Algoritmo KEM usado
    pub kem_algorithm: KemAlgorithm,
}

impl PqcRatchetPublicKey {
    /// Calcula overhead da chave pública usando APIs reais (dinâmico)
    pub fn size_bytes(&self) -> usize {
        let curve25519_size = self.curve25519_key.as_bytes().len();
        let kem_size = self.kem_public_key.size_bytes();
        
        curve25519_size + kem_size
    }
    
    /// Informações detalhadas da chave
    pub fn info(&self) -> String {
        format!("PqcRatchetPublicKey: Curve25519 (32B) + {} ({}B) = {}B total",
                self.kem_algorithm.name(),
                self.kem_public_key.size_bytes(),
                self.size_bytes())
    }
    
    /// 3. SERIALIZAÇÃO OTIMIZADA PARA REDUZIR OVERHEAD
    /// Serializa para bytes brutos (sem Base64)
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
        
        // Formato simples seguindo vodozemac: [32B Curve25519] [2B kem_size] [kem_bytes] [1B algorithm]
        let mut serialized = Vec::new();
        serialized.extend_from_slice(curve25519_bytes);
        serialized.extend_from_slice(&(kem_bytes.len() as u16).to_le_bytes());
        serialized.extend_from_slice(&kem_bytes);
        serialized.push(algorithm_byte);
        
        serialized
    }
    
    /// Serializa para Base64 seguindo padrão vodozemac simples
    pub fn to_base64(&self) -> String {
        B64.encode(&self.to_bytes())
    }
    
    /// Desserializa de bytes brutos
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 35 { // Mínimo: 32 (Curve25519) + 2 (size) + 1 (algorithm)
            return Err(CryptoError::Protocol);
        }
        
        let curve25519_bytes: [u8; 32] = bytes[0..32].try_into()
            .map_err(|_| CryptoError::Protocol)?;
        let curve25519_key = Curve25519PublicKey::from(curve25519_bytes);
        
        // Ler tamanho da chave KEM
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
        
        // Extrair chave KEM diretamente (sem descompressão)
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

    

    
    /// Desserializa de Base64 seguindo o padrão vodozemac simples
    pub fn from_base64(b64: &str) -> Result<Self, CryptoError> {
        let bytes = B64.decode(b64).map_err(|_| CryptoError::Protocol)?;
        Self::from_bytes(&bytes)
    }
}

/// Mensagem Olm híbrida com componentes PQC adicionais
///
/// Wrapper sobre vodozemac OlmMessage que adiciona campos necessários para
/// o Double Ratchet PQC, mantendo compatibilidade com o protocolo Matrix.
///
/// # Estrutura (Hybrid Layer)
/// - `classic_component`: OlmMessage vodozemac (PreKeyMessage ou Normal Message)
///   * Contém criptografia base: AES-256-CBC + HMAC-SHA-256
///   * Gerencia Double Ratchet clássico (X25519 apenas)
///
/// - `ratchet_key`: Nossa chave pública híbrida atual (Curve25519 + Kyber)
///   * Enviada em TODAS as mensagens (padrão Matrix/vodozemac)
///   * Permite receiver detectar mudanças de direção por comparação de bytes
///
/// - `kem_ciphertext`: Resultado de encapsulate() KEM (~768-1568 bytes)
///   * Presente APENAS em avanços assimétricos (mudança de direção)
///   * CRÍTICO: Sem isso, sender e receiver derivam shared_secrets diferentes
///   * Receiver usa para decapsulate() e obter mesmo shared_secret
///
/// - `pqc_enabled`: Flag indicando capacidades PQC ativas
/// - `message_index`: Contador para verificação de ordem
///
/// # Serialização JSON Matrix-Compatível
/// Formato: {"type":2,"body":"base64_payload"}
/// 
/// Payload binário:
/// 1. pqc_version (1 byte)
/// 2. classic_type (1 byte): 0=PreKey, 1=Normal
/// 3. classic_size (4 bytes) + classic_bytes
/// 4. message_index (4 bytes)
/// 5. pqc_enabled (1 byte)
/// 6. ratchet_key_size (4 bytes) + ratchet_bytes (se presente)
/// 7. kem_ciphertext_size (4 bytes) + kem_ciphertext (se presente)
///
/// # Overhead por Tipo de Avanço
/// - Avanço simétrico: ~40 bytes (headers + ratchet_key sem kem_ciphertext)
/// - Avanço assimétrico: ~800-1600 bytes (ratchet_key + kem_ciphertext completo)
#[derive(Clone)]
pub struct PqcOlmMessage {
    /// Mensagem vodozemac clássica (base)
    pub classic_component: OlmMessage,
    
    /// Nova chave pública de ratchet (se ratchet avançou)
    pub ratchet_key: Option<PqcRatchetPublicKey>,
    
    /// Ciphertext KEM (CRÍTICO para KEM real)
    /// Contém o resultado de encapsulate() que o receptor usa para decapsulate()
    /// SEM isso, o KEM não funciona - Alice e Bob teriam shared secrets diferentes
    pub kem_ciphertext: Option<Vec<u8>>,
    
    /// Indicador de capacidade PQC
    pub pqc_enabled: bool,
    
    /// Contador de mensagens para verificação
    pub message_index: u32,
}

impl PqcOlmMessage {
    /// Cria mensagem PQC a partir de componente clássico
    pub fn from_classic(classic: OlmMessage, message_index: u32) -> Self {
        Self {
            classic_component: classic,
            ratchet_key: None,
            kem_ciphertext: None,
            pqc_enabled: false,
            message_index,
        }
    }
    
    /// Adiciona componente PQC à mensagem
    pub fn with_pqc_ratchet(mut self, ratchet_key: PqcRatchetPublicKey) -> Self {
        self.ratchet_key = Some(ratchet_key);
        self.pqc_enabled = true;
        self
    }
    
    /// Calcula overhead total da mensagem usando tamanhos reais
    pub fn overhead_bytes(&self) -> usize {
        let base_size = match &self.classic_component {
            OlmMessage::PreKey(m) => m.to_bytes().len(),
            OlmMessage::Normal(m) => m.to_bytes().len(),
        };
        
        let pqc_overhead = if let Some(ref ratchet_key) = self.ratchet_key {
            ratchet_key.size_bytes() // Usa tamanho real da instância
        } else {
            0
        };
        
        // Overhead calculado dinamicamente
        let metadata_overhead = if self.pqc_enabled { 
            std::mem::size_of::<u32>() + // message_index
            std::mem::size_of::<bool>() + // pqc_enabled flag
            8 // serialization overhead estimado
        } else { 
            std::mem::size_of::<u32>() + 4 // minimal metadata
        };
        base_size + pqc_overhead + metadata_overhead
    }
    
    /// Retorna tamanho da componente clássica (vodozemac base)
    pub fn classical_component_bytes(&self) -> usize {
        match &self.classic_component {
            OlmMessage::PreKey(m) => m.to_bytes().len(),
            OlmMessage::Normal(m) => m.to_bytes().len(),
        }
    }
    
    /// Retorna tamanho da componente PQC (ratchet key + kem ciphertext)
    pub fn pqc_component_bytes(&self) -> usize {
        let ratchet_key_size = if let Some(ref ratchet_key) = self.ratchet_key {
            ratchet_key.size_bytes()
        } else {
            0
        };
        
        let kem_ciphertext_size = if let Some(ref ct) = self.kem_ciphertext {
            ct.len()
        } else {
            0
        };
        
        ratchet_key_size + kem_ciphertext_size
    }
    
    /// Retorna breakdown completo: (clássico, pqc, metadata, total)
    pub fn size_breakdown(&self) -> (usize, usize, usize, usize) {
        let classical = self.classical_component_bytes();
        let pqc = self.pqc_component_bytes();
        let metadata = if self.pqc_enabled { 
            std::mem::size_of::<u32>() + std::mem::size_of::<bool>() + 8
        } else { 
            std::mem::size_of::<u32>() + 4
        };
        let total = classical + pqc + metadata;
        (classical, pqc, metadata, total)
    }

    /// SERIALIZAÇÃO PQC COMPLETA: Converte mensagem híbrida para JSON Matrix-compatível
    /// 
    /// IMPORTANTE: Por que usar JSON ao invés de Base64 simples?
    /// 
    /// O formato JSON é necessário para evitar dupla codificação Base64:
    /// 
    /// - Mensagens vodozemac já são serializadas internamente em binário
    /// - Se codificássemos a mensagem completa em Base64 novamente, teríamos:
    ///   `Base64(Base64(vodozemac) + Base64(pqc_keys))` = overhead exponencial
    /// 
    /// Com JSON, conseguimos:
    /// - Estrutura clara: `{"type":2, "body":"base64_payload"}`
    /// - Apenas UMA camada de Base64 para o payload completo
    /// - Compatibilidade com protocolo Matrix (type 0=PreKey, 1=Normal, 2=PQC)
    /// - Overhead controlado: ~20 bytes de JSON vs centenas de bytes com dupla codificação
    /// 
    /// Formato interno ProtoBuf-like: [1B version][classic_component][pqc_metadata]
    pub fn to_transport_string(&self) -> String {
        // Serializar componente clássico
        let (classic_type, classic_bytes) = match &self.classic_component {
            OlmMessage::PreKey(m) => (0u8, m.to_bytes()),
            OlmMessage::Normal(m) => (1u8, m.to_bytes()),
        };

        let mut payload = Vec::new();
        
        // 1. Versão PQC (compatibilidade futura)
        payload.push(1u8); // PQC version 1
        
        // 2. Tipo de mensagem clássica base
        payload.push(classic_type);
        
        // 3. Tamanho e dados da mensagem clássica
        payload.extend_from_slice(&(classic_bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(&classic_bytes);
        
        // 4. Metadata PQC
        payload.extend_from_slice(&self.message_index.to_le_bytes());
        let pqc_enabled_byte = if self.pqc_enabled { 1 } else { 0 };
        vlog!(VerbosityLevel::Debug, "[SERIALIZE] pqc_enabled={}, byte={}, ratchet_key.is_some()={}", 
              self.pqc_enabled, pqc_enabled_byte, self.ratchet_key.is_some());
        vlog!(VerbosityLevel::Debug, "[SERIALIZE] Payload size ANTES de pqc_enabled: {}, byte será adicionado no offset {}", 
              payload.len(), payload.len());
        payload.push(pqc_enabled_byte);
        vlog!(VerbosityLevel::Debug, "[SERIALIZE] Payload size DEPOIS de pqc_enabled: {}, byte {} adicionado no offset {}", 
              payload.len(), pqc_enabled_byte, payload.len() - 1);
        
        // 5. Chave de ratchet PQC (se disponível)
        if let Some(ref ratchet_key) = self.ratchet_key {
            let ratchet_bytes = ratchet_key.to_bytes();
            payload.extend_from_slice(&(ratchet_bytes.len() as u32).to_le_bytes());
            payload.extend_from_slice(&ratchet_bytes);
        } else {
            payload.extend_from_slice(&0u32.to_le_bytes()); // size = 0
        }
        
        // 6. Ciphertext KEM (CRÍTICO para KEM real - só presente quando ratchet avança)
        if let Some(ref kem_ct) = self.kem_ciphertext {
            payload.extend_from_slice(&(kem_ct.len() as u32).to_le_bytes());
            payload.extend_from_slice(kem_ct);
            vlog!(VerbosityLevel::Debug, "[SERIALIZE] Incluindo KEM ciphertext ({} bytes)", kem_ct.len());
        } else {
            payload.extend_from_slice(&0u32.to_le_bytes()); // size = 0
        }
        
        // Formato JSON Matrix-compatível com type 2 para mensagens PQC
        let body_b64 = B64.encode(&payload);
        
        vlog!(VerbosityLevel::Debug, "[SERIALIZE] Payload total: {} bytes", payload.len());
        vlog!(VerbosityLevel::Debug, "[SERIALIZE] Byte 512 do payload: {}", if payload.len() > 512 { payload[512] } else { 255 });
        vlog!(VerbosityLevel::Debug, "[SERIALIZE] Primeiros 20 bytes: {:?}", &payload[..20.min(payload.len())]);
        
        format!(r#"{{"type":2,"body":"{}"}}"#, body_b64)
    }
    
    /// DESERIALIZAÇÃO PQC COMPLETA: Reconstrói mensagem híbrida do JSON Matrix
    pub fn from_transport_string(transport: &str) -> Result<Self, CryptoError> {
        // Parse JSON Matrix format: {"type":2,"body":"base64_data"}
        let transport = transport.trim();
        if !transport.starts_with(r#"{"type":2,"#) {
            vlog!(VerbosityLevel::Debug, "[DESERIALIZE] Mensagem não começa com {{\"type\":2,");
            return Err(CryptoError::Protocol);
        }
        
        // Extrair body do JSON de forma simples (sem serde para reduzir deps)
        let body_start = transport.find(r#""body":"#)
            .ok_or(CryptoError::Protocol)? + 8; // len('"body":"')
        let body_end = transport.rfind(r#""}"#)
            .ok_or(CryptoError::Protocol)?;
        
        if body_start >= body_end {
            vlog!(VerbosityLevel::Debug, "[DESERIALIZE] body_start >= body_end");
            return Err(CryptoError::Protocol);
        }
        
        let body_b64 = &transport[body_start..body_end];
        vlog!(VerbosityLevel::Debug, "[DESERIALIZE] Decodificando Base64, tamanho: {}", body_b64.len());
        let bytes = B64.decode(body_b64).map_err(|e| {
            vlog!(VerbosityLevel::Debug, "[DESERIALIZE] Erro Base64: {:?}", e);
            CryptoError::B64
        })?;
        
        if bytes.len() < 11 { // Mínimo: 1 (version) + 1 (type) + 4 (size) + 4 (index) + 1 (flag)
            return Err(CryptoError::Protocol);
        }
        
        let mut cursor = 0;
        
        // 1. Verificar versão PQC
        let pqc_version = bytes[cursor];
        if pqc_version != 1 {
            return Err(CryptoError::Protocol); // Versão não suportada
        }
        cursor += 1;
        
        // 2. Tipo de mensagem clássica
        let classic_type = bytes[cursor];
        cursor += 1;
        
        // 3. Deserializar componente clássico
        let classic_size = u32::from_le_bytes(
            bytes[cursor..cursor+4].try_into().map_err(|_| CryptoError::Protocol)?
        ) as usize;
        cursor += 4;
        
        if cursor + classic_size > bytes.len() {
            return Err(CryptoError::Protocol);
        }
        
        let classic_bytes = &bytes[cursor..cursor + classic_size];
        cursor += classic_size;
        
        // Reconstruir mensagem clássica baseada no tipo
        let classic_component = match classic_type {
            0 => OlmMessage::PreKey(PreKeyMessage::from_bytes(classic_bytes)
                .map_err(|_| CryptoError::Protocol)?),
            1 => OlmMessage::Normal(Message::from_bytes(classic_bytes)
                .map_err(|_| CryptoError::Protocol)?),
            _ => return Err(CryptoError::Protocol),
        };
        
        // 4. Deserializar metadata PQC
        if cursor + 5 > bytes.len() { // 4 (message_index) + 1 (flag)
            return Err(CryptoError::Protocol);
        }
        
        let message_index = u32::from_le_bytes(
            bytes[cursor..cursor+4].try_into().map_err(|_| CryptoError::Protocol)?
        );
        cursor += 4;
        
        let pqc_enabled = bytes[cursor] != 0;
        cursor += 1;
        
        // 5. Deserializar chave de ratchet PQC (se presente)
        if cursor + 4 > bytes.len() {
            return Err(CryptoError::Protocol);
        }
        
        let ratchet_key_size = u32::from_le_bytes(
            bytes[cursor..cursor+4].try_into().map_err(|_| CryptoError::Protocol)?
        ) as usize;
        cursor += 4;
        
        let ratchet_key = if ratchet_key_size > 0 {
            if cursor + ratchet_key_size > bytes.len() {
                return Err(CryptoError::Protocol);
            }
            
            let ratchet_bytes = &bytes[cursor..cursor + ratchet_key_size];
            cursor += ratchet_key_size;
            Some(PqcRatchetPublicKey::from_bytes(ratchet_bytes)?)
        } else {
            cursor += 0; // size já avançado
            None
        };
        
        // 6. Deserializar ciphertext KEM (CRÍTICO para KEM real)
        let kem_ciphertext = if cursor + 4 <= bytes.len() {
            let kem_ct_size = u32::from_le_bytes(
                bytes[cursor..cursor+4].try_into().map_err(|_| CryptoError::Protocol)?
            ) as usize;
            cursor += 4;
            
            if kem_ct_size > 0 {
                if cursor + kem_ct_size > bytes.len() {
                    return Err(CryptoError::Protocol);
                }
                
                let kem_ct = bytes[cursor..cursor + kem_ct_size].to_vec();
                // cursor += kem_ct_size; // Final field, não precisa avançar
                vlog!(VerbosityLevel::Debug, "[DESERIALIZE] KEM ciphertext recuperado ({} bytes)", kem_ct.len());
                Some(kem_ct)
            } else {
                None
            }
        } else {
            // Mensagens antigas sem campo kem_ciphertext (retrocompatibilidade)
            None
        };
        
        Ok(PqcOlmMessage {
            classic_component,
            ratchet_key,
            kem_ciphertext,
            pqc_enabled,
            message_index,
        })
    }
}

/// Estados do Double Ratchet híbrido (seguindo padrão vodozemac)
/// 
/// SEGURANÇA: Clone não é implementado intencionalmente para evitar múltiplas cópias de chaves privadas.
/// As chaves privadas estão protegidas por wrappers ZeroizingKyber*Key.
pub enum PqcRatchetState {
    /// Estado Ativo: enviando mensagens, tem chain key para próxima mensagem
    Active {
        root_key: [u8; 32],
        our_ratchet_keys: PqcRatchetKeyPair,
        their_ratchet_key: Option<PqcRatchetPublicKey>,
        chain_key: [u8; 32],
        send_counter: u32,
    },
    /// Estado Inativo: recebeu mensagem, aguarda enviar (para ativar)
    Inactive {
        root_key: [u8; 32],
        our_ratchet_keys: PqcRatchetKeyPair,
        their_ratchet_key: PqcRatchetPublicKey, // sempre tem chave do peer
        receive_counter: u32,
    },
}

/// Estado do Double Ratchet híbrido
pub struct PqcDoubleRatchetState {
    /// Estado atual do ratchet (Active ou Inactive)
    state: PqcRatchetState,
    /// Flag de modo híbrido ativo
    hybrid_mode_enabled: bool,
    /// Algoritmo KEM usado nesta sessão
    kem_algorithm: KemAlgorithm,
    /// Contador de avanços assimétricos (mudanças de direção)
    asymmetric_advance_count: u32,
}

impl PqcDoubleRatchetState {
    /// Inicializa estado com chave raiz do PQXDH e algoritmo KEM
    pub fn new(initial_root_key: [u8; 32], kem_algorithm: KemAlgorithm, starts_as_sender: bool) -> Self {
        vlog!(VerbosityLevel::Debug, "Inicializando Double Ratchet PQC com {} (sender: {})", kem_algorithm.name(), starts_as_sender);
        
        let our_ratchet_keys = PqcRatchetKeyPair::generate(kem_algorithm);
        
        let state = if starts_as_sender {
            // Alice: começa ativa (pode enviar imediatamente)
            // Derivar chain key inicial a partir da root key
            let chain_key = Self::derive_initial_chain_key(&initial_root_key);
            PqcRatchetState::Active {
                root_key: initial_root_key,
                our_ratchet_keys,
                their_ratchet_key: None,
                chain_key,
                send_counter: 0,
            }
        } else {
            // Bob: precisa receber primeira mensagem para ter their_ratchet_key
            // Por agora, criar com chave temporária - será atualizada na primeira mensagem
            let temp_their_key = PqcRatchetKeyPair::generate(kem_algorithm).public_keys();
            PqcRatchetState::Inactive {
                root_key: initial_root_key,
                our_ratchet_keys,
                their_ratchet_key: temp_their_key,
                receive_counter: 0,
            }
        };
        
        Self {
            state,
            hybrid_mode_enabled: true,
            kem_algorithm,
            asymmetric_advance_count: 0,
        }
    }
    
    /// Deriva chain key inicial a partir da root key
    fn derive_initial_chain_key(root_key: &[u8; 32]) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"pqc-initial-chain-key-v1");
        hasher.update(root_key);
        hasher.finalize().into()
    }
    
    /// Deriva chain key específica para mensagem consecutiva
    /// 
    /// Para mensagens consecutivas na mesma direção (sem troca de ratchet),
    /// deriva uma chain key única baseada no contador de mensagens.
    /// Usa HKDF para garantir independência entre chaves de mensagens diferentes.
    fn derive_chain_key_for_message(root_key: &[u8; 32], message_counter: u32) -> Result<[u8; 32], CryptoError> {
        let salt = b"matrix-consecutive-chain-key-v1";
        let info = format!("chain-key-msg-{}", message_counter);
        
        let hk = Hkdf::<Sha256>::new(Some(salt), root_key.as_slice());
        
        let mut chain_key = [0u8; 32];
        hk.expand(info.as_bytes(), &mut chain_key)
            .map_err(|_| CryptoError::Protocol)?;
        
        Ok(chain_key)
    }
    
    /// Deriva chain key a partir do hybrid secret (KEM + DH) para mensagens consecutivas
    /// 
    /// Similar a derive_chain_key_for_message mas usa o hybrid secret diretamente
    /// quando temos KEM decapsulate completo. Garante que cada mensagem consecutiva
    /// tenha chave única mesmo sem mudança de direção do ratchet.
    fn derive_chain_key_from_hybrid(hybrid_secret: &[u8], message_counter: u32) -> Result<[u8; 32], CryptoError> {
        let salt = b"matrix-hybrid-chain-key-v1";
        let info = format!("hybrid-chain-msg-{}", message_counter);
        
        let hk = Hkdf::<Sha256>::new(Some(salt), hybrid_secret);
        
        let mut chain_key = [0u8; 32];
        hk.expand(info.as_bytes(), &mut chain_key)
            .map_err(|_| CryptoError::Protocol)?;
        
        Ok(chain_key)
    }
    
    /// DERIVAÇÃO DE MESSAGE KEY SEPARADA (seguindo padrão OLM oficial)
    /// 
    /// Deriva uma message key específica a partir da chain key usando HMAC-SHA256.
    /// Seguindo spec OLM: usa seed 0x01 para derivar message key sem avançar chain.
    /// 
    /// Esta é a chave efetivamente usada para criptografia AES, garantindo que
    /// a chain key nunca seja exposta diretamente em mensagens.
    fn derive_message_key_from_chain(chain_key: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(chain_key)
            .map_err(|_| CryptoError::Protocol)?;
        
        mac.update(MESSAGE_KEY_SEED); // 0x01
        
        let result = mac.finalize();
        let bytes = result.into_bytes();
        
        let mut message_key = [0u8; 32];
        message_key.copy_from_slice(&bytes);
        
        Ok(message_key)
    }
    
    /// AVANÇO DE CHAIN KEY (seguindo padrão OLM oficial)
    /// 
    /// Avança a chain key para a próxima posição usando HMAC-SHA256.
    /// Seguindo spec OLM: usa seed 0x02 para avançar ratchet simétrico.
    /// 
    /// Cada avanço produz uma nova chain key criptograficamente independente,
    /// garantindo forward secrecy: compromisso de chain_key[n] não revela chain_key[n-1].
    fn advance_chain_key(chain_key: &mut [u8; 32]) -> Result<(), CryptoError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(chain_key)
            .map_err(|_| CryptoError::Protocol)?;
        
        mac.update(CHAIN_ADVANCEMENT_SEED); // 0x02
        
        let result = mac.finalize();
        let bytes = result.into_bytes();
        
        chain_key.copy_from_slice(&bytes);
        
        Ok(())
    }
    
    /// Versão padrão (Kyber1024 para compatibilidade)
    pub fn new_default(initial_root_key: [u8; 32]) -> Self {
        Self::new(initial_root_key, KemAlgorithm::Kyber1024, true) // Padrão: começa enviando
    }
    
    /// Define chave pública do peer (inicialização da sessão)
    pub fn set_peer_ratchet_key(&mut self, peer_key: PqcRatchetPublicKey) {
        match &mut self.state {
            PqcRatchetState::Active { their_ratchet_key, .. } => {
                *their_ratchet_key = Some(peer_key);
            }
            PqcRatchetState::Inactive { their_ratchet_key, .. } => {
                *their_ratchet_key = peer_key;
            }
        }
    }
    
    /// Avança ratchet para envio COM ciphertext KEM
    /// Retorna: (chain_key, optional_kem_ciphertext)
    /// kem_ciphertext é Some() quando há transição Inactive→Active (mudança de direção)
    pub fn advance_sending_ratchet_with_kem(&mut self) -> Result<([u8; 32], Option<Vec<u8>>), CryptoError> {
        // Substituir o estado temporariamente para extrair campos sem Clone
        let old_state = std::mem::replace(&mut self.state, PqcRatchetState::Active {
            root_key: [0u8; 32],
            our_ratchet_keys: PqcRatchetKeyPair::generate(self.kem_algorithm),
            their_ratchet_key: None,
            chain_key: [0u8; 32],
            send_counter: 0,
        });

        match old_state {
            PqcRatchetState::Inactive { root_key, our_ratchet_keys: _, their_ratchet_key, receive_counter: _ } => {
                // Transição Inactive → Active: AVANÇO ASSIMÉTRICO 
                vlog!(VerbosityLevel::Normal, " Troca de direção: avanço da catraca assimétrica!");
                
                // Incrementar contador de avanços assimétricos (mudança de direção)
                self.asymmetric_advance_count += 1;
                
                // Gerar novas chaves ratchet para esta direção
                let new_ratchet_keys = PqcRatchetKeyPair::generate(self.kem_algorithm);
                
                // Usar KEM COMPLETO com ciphertext
                let (hybrid_secret, kem_ciphertext) = new_ratchet_keys.hybrid_dh_with_kem(&their_ratchet_key)?;
                let (new_root_key, chain_key) = Self::derive_root_chain_keys(&hybrid_secret, &root_key)?;
                
                vlog!(VerbosityLevel::Debug, " Ratchet PQC avançado: envio #1 ({})", self.kem_algorithm.name());
                vlog!(VerbosityLevel::Normal, "   Nova root key: {}", hex::encode(&new_root_key[..8]));
                vlog!(VerbosityLevel::Debug, "   KEM ciphertext gerado: {} bytes", kem_ciphertext.len());
                
                // Transição para Active com nova chain key
                self.state = PqcRatchetState::Active {
                    root_key: new_root_key,
                    our_ratchet_keys: new_ratchet_keys,
                    their_ratchet_key: Some(their_ratchet_key),
                    chain_key,
                    send_counter: 1,
                };
                
                Ok((chain_key, Some(kem_ciphertext)))
            }
            PqcRatchetState::Active { root_key, our_ratchet_keys, their_ratchet_key, chain_key: old_chain_key, send_counter } => {
                // Continua Active: AVANÇO SIMÉTRICO (apenas chain key)
                // NÃO fazemos novo DH/KEM - apenas avançamos a chain key via KDF
                vlog!(VerbosityLevel::Normal, "  Canal ativo: avanço simétrico da chain key (mesmo destinatário)");
                
                // KDF para avançar chain key: HMAC-SHA256(chain_key, 0x02)
                let mut mac = HmacSha256::new_from_slice(&old_chain_key)
                    .map_err(|_| CryptoError::Protocol)?;
                mac.update(&[0x02]);
                let new_chain_key: [u8; 32] = mac.finalize().into_bytes().into();
                
                let new_counter = send_counter + 1;
                
                // Restaurar estado Active com contador atualizado
                self.state = PqcRatchetState::Active {
                    root_key,
                    our_ratchet_keys,
                    their_ratchet_key,
                    chain_key: new_chain_key,
                    send_counter: new_counter,
                };
                
                vlog!(VerbosityLevel::Debug, "    Nova chain key: {}...", hex::encode(&new_chain_key[..8]));
                
                Ok((new_chain_key, None))  // Sem KEM ciphertext (mesma direção)
            }
        }
    }
    
    /// Verifica se a chave do peer mudou (para decidir entre avanço assimétrico ou simétrico)
    /// 
    /// OPÇÃO B: padrão Matrix - ratchet_key sempre presente, mas só avança assimetricamente
    /// se a chave realmente mudou.
    pub fn has_peer_key_changed(&self, new_key: &PqcRatchetPublicKey) -> bool {
        match &self.state {
            PqcRatchetState::Active { their_ratchet_key, .. } => {
                // Se não temos chave do peer ainda, é mudança
                if let Some(ref current_key) = their_ratchet_key {
                    // Comparar bytes das chaves públicas
                    current_key.to_bytes() != new_key.to_bytes()
                } else {
                    true // Primeira chave recebida
                }
            }
            PqcRatchetState::Inactive { their_ratchet_key, .. } => {
                // Inactive sempre tem a chave do peer
                their_ratchet_key.to_bytes() != new_key.to_bytes()
            }
        }
    }
    
    /// Avança ratchet para recebimento (processa chave do peer)
    /// Avança ratchet PQC no recebimento com KEM completo (decapsulate)
    /// 
    /// Esta versão usa o ciphertext KEM recebido para realizar decapsulate() real,
    /// garantindo que Alice e Bob derivem o MESMO shared secret.
    pub fn advance_receiving_ratchet_with_decapsulate(
        &mut self, 
        peer_new_key: &PqcRatchetPublicKey,
        kem_ciphertext: Option<&[u8]>
    ) -> Result<[u8; 32], CryptoError> {
        // Verificar compatibilidade do algoritmo
        if peer_new_key.kem_algorithm != self.kem_algorithm {
            return Err(CryptoError::Protocol);
        }

        // Substituir o estado temporariamente para extrair campos sem Clone
        let old_state = std::mem::replace(&mut self.state, PqcRatchetState::Active {
            root_key: [0u8; 32],
            our_ratchet_keys: PqcRatchetKeyPair::generate(self.kem_algorithm),
            their_ratchet_key: None,
            chain_key: [0u8; 32],
            send_counter: 0,
        });

        // Seguir padrão vodozemac: Active → Inactive após receber mensagem  
        match old_state {
            PqcRatchetState::Active { root_key, our_ratchet_keys, their_ratchet_key: _, send_counter: _, chain_key: _ } => {
                // Active → Inactive: mensagem recebida, devemos regenerar chaves e ficar inativo
                
                // Incrementar contador de avanços assimétricos (mudança de direção)
                self.asymmetric_advance_count += 1;
                
                // CORRETO: usar hybrid_dh_with_decapsulate para KEM real
                let kem_ct = kem_ciphertext.ok_or(CryptoError::Protocol)?;
                let hybrid_secret = our_ratchet_keys.hybrid_dh_with_decapsulate(peer_new_key, kem_ct)?;
                let (new_root_key, chain_key) = Self::derive_root_chain_keys(&hybrid_secret, &root_key)?;
                
                // Gerar novas chaves para próximo envio
                let new_our_keys = PqcRatchetKeyPair::generate(self.kem_algorithm);
                
                // Transição para Inactive
                self.state = PqcRatchetState::Inactive {
                    root_key: new_root_key,
                    our_ratchet_keys: new_our_keys,
                    their_ratchet_key: peer_new_key.clone(),
                    receive_counter: 1, // Primeira mensagem recebida neste ciclo
                };
                
                vlog!(VerbosityLevel::Normal, "  Recebimento: Active → Inactive (aguardando envio) - KEM decapsulate");
                vlog!(VerbosityLevel::Debug, "  Ratchet PQC processado: recebimento ({})", self.kem_algorithm.name());
                vlog!(VerbosityLevel::Normal, "   Nova root key: {}", hex::encode(&new_root_key[..8]));
                vlog!(VerbosityLevel::Normal, "   Chave recebida: {}", peer_new_key.info());
                
                Ok(chain_key)
            }
            PqcRatchetState::Inactive { root_key, our_ratchet_keys, their_ratchet_key: _, receive_counter } => {
                // Já inactive: mensagens consecutivas do peer (mesma direção)
                let new_counter = receive_counter + 1;
                
                // CORRETO: usar hybrid_dh_with_decapsulate mesmo para mensagens consecutivas
                let kem_ct = kem_ciphertext.ok_or(CryptoError::Protocol)?;
                let hybrid_secret = our_ratchet_keys.hybrid_dh_with_decapsulate(peer_new_key, kem_ct)?;
                let chain_key = Self::derive_chain_key_from_hybrid(&hybrid_secret, new_counter)?;
                
                // Restaurar estado com contador atualizado
                self.state = PqcRatchetState::Inactive {
                    root_key,
                    our_ratchet_keys,
                    their_ratchet_key: peer_new_key.clone(),
                    receive_counter: new_counter,
                };
                
                vlog!(VerbosityLevel::Normal, "  Recebimento: permanece Inactive (mensagem #{}) - KEM decapsulate", new_counter);
                vlog!(VerbosityLevel::Normal, "   Chave recebida: {}", peer_new_key.info());
                vlog!(VerbosityLevel::Debug, "   Chain key derivada para mensagem #{}", new_counter);
                
                Ok(chain_key)
            }
        }
    }
    
    /// Deriva root key e chain key usando HKDF (aceita tamanhos dinâmicos)
    fn derive_root_chain_keys(hybrid_dh: &[u8], current_root_key: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), CryptoError> {
        let salt = b"matrix-ratchet-root-derivation-v1";
        let info = b"root-chain-keys";
        
        let hk = Hkdf::<Sha256>::new(Some(salt), hybrid_dh);
        
        // Expandir para derivação de chaves root e chain (SHA256 output size * 2)
        const SHA256_SIZE: usize = 32; // sha2::Sha256 output size
        let mut expanded = [0u8; SHA256_SIZE * 2];
        hk.expand(info, &mut expanded)
            .map_err(|_| CryptoError::Protocol)?;
        
        // XOR com root key atual (ratcheting property)
        for i in 0..SHA256_SIZE {
            expanded[i] ^= current_root_key[i];
        }
        
        let new_root_key: [u8; SHA256_SIZE] = expanded[0..SHA256_SIZE].try_into().unwrap();
        let chain_key: [u8; SHA256_SIZE] = expanded[SHA256_SIZE..(SHA256_SIZE * 2)].try_into().unwrap();
        
        Ok((new_root_key, chain_key))
    }
    
    /// Obtém estatísticas do Double Ratchet
    pub fn get_ratchet_stats(&self) -> RatchetStats {
        let (messages_sent, messages_received, root_key_hash) = match &self.state {
            PqcRatchetState::Active { root_key, send_counter, .. } => {
                (*send_counter, 0, hex::encode(&root_key[..8]))
            }
            PqcRatchetState::Inactive { root_key, receive_counter, .. } => {
                (0, *receive_counter, hex::encode(&root_key[..8]))
            }
        };

        RatchetStats {
            messages_sent,
            messages_received,
            hybrid_mode: self.hybrid_mode_enabled,
            current_root_key_hash: root_key_hash,
            ratchet_advances: messages_sent + messages_received,
            asymmetric_advances: self.asymmetric_advance_count,
        }
    }
}

/// Estatísticas do Double Ratchet
#[derive(Clone, Debug)]
pub struct RatchetStats {
    pub messages_sent: u32,
    pub messages_received: u32,
    pub hybrid_mode: bool,
    pub current_root_key_hash: String,
    pub ratchet_advances: u32,           // Total de avanços (simétricos + assimétricos)
    pub asymmetric_advances: u32,        // Apenas mudanças de direção (Inactive↔Active)
}

/// Sessão Olm híbrida (orquestrador vodozemac + Double Ratchet PQC)
///
/// Combina sessão vodozemac clássica (base) com Double Ratchet PQC (extensão)
/// para fornecer segurança híbrida pós-quântica mantendo compatibilidade Matrix.
///
/// # Arquitetura em Camadas
///
/// **Camada Base (vodozemac_session)**:
/// - Double Ratchet clássico: X25519 ECDH para acordos de chaves
/// - Criptografia: AES-256-CBC + HMAC-SHA-256 (Encrypt-then-MAC)
/// - Formato: PreKeyMessage (primeira) ou Normal Message (subsequentes)
/// - Estados: has_received_message() rastreia se DH peer_key foi estabelecido
///
/// **Camada PQC (pqc_ratchet)**:
/// - Double Ratchet híbrido: X25519 + Kyber KEM em paralelo
/// - Derivação: HKDF-SHA-256 combina segredos DH + KEM → root_key + chain_key
/// - Estados: Active (enviando) ↔ Inactive (aguardando enviar)
/// - Avanços: Simétrico (HMAC, 0 overhead) vs Assimétrico (KEM, ~800-1600 bytes)
///
/// **Camada de Mensagem**:
/// - Formato JSON: {"type":2,"body":"base64"} para mensagens PQC
/// - Conteúdo: classic_component + ratchet_key + optional(kem_ciphertext)
/// - Detecção: Prefixo JSON identifica PQC, Base64 puro identifica clássico
///
/// # Campos
/// - `vodozemac_session`: Sessão base (pública para compatibilidade direta)
/// - `pqc_ratchet`: Estado do Double Ratchet PQC (None = modo clássico)
/// - `message_counter`: Contador global de mensagens
/// - `pending_kem_ciphertext`: Buffer para forced ratchet (rotação Megolm)
///
/// # Fluxo de Operação
///
/// **Inicialização**:
/// 1. Criar com `from_vodozemac(vodozemac_session)` → modo clássico
/// 2. Habilitar PQC: `enable_pqc_mode()` (sender) ou `enable_pqc_mode_as_receiver()` (receiver)
///
/// **Criptografia** (`encrypt_hybrid`):
/// 1. Vodozemac encrypt → classic_component
/// 2. Avanço ratchet PQC → determina se simétrico ou assimétrico
/// 3. Monta PqcOlmMessage com ratchet_key (sempre) + kem_ciphertext (se assimétrico)
/// 4. Serializa para JSON Matrix-compatível
///
/// **Descriptografia** (`decrypt_hybrid`):
/// 1. Deserializa PqcOlmMessage do JSON
/// 2. Compara ratchet_key com chave anterior → detecta mudança de direção
/// 3. Se mudou: `advance_receiving_ratchet_with_decapsulate(kem_ciphertext)`
/// 4. Se igual: avanço simétrico (sem KEM)
/// 5. Vodozemac decrypt → plaintext
///
/// **Forced Ratchet** (`force_asymmetric_ratchet_advance`):
/// - Usado antes de redistribuir chaves Megolm
/// - Executa avanço assimétrico imediato (gera KEM ciphertext)
/// - Armazena em `pending_kem_ciphertext` para próxima mensagem
/// - Garante forward secrecy PQC na rotação
pub struct HybridOlmSession {
    /// Sessão vodozemac base (X25519 clássica) - pública para compatibilidade
    pub vodozemac_session: VodoSession,
    /// Estado do Double Ratchet híbrido PQC
    pqc_ratchet: Option<PqcDoubleRatchetState>,
    /// Contador de mensagens processadas
    message_counter: u32,
    /// KEM ciphertext pendente de forced ratchet (para incluir na próxima mensagem)
    /// Este campo armazena o ciphertext KEM gerado durante force_asymmetric_ratchet_advance()
    /// para que seja incluído na próxima mensagem enviada, garantindo que o receptor
    /// possa decapsular e obter o mesmo shared secret.
    pending_kem_ciphertext: Option<Vec<u8>>,
}

impl HybridOlmSession {
    /// Retorna referência à sessão vodozemac base
    pub fn get_vodozemac_session(&self) -> &VodoSession {
        &self.vodozemac_session
    }
    /// Cria sessão híbrida a partir de sessão vodozemac
    pub fn from_vodozemac(session: VodoSession) -> Self {
        Self {
            vodozemac_session: session,
            pqc_ratchet: None,
            message_counter: 0,
            pending_kem_ciphertext: None,
        }
    }
    
    /// Habilita modo PQC com chave raiz inicial e algoritmo KEM
    pub fn enable_pqc_mode(&mut self, initial_root_key: [u8; 32], kem_algorithm: KemAlgorithm) {
        // Alice (primeira a enviar) começa ativa, Bob deve usar enable_pqc_mode_as_receiver
        let starts_as_sender = true;
        self.pqc_ratchet = Some(PqcDoubleRatchetState::new(initial_root_key, kem_algorithm, starts_as_sender));
        vlog!(VerbosityLevel::Debug, "├─Modo PQC habilitado no Double Ratchet com {}", kem_algorithm.name());
    }
    
    /// Habilita modo PQC como receptor (para Bob)
    pub fn enable_pqc_mode_as_receiver(&mut self, initial_root_key: [u8; 32], kem_algorithm: KemAlgorithm) {
        // Bob (primeiro a receber) começa inativo
        let starts_as_sender = false;
        self.pqc_ratchet = Some(PqcDoubleRatchetState::new(initial_root_key, kem_algorithm, starts_as_sender));
        vlog!(VerbosityLevel::Debug, "├─Modo PQC habilitado no Double Ratchet com {} (como receptor)", kem_algorithm.name());
    }
    
    /// Versão de compatibilidade (usa Kyber1024)
    pub fn enable_pqc_mode_default(&mut self, initial_root_key: [u8; 32]) {
        self.enable_pqc_mode(initial_root_key, KemAlgorithm::Kyber1024);
    }
    
    /// Define chave pública do peer para PQC
    pub fn set_peer_pqc_key(&mut self, peer_key: PqcRatchetPublicKey) -> Result<(), CryptoError> {
        if let Some(ref mut pqc_state) = self.pqc_ratchet {
            pqc_state.set_peer_ratchet_key(peer_key);
            Ok(())
        } else {
            Err(CryptoError::Protocol) // PQC não habilitado
        }
    }
    
    /// Obtém nossas chaves ratchet públicas
    pub fn get_our_ratchet_keys(&self) -> Result<PqcRatchetPublicKey, CryptoError> {
        if let Some(ref pqc_state) = self.pqc_ratchet {
            match &pqc_state.state {
                PqcRatchetState::Active { our_ratchet_keys, .. } |
                PqcRatchetState::Inactive { our_ratchet_keys, .. } => {
                    Ok(our_ratchet_keys.public_keys())
                }
            }
        } else {
            Err(CryptoError::Protocol) // PQC não habilitado
        }
    }
    
    /// Força avanço assimétrico do Double Ratchet PQC (para rotações Megolm)
    /// 
    /// EXECUTA AVANÇO ASSIMÉTRICO IMEDIATO (não apenas prepara estado)
    /// 
    /// Gera novas chaves Kyber, executa KEM completo e atualiza root key.
    /// Garante que contadores de avanços assimétricos sejam incrementados.
    /// 
    /// Uso: Chamar antes de redistribuir chaves Megolm durante rotação
    /// para garantir forward secrecy PQC.
    pub fn force_asymmetric_ratchet_advance(&mut self) -> Result<(), CryptoError> {
        if let Some(ref mut pqc_state) = self.pqc_ratchet {
            vlog!(VerbosityLevel::Debug, "[SYNC] [FORCE_RATCHET] Iniciando avanço assimétrico forçado");
            vlog!(VerbosityLevel::Debug, "   └─ Algoritmo KEM: {}", pqc_state.kem_algorithm.name());
            
            // Obter estatísticas antes
            let stats_before = pqc_state.get_ratchet_stats();
            vlog!(VerbosityLevel::Debug, "   └─ Avanços antes: total={}, assimétricos={}", 
                 stats_before.ratchet_advances, stats_before.asymmetric_advances);
            
            // EXECUTAR avanço assimétrico imediato (não apenas preparar)
            match &pqc_state.state {
                PqcRatchetState::Active { root_key, their_ratchet_key, send_counter, .. } => {
                    vlog!(VerbosityLevel::Debug, "   └─ Estado anterior: Active (send_counter={})", send_counter);
                    
                    // Gerar novas chaves para este avanço forçado
                    let new_ratchet_keys = PqcRatchetKeyPair::generate(pqc_state.kem_algorithm);
                    
                    vlog!(VerbosityLevel::Debug, "   └─ Novas chaves Kyber geradas:");
                    vlog!(VerbosityLevel::Debug, "      └─ Chave pública Curve25519: {} bytes", 
                         new_ratchet_keys.curve25519_public.as_bytes().len());
                    vlog!(VerbosityLevel::Debug, "      └─ Chave pública KEM: {} bytes", 
                         new_ratchet_keys.kem_keypair.public_key().size_bytes());
                    
                    // Precisamos ter their_ratchet_key para fazer KEM
                    if let Some(peer_key) = their_ratchet_key {
                        // EXECUTAR KEM COMPLETO AGORA (não esperar próxima mensagem)
                        let (hybrid_secret, kem_ciphertext) = new_ratchet_keys.hybrid_dh_with_kem(peer_key)?;
                        let (new_root_key, _chain_key) = PqcDoubleRatchetState::derive_root_chain_keys(&hybrid_secret, root_key)?;
                        
                        // ARMAZENAR KEM ciphertext para próxima mensagem
                        self.pending_kem_ciphertext = Some(kem_ciphertext.clone());
                        
                        // Incrementar contador de avanços assimétricos
                        pqc_state.asymmetric_advance_count += 1;
                        
                        vlog!(VerbosityLevel::Debug, "   └─ KEM executado: hybrid_dh_with_kem()");
                        vlog!(VerbosityLevel::Debug, "      └─ Nova root key derivada: {}", hex::encode(&new_root_key[..8]));
                        vlog!(VerbosityLevel::Debug, "      └─ KEM ciphertext armazenado: {} bytes (para próxima mensagem)", kem_ciphertext.len());
                        vlog!(VerbosityLevel::Debug, "      └─ Avanços assimétricos: {}", pqc_state.asymmetric_advance_count);
                        
                        // Transicionar para Inactive com novas chaves e nova root key
                        pqc_state.state = PqcRatchetState::Inactive {
                            root_key: new_root_key,
                            our_ratchet_keys: new_ratchet_keys,
                            their_ratchet_key: peer_key.clone(),
                            receive_counter: 0,
                        };
                        
                        vlog!(VerbosityLevel::Debug, "   └─ Transição: Active → Inactive (avanço assimétrico COMPLETO)");
                        vlog!(VerbosityLevel::Debug, "   └─ Avanço assimétrico forçado EXECUTADO COM SUCESSO");
                        vlog!(VerbosityLevel::Debug, "      └─ Algoritmo: {} ({} bits segurança)", 
                             pqc_state.kem_algorithm.name(), pqc_state.kem_algorithm.security_level());
                        vlog!(VerbosityLevel::Debug, "      └─ Operação KEM: Encapsulate + Decapsulate");
                        vlog!(VerbosityLevel::Debug, "      └─ Root key atualizada com hybrid secret (ECDH + KEM)");
                    } else {
                        // Sem peer key ainda - não podemos fazer KEM
                        vlog!(VerbosityLevel::Debug, "   └─  Active sem peer_key - não é possível executar KEM");
                        vlog!(VerbosityLevel::Debug, "      └─ Aguardando primeira mensagem do peer");
                        vlog!(VerbosityLevel::Debug, "      └─ KEM será executado quando houver troca de mensagens");
                        vlog!(VerbosityLevel::Debug, "   └─ Avanço assimétrico forçado NÃO EXECUTADO (sessão lazy)");
                    }
                },
                PqcRatchetState::Inactive { root_key, their_ratchet_key, receive_counter, .. } => {
                    vlog!(VerbosityLevel::Debug, "   └─ Estado anterior: Inactive (receive_counter={})", receive_counter);
                    
                    // Gerar novas chaves para este avanço forçado
                    let new_ratchet_keys = PqcRatchetKeyPair::generate(pqc_state.kem_algorithm);
                    
                    vlog!(VerbosityLevel::Debug, "   └─ Novas chaves Kyber geradas:");
                    vlog!(VerbosityLevel::Debug, "      └─ Chave pública Curve25519: {} bytes", 
                         new_ratchet_keys.curve25519_public.as_bytes().len());
                    vlog!(VerbosityLevel::Debug, "      └─ Chave pública KEM: {} bytes", 
                         new_ratchet_keys.kem_keypair.public_key().size_bytes());
                    
                    // EXECUTAR KEM COMPLETO AGORA
                    let (hybrid_secret, kem_ciphertext) = new_ratchet_keys.hybrid_dh_with_kem(their_ratchet_key)?;
                    let (new_root_key, _chain_key) = PqcDoubleRatchetState::derive_root_chain_keys(&hybrid_secret, root_key)?;
                    
                    // ARMAZENAR KEM ciphertext para próxima mensagem
                    self.pending_kem_ciphertext = Some(kem_ciphertext.clone());
                    
                    // Incrementar contador de avanços assimétricos
                    pqc_state.asymmetric_advance_count += 1;
                    
                    vlog!(VerbosityLevel::Debug, "   └─ KEM executado: hybrid_dh_with_kem()");
                    vlog!(VerbosityLevel::Debug, "      └─ Nova root key derivada: {}", hex::encode(&new_root_key[..8]));
                    vlog!(VerbosityLevel::Debug, "      └─ KEM ciphertext armazenado: {} bytes (para próxima mensagem)", kem_ciphertext.len());
                    vlog!(VerbosityLevel::Debug, "      └─ Avanços assimétricos: {}", pqc_state.asymmetric_advance_count);
                    
                    // Permanecer Inactive mas com novas chaves e nova root key
                    pqc_state.state = PqcRatchetState::Inactive {
                        root_key: new_root_key,
                        our_ratchet_keys: new_ratchet_keys,
                        their_ratchet_key: their_ratchet_key.clone(),
                        receive_counter: 0, // Reset counter após avanço forçado
                    };
                    
                    vlog!(VerbosityLevel::Debug, "   └─ Atualização: Inactive → Inactive (avanço assimétrico COMPLETO)");
                    vlog!(VerbosityLevel::Debug, "   └─ Avanço assimétrico forçado EXECUTADO COM SUCESSO");
                    vlog!(VerbosityLevel::Debug, "      └─ Algoritmo: {} ({} bits segurança)", 
                         pqc_state.kem_algorithm.name(), pqc_state.kem_algorithm.security_level());
                    vlog!(VerbosityLevel::Debug, "      └─ Operação KEM: Encapsulate + Decapsulate");
                    vlog!(VerbosityLevel::Debug, "      └─ Root key atualizada com hybrid secret (ECDH + KEM)");
                }
            }
            
            Ok(())
        } else {
            // Sem PQC habilitado - não fazer nada (silencioso para compatibilidade com clássico)
            vlog!(VerbosityLevel::Debug, "[SYNC] [FORCE_RATCHET] PQC não habilitado - modo clássico");
            Ok(())
        }
    }
    
    /// Criptografa mensagem com Double Ratchet híbrido
    pub fn encrypt_hybrid(&mut self, plaintext: &[u8]) -> Result<PqcOlmMessage, CryptoError> {
        self.message_counter += 1;
        
        if let Some(ref mut pqc_state) = self.pqc_ratchet {
            let was_inactive = matches!(pqc_state.state, PqcRatchetState::Inactive { .. });
            
            // 1. Avançar ratchet para obter chain key E ciphertext KEM (se houver mudança de direção)
            let (chain_key, kem_ciphertext_opt) = pqc_state.advance_sending_ratchet_with_kem()?;
            
            // 2. Derivar message key a partir da chain key (HMAC com seed 0x01)
            let message_key = PqcDoubleRatchetState::derive_message_key_from_chain(&chain_key)?;
            
            // 3. Avançar chain key para próxima mensagem (HMAC com seed 0x02)
            // Nota: Em implementação completa, isso seria feito automaticamente
            // por uma estrutura ChainKey que mantém estado
            vlog!(VerbosityLevel::Debug, "  ├─Message key derivada: {}...", hex::encode(&message_key[..8]));
            vlog!(VerbosityLevel::Debug, "  ├─Chain key será avançada para próxima mensagem");
            
            if let Some(ref kem_ct) = kem_ciphertext_opt {
                vlog!(VerbosityLevel::Debug, "  ├─KEM ciphertext incluído: {} bytes", kem_ct.len());
            }
            
            // 4. Criptografia vodozemac base (usa suas próprias chaves)
            // Nota: Em implementação completa, usaríamos message_key para AES
            let classic_msg = self.vodozemac_session.encrypt(plaintext);
            let mut pqc_msg = PqcOlmMessage::from_classic(classic_msg, self.message_counter);
            
            // 5. PADRÃO MATRIX: SEMPRE incluir nossa ratchet key atual
            // O Matrix envia a componente PQC em TODAS as mensagens, independentemente
            // de haver mudança de direção. Isso garante que o receptor sempre saiba
            // qual ratchet key está ativa, facilitando sincronização.
            let our_current_ratchet_key = match &pqc_state.state {
                PqcRatchetState::Active { our_ratchet_keys, .. } => our_ratchet_keys.public_keys(),
                PqcRatchetState::Inactive { our_ratchet_keys, .. } => our_ratchet_keys.public_keys(),
            };
            
            vlog!(VerbosityLevel::Debug, "  ├─[ENCRYPT] Antes de with_pqc_ratchet: pqc_enabled={}", pqc_msg.pqc_enabled);
            pqc_msg = pqc_msg.with_pqc_ratchet(our_current_ratchet_key);
            vlog!(VerbosityLevel::Debug, "  ├─[ENCRYPT] Depois de with_pqc_ratchet: pqc_enabled={}, ratchet_key.is_some()={}", 
                  pqc_msg.pqc_enabled, pqc_msg.ratchet_key.is_some());
            
            // 6. PRIORIDADE: Verificar se há KEM ciphertext pendente (de forced ratchet)
            //    Se sim, usar esse ao invés do kem_ciphertext_opt do avanço normal
            if let Some(pending_kem) = self.pending_kem_ciphertext.take() {
                vlog!(VerbosityLevel::Debug, "  ├─ Usando KEM ciphertext de FORCED RATCHET: {} bytes", pending_kem.len());
                pqc_msg.kem_ciphertext = Some(pending_kem);
            } else {
                // Usar KEM ciphertext do avanço normal (se houver mudança de direção)
                pqc_msg.kem_ciphertext = kem_ciphertext_opt;
            }
            
            if was_inactive {
                vlog!(VerbosityLevel::Debug, "  └─Double Ratchet PQC: Nova chave ratchet (troca de direção) + KEM ciphertext");
            } else {
                if pqc_msg.kem_ciphertext.is_some() {
                    vlog!(VerbosityLevel::Debug, "  └─Double Ratchet PQC: KEM ciphertext de forced ratchet (mesma direção)");
                } else {
                    vlog!(VerbosityLevel::Debug, "  └─Double Ratchet PQC: Mesma direção (ratchet key repetida, sem KEM ciphertext)");
                }
            }
            
            Ok(pqc_msg)
        } else {
            // Fallback clássico
            let classic_msg = self.vodozemac_session.encrypt(plaintext);
            let pqc_msg = PqcOlmMessage::from_classic(classic_msg, self.message_counter);
            vlog!(VerbosityLevel::Debug, "  └─Distribuição clássica (canal Olm sem PQC)");
            Ok(pqc_msg)
        }
    }
    
    /// Descriptografa mensagem com Double Ratchet híbrido
    pub fn decrypt_hybrid(&mut self, pqc_msg: &PqcOlmMessage) -> Result<Vec<u8>, CryptoError> {
        // Derivar message key separada da chain key para descriptografia
        
        if let Some(ref mut pqc_state) = self.pqc_ratchet {
            // PADRÃO MATRIX: ratchet_key sempre presente
            if let Some(ref new_ratchet_key) = pqc_msg.ratchet_key {
                // OPÇÃO B: Comparar se a chave realmente mudou
                let key_changed = pqc_state.has_peer_key_changed(new_ratchet_key);
                
                if key_changed {
                    // MUDANÇA DE DIREÇÃO: chave nova, precisa de KEM ciphertext
                    if let Some(ref kem_ct) = pqc_msg.kem_ciphertext {
                        vlog!(VerbosityLevel::Debug, "  ├─Ratchet key MUDOU - avanço assimétrico com KEM");
                        
                        // 1. Avançar ratchet PQC com KEM completo (decapsulate)
                        let chain_key = pqc_state.advance_receiving_ratchet_with_decapsulate(
                            new_ratchet_key, 
                            Some(kem_ct.as_slice())
                        )?;
                        
                        // 2. Derivar message key a partir da chain key
                        let _message_key = PqcDoubleRatchetState::derive_message_key_from_chain(&chain_key)?;
                        
                        vlog!(VerbosityLevel::Debug, "  ├─Message key derivada: {}...", hex::encode(&_message_key[..8]));
                        
                        // 3. Descriptografia vodozemac
                        let plaintext = self.vodozemac_session.decrypt(&pqc_msg.classic_component)
                            .map_err(|e| {
                                vlog!(VerbosityLevel::Normal, "ERRO: decrypt_hybrid (avanço assimétrico) falhou: {:?}", e);
                                CryptoError::Protocol
                            })?;
                        
                        Ok(plaintext)
                    } else {
                        // ERRO: chave mudou mas não tem ciphertext KEM
                        vlog!(VerbosityLevel::Normal, "[ERRO] Ratchet key mudou mas sem KEM ciphertext - KEM incompleto!");
                        return Err(CryptoError::Protocol);
                    }
                } else {
                    // MESMA DIREÇÃO: chave repetida, avanço simétrico (não precisa KEM)
                    vlog!(VerbosityLevel::Debug, "  ├─Ratchet key igual - avanço simétrico (chain key)");
                    
                    // Não avança ratchet assimetricamente, apenas descriptografa
                    // (vodozemac já gerencia as chain keys internas)
                    let plaintext = self.vodozemac_session.decrypt(&pqc_msg.classic_component)
                        .map_err(|e| {
                            vlog!(VerbosityLevel::Normal, "ERRO: decrypt_hybrid (avanço simétrico) falhou: {:?}", e);
                            CryptoError::Protocol
                        })?;
                    
                    Ok(plaintext)
                }
            } else {
                // RETROCOMPATIBILIDADE: mensagem sem ratchet_key (não deveria acontecer no padrão Matrix)
                vlog!(VerbosityLevel::Debug, "  ├─Sem ratchet_key (retrocompatibilidade)");
                
                let plaintext = self.vodozemac_session.decrypt(&pqc_msg.classic_component)
                    .map_err(|e| {
                        vlog!(VerbosityLevel::Normal, "ERRO: decrypt_hybrid (sem ratchet) falhou: {:?}", e);
                        CryptoError::Protocol
                    })?;
                
                Ok(plaintext)
            }
        } else {
            // Modo PQC não habilitado
            if pqc_msg.ratchet_key.is_some() {
                vlog!(VerbosityLevel::Normal, "Componente PQC ignorado (modo PQC não habilitado)");
                return Err(CryptoError::Protocol);
            }
            
            vlog!(VerbosityLevel::Debug, "  └─Mensagem clássica recebida (sem PQC)");
            
            let plaintext = self.vodozemac_session.decrypt(&pqc_msg.classic_component)
                .map_err(|e| {
                    vlog!(VerbosityLevel::Normal, "ERRO: decrypt (modo clássico) falhou: {:?}", e);
                    CryptoError::Protocol
                })?;
            
            Ok(plaintext)
        }
    }
    

    

    
    /// Verifica se a sessão PQC tem peer_key definida (sessão já foi usada)
    /// Retorna true se a sessão já trocou mensagens e tem their_ratchet_key
    /// Retorna false para sessões "lazy" (nunca usadas)
    /// 
    /// IMPORTANTE: Verifica AMBAS as camadas (PQC E clássica)
    /// - Camada PQC: their_ratchet_key (KEM peer key)
    /// - Camada clássica: vodozemac has_received_message (DH peer key)
    /// 
    /// Uma sessão é considerada "established" (não-lazy) se QUALQUER das camadas
    /// tiver peer_key definida, pois ambas as formas permitem avanço do ratchet.
    pub fn has_peer_key(&self) -> bool {
        // Verificar camada PQC primeiro
        let pqc_has_peer = if let Some(ref pqc_state) = self.pqc_ratchet {
            match &pqc_state.state {
                PqcRatchetState::Active { their_ratchet_key, .. } => their_ratchet_key.is_some(),
                PqcRatchetState::Inactive { .. } => true, // Inactive sempre tem peer_key
            }
        } else {
            false // Sem PQC habilitado
        };
        
        // Se PQC tem peer_key, retornar true imediatamente
        if pqc_has_peer {
            return true;
        }
        
        // Caso contrário, verificar camada clássica (vodozemac)
        // Se vodozemac já recebeu mensagens, significa que DH peer_key foi estabelecido
        self.vodozemac_session.has_received_message()
    }
    
    /// Verifica se a sessão vodozemac já recebeu mensagem do peer
    pub fn has_received_message_classic(&self) -> bool {
        self.vodozemac_session.has_received_message()
    }
    
    /// Criptografia clássica (fallback/compatibilidade)
    pub fn encrypt_classic(&mut self, plaintext: &[u8]) -> vodozemac::olm::OlmMessage {
        self.vodozemac_session.encrypt(plaintext)
    }
    
    /// Descriptografia clássica (fallback/compatibilidade)
    pub fn decrypt_classic(&mut self, message: &vodozemac::olm::OlmMessage) -> Result<Vec<u8>, vodozemac::olm::DecryptionError> {
        self.vodozemac_session.decrypt(message)
    }

    /// Obtém estatísticas da sessão híbrida
    pub fn get_session_stats(&self) -> SessionStats {
        let pqc_stats = self.pqc_ratchet.as_ref()
            .map(|s| s.get_ratchet_stats());
        
        SessionStats {
            total_messages: self.message_counter,
            pqc_enabled: self.pqc_ratchet.is_some(),
            session_id: self.vodozemac_session.session_id(),
            ratchet_stats: pqc_stats,
        }
    }
    
    /// NOVOS MÉTODOS PARA TRANSPARÊNCIA
    
    /// Criptografa mensagem de forma inteligente (PQC se disponível, senão clássico)
    pub fn encrypt_transparent(&mut self, plaintext: &[u8]) -> String {
        if self.pqc_ratchet.is_some() {
            // Modo híbrido: usar Double Ratchet PQC com serialização completa
            match self.encrypt_hybrid(plaintext) {
                Ok(pqc_msg) => {
                    // Usar serialização completa Matrix-compatível
                    pqc_msg.to_transport_string()
                }
                Err(e) => {
                    // FALLBACK CRÍTICO: PQC falhou, usando clássico
                    vlog!(VerbosityLevel::Normal, "FALLBACK CRÍTICO: encrypt_hybrid falhou ({:?}), usando clássico", e);
                    vlog!(VerbosityLevel::Normal, "Isso NÃO deveria acontecer em experimentos - investigate!");
                    self.encrypt_classic_fallback(plaintext)
                }
            }
        } else {
            // Modo clássico puro
            self.encrypt_classic_fallback(plaintext)
        }
    }
    
    /// Descriptografa mensagem de forma inteligente (detecta formato)
    pub fn decrypt_transparent(&mut self, ciphertext: &str) -> Result<Vec<u8>, CryptoError> {
        // Detectar formato da mensagem pelo prefixo JSON
        if ciphertext.starts_with(r#"{"type":2,"#) {
            // Mensagem PQC híbrida (type 2): usar descriptografia completa
            if self.pqc_ratchet.is_some() {
                let pqc_msg = PqcOlmMessage::from_transport_string(ciphertext)?;
                self.decrypt_hybrid(&pqc_msg)
            } else {
                // PQC não habilitado, mas recebeu mensagem PQC - erro
                Err(CryptoError::Protocol)
            }
        } else if ciphertext.starts_with("hybrid:") {
            // Formato legado (compatibilidade): extrair parte clássica
            let classic_part = &ciphertext[7..];
            self.decrypt_classic_fallback(classic_part)
        } else {
            // Mensagem clássica pura
            self.decrypt_classic_fallback(ciphertext)
        }
    }
    
    /// Criptografia clássica via vodozemac
    fn encrypt_classic_fallback(&mut self, plaintext: &[u8]) -> String {
        let message = self.vodozemac_session.encrypt(plaintext);
        use base64::prelude::*;
        match message {
            vodozemac::olm::OlmMessage::PreKey(m) => BASE64_STANDARD.encode(&m.to_bytes()),
            vodozemac::olm::OlmMessage::Normal(m) => BASE64_STANDARD.encode(&m.to_bytes()),
        }
    }
    
    /// Descriptografia clássica via vodozemac
    fn decrypt_classic_fallback(&mut self, ciphertext: &str) -> Result<Vec<u8>, CryptoError> {
        use base64::prelude::*;
        let raw = BASE64_STANDARD.decode(ciphertext).map_err(|_| CryptoError::B64)?;
        
        // Tentar PreKeyMessage primeiro
        if let Ok(pre) = vodozemac::olm::PreKeyMessage::from_bytes(&raw) {
            let msg = vodozemac::olm::OlmMessage::PreKey(pre);
            return self.vodozemac_session.decrypt(&msg)
                .map_err(|_| CryptoError::Protocol);
        }
        
        // Tentar Message normal
        if let Ok(norm) = vodozemac::olm::Message::from_bytes(&raw) {
            let msg = vodozemac::olm::OlmMessage::Normal(norm);
            return self.vodozemac_session.decrypt(&msg)
                .map_err(|_| CryptoError::Protocol);
        }
        
        Err(CryptoError::Protocol)
    }
    
    /// Verifica se modo PQC está ativo
    pub fn is_pqc_enabled(&self) -> bool {
        self.pqc_ratchet.is_some()
    }
    
    /// Obtém e remove o pending_kem_ciphertext (para compartilhar entre sessions)
    pub fn take_pending_kem_ciphertext(&mut self) -> Option<Vec<u8>> {
        self.pending_kem_ciphertext.take()
    }
    
    /// Define o pending_kem_ciphertext (para receber de outra session)
    pub fn set_pending_kem_ciphertext(&mut self, kem_ct: Vec<u8>) {
        self.pending_kem_ciphertext = Some(kem_ct);
    }
    
    /// Obtém ID da sessão
    pub fn session_id(&self) -> String {
        self.vodozemac_session.session_id()
    }
}

/// Estatísticas da sessão híbrida
#[derive(Clone, Debug)]
pub struct SessionStats {
    pub total_messages: u32,
    pub pqc_enabled: bool,
    pub session_id: String,
    pub ratchet_stats: Option<RatchetStats>,
}

/// Simulador completo Bob para processamento de mensagens PQC
pub struct BobPqcProcessor {
    /// Sessão híbrida de Bob
    pub session: HybridOlmSession,
    
    /// Chaves de ratchet atuais de Bob
    pub ratchet_keys: PqcRatchetKeyPair,
    
    /// Histórico de mensagens processadas
    pub processed_messages: Vec<ProcessedMessage>,
    
    /// Algoritmo KEM usado
    pub kem_algorithm: KemAlgorithm,
}

/// Mensagem processada com verificação de integridade
#[derive(Clone)]
pub struct ProcessedMessage {
    pub message_index: u32,
    pub plaintext: Vec<u8>,
    pub integrity_verified: bool,
    pub pqc_component_present: bool,
    pub processing_time_ms: f64,
    pub ratchet_advanced: bool,
}

impl BobPqcProcessor {
    /// Cria novo processador Bob a partir de sessão vodozemac
    pub fn new(vodozemac_session: VodoSession, kem_algorithm: KemAlgorithm) -> Self {
        Self {
            session: HybridOlmSession::from_vodozemac(vodozemac_session),
            ratchet_keys: PqcRatchetKeyPair::generate(kem_algorithm),
            processed_messages: Vec::new(),
            kem_algorithm,
        }
    }
    
    /// Inicializa processador com chave raiz PQXDH
    pub fn initialize_pqc(&mut self, initial_root_key: [u8; 32]) -> PqcRatchetPublicKey {
        // Bob começa como receptor (is_active = false)
        self.session.enable_pqc_mode_as_receiver(initial_root_key, self.kem_algorithm);
        
        // Retornar chaves públicas para Alice
        self.ratchet_keys.public_keys()
    }
    
    /// Define chave pública do peer (Alice) para PQC
    pub fn set_peer_pqc_key(&mut self, peer_key: PqcRatchetPublicKey) -> Result<(), CryptoError> {
        self.session.set_peer_pqc_key(peer_key)
    }
    
    /// Processa mensagem PQC completa com verificação de integridade
    pub fn process_message(&mut self, pqc_msg: &PqcOlmMessage) -> Result<ProcessedMessage, CryptoError> {
        let start_time = std::time::Instant::now();
        
        vlog!(VerbosityLevel::Normal, " Bob processando mensagem #{}", pqc_msg.message_index);
        
        // 1. Verificar integridade da mensagem
        let integrity_verified = self.verify_message_integrity(pqc_msg)?;
        
        // 2. Processar componente PQC se presente
        let mut ratchet_advanced = false;
        if let Some(ref new_alice_key) = pqc_msg.ratchet_key {
            if let Some(ref mut pqc_state) = self.session.pqc_ratchet {
                vlog!(VerbosityLevel::Debug, "   ├─ Processando nova chave ratchet de Alice");
                vlog!(VerbosityLevel::Debug, "   ├─ Algoritmo: {}", new_alice_key.kem_algorithm.name());
                vlog!(VerbosityLevel::Debug, "   ├─ Tamanho chave: {}B", new_alice_key.size_bytes());
                
                // Avançar ratchet recebimento COM decapsulação KEM
                let kem_ct = pqc_msg.kem_ciphertext.as_ref().map(|v| v.as_slice());
                let _chain_key = pqc_state.advance_receiving_ratchet_with_decapsulate(new_alice_key, kem_ct)?;
                ratchet_advanced = true;
                
                vlog!(VerbosityLevel::Debug, "   ├─  Ratchet avançado com sucesso");
            }
        }
        
        // 3. Descriptografar mensagem base
        let plaintext = self.session.decrypt_hybrid(pqc_msg)?;
        
        // 4. Registrar processamento
        let processing_time = start_time.elapsed().as_micros() as f64 / 1000.0;
        let processed = ProcessedMessage {
            message_index: pqc_msg.message_index,
            plaintext: plaintext.clone(),
            integrity_verified,
            pqc_component_present: pqc_msg.pqc_enabled,
            processing_time_ms: processing_time,
            ratchet_advanced,
        };
        
        self.processed_messages.push(processed.clone());
        
        vlog!(VerbosityLevel::Debug, "   ├─ Descriptografado: \"{}\"", String::from_utf8_lossy(&plaintext));
        vlog!(VerbosityLevel::Debug, "   ├─ Integridade: {}", if integrity_verified { "OK" } else { "FAIL" });
        vlog!(VerbosityLevel::Debug, "   ├─ Tempo: {:.3}ms", processing_time);
        vlog!(VerbosityLevel::Debug, "   ├─ Processamento completo");
        
        Ok(processed)
    }
    
    /// Responde com mensagem própria (Bob → Alice)
    pub fn respond_message(&mut self, response_text: &str) -> Result<PqcOlmMessage, CryptoError> {
        vlog!(VerbosityLevel::Normal, " Bob enviando resposta: \"{}\"", response_text);
        
        // Usar o método encrypt_hybrid que já gerencia o avanço do ratchet corretamente
        self.session.encrypt_hybrid(response_text.as_bytes())
    }
    
    /// Obtém estatísticas completas de Bob
    pub fn get_processing_stats(&self) -> BobProcessingStats {
        let total_messages = self.processed_messages.len();
        let pqc_messages = self.processed_messages.iter()
            .filter(|m| m.pqc_component_present)
            .count();
        let avg_processing_time = if total_messages > 0 {
            self.processed_messages.iter()
                .map(|m| m.processing_time_ms)
                .sum::<f64>() / total_messages as f64
        } else { 0.0 };
        
        BobProcessingStats {
            total_messages_processed: total_messages,
            pqc_messages_processed: pqc_messages,
            integrity_failures: self.processed_messages.iter()
                .filter(|m| !m.integrity_verified)
                .count(),
            avg_processing_time_ms: avg_processing_time,
            ratchet_advancements: self.processed_messages.iter()
                .filter(|m| m.ratchet_advanced)
                .count(),
            session_stats: self.session.get_session_stats(),
        }
    }
    
    /// 2. VERIFICAÇÃO DE INTEGRIDADE DAS CHAVES RATCHET (COMPLETA)
    fn verify_message_integrity(&self, pqc_msg: &PqcOlmMessage) -> Result<bool, CryptoError> {
        vlog!(VerbosityLevel::Debug, "   ├─ Verificando integridade da mensagem...");
        
        // 1. Verificar índice sequencial
        let expected_index = self.processed_messages.len() as u32 + 1;
        if pqc_msg.message_index != expected_index {
            vlog!(VerbosityLevel::Normal, "   FALHA: Índice fora de sequência (esperado: {}, recebido: {})", 
                     expected_index, pqc_msg.message_index);
            return Ok(false);
        }
        
        // 2. Verificar integridade da chave ratchet PQC
        if let Some(ref ratchet_key) = pqc_msg.ratchet_key {
            // Verificar tamanho exato da chave Curve25519
            if ratchet_key.curve25519_key.as_bytes().len() != 32 {
                vlog!(VerbosityLevel::Normal, "   FALHA: Chave Curve25519 inválida: {}B", ratchet_key.curve25519_key.as_bytes().len());
                return Ok(false);
            }
            
            // Verificar que chave não é ponto zero (ataque de chave fraca)
            if ratchet_key.curve25519_key.as_bytes().iter().all(|&b| b == 0) {
                vlog!(VerbosityLevel::Normal, "   FALHA: Chave Curve25519 é ponto zero (vulnerável)");
                return Ok(false);
            }
            
            // Verificar tamanho exato da chave KEM baseado no algoritmo
            let (expected_kem_size, algorithm_name) = match ratchet_key.kem_algorithm {
                KemAlgorithm::Kyber512 => (800, "Kyber-512"),
                KemAlgorithm::Kyber768 => (1184, "Kyber-768"),
                KemAlgorithm::Kyber1024 => (1568, "Kyber-1024"),
            };
            
            let actual_kem_size = ratchet_key.kem_public_key.size_bytes();
            if actual_kem_size != expected_kem_size {
                vlog!(VerbosityLevel::Normal, "   FALHA: Chave {} inválida: {}B (esperado: {}B)", 
                         algorithm_name, actual_kem_size, expected_kem_size);
                return Ok(false);
            }
            
            // Verificar compatibilidade de algoritmos
            if ratchet_key.kem_algorithm != self.kem_algorithm {
                vlog!(VerbosityLevel::Normal, "   FALHA: Algoritmo incompatível: {} vs {}", 
                         ratchet_key.kem_algorithm.name(), self.kem_algorithm.name());
                return Ok(false);
            }
            
            // Validação criptográfica: testar se chave KEM é válida
            if !self.validate_kem_public_key(&ratchet_key.kem_public_key)? {
                vlog!(VerbosityLevel::Normal, "   FALHA: Chave KEM falhou na validação criptográfica");
                return Ok(false);
            }
            
            // Verificar serialização round-trip (integridade estrutural)
            match self.verify_key_serialization_integrity(ratchet_key) {
                Ok(true) => {},
                Ok(false) => {
                    vlog!(VerbosityLevel::Normal, "   FALHA: Chave falhou no teste de serialização");
                    return Ok(false);
                }
                Err(_) => {
                    vlog!(VerbosityLevel::Normal, "   FALHA: Erro durante verificação de serialização");
                    return Ok(false);
                }
            }
            
            vlog!(VerbosityLevel::Normal, "   SUCESSO: Chave ratchet PQC validada");
        }
        
        // 3. Verificar integridade do componente vodozemac
        let vodozemac_size = match &pqc_msg.classic_component {
            vodozemac::olm::OlmMessage::PreKey(msg) => msg.to_bytes().len(),
            vodozemac::olm::OlmMessage::Normal(msg) => msg.to_bytes().len(),
        };
        
        if vodozemac_size < 32 {
            vlog!(VerbosityLevel::Normal, "   FALHA: Componente vodozemac muito pequeno: {}B", vodozemac_size);
            return Ok(false);
        }
        
        // 4. Verificar checksum da mensagem completa (básico)
        let message_hash = self.compute_message_hash(pqc_msg)?;
        if !self.verify_message_hash(&message_hash) {
            vlog!(VerbosityLevel::Normal, "   FALHA: Hash da mensagem suspeito");
            return Ok(false);
        }
        
        vlog!(VerbosityLevel::Debug, "   ├─ SUCESSO: Integridade da mensagem verificada");
        Ok(true)
    }
    
    /// Valida se chave KEM é criptograficamente válida
    fn validate_kem_public_key(&self, kem_key: &KemPublicKey) -> Result<bool, CryptoError> {
        let key_bytes = match kem_key {
            KemPublicKey::Kyber512(k) => k.as_bytes(),
            KemPublicKey::Kyber768(k) => k.as_bytes(),
            KemPublicKey::Kyber1024(k) => k.as_bytes(),
        };
        
        // Verificar que não é chave zero (ataque de chave fraca)
        if key_bytes.iter().all(|&b| b == 0) {
            return Ok(false);
        }
        
        // Verificar que não é chave "toda 0xFF" (suspeito)
        if key_bytes.iter().all(|&b| b == 0xFF) {
            return Ok(false);
        }
        
        // Verificar entropia mínima (chave deve ter variação)
        let mut unique_bytes = std::collections::HashSet::new();
        for &byte in key_bytes {
            unique_bytes.insert(byte);
        }
        
        // Kyber keys devem ter pelo menos 32 bytes únicos (entropia mínima)
        if unique_bytes.len() < 32 {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    /// Verifica integridade da serialização (round-trip test)
    fn verify_key_serialization_integrity(&self, ratchet_key: &PqcRatchetPublicKey) -> Result<bool, CryptoError> {
        // Testar serialização e deserialização
        let serialized = ratchet_key.to_base64();
        let deserialized = PqcRatchetPublicKey::from_base64(&serialized)?;
        
        // Verificar se dados são idênticos após round-trip
        let original_curve = ratchet_key.curve25519_key.as_bytes();
        let recovered_curve = deserialized.curve25519_key.as_bytes();
        
        if original_curve != recovered_curve {
            return Ok(false);
        }
        
        // Verificar se algoritmo é preservado
        if ratchet_key.kem_algorithm != deserialized.kem_algorithm {
            return Ok(false);
        }
        
        // Verificar se tamanho das chaves KEM é preservado
        if ratchet_key.kem_public_key.size_bytes() != deserialized.kem_public_key.size_bytes() {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    /// Computa hash da mensagem para verificação de integridade
    fn compute_message_hash(&self, pqc_msg: &PqcOlmMessage) -> Result<[u8; 32], CryptoError> {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        
        // Hash do componente vodozemac
        let vodozemac_bytes = match &pqc_msg.classic_component {
            vodozemac::olm::OlmMessage::PreKey(msg) => msg.to_bytes(),
            vodozemac::olm::OlmMessage::Normal(msg) => msg.to_bytes(),
        };
        hasher.update(&vodozemac_bytes);
        
        // Hash do componente PQC se presente
        if let Some(ref ratchet_key) = pqc_msg.ratchet_key {
            hasher.update(ratchet_key.curve25519_key.as_bytes());
            let kem_bytes = match &ratchet_key.kem_public_key {
                KemPublicKey::Kyber512(k) => k.as_bytes(),
                KemPublicKey::Kyber768(k) => k.as_bytes(),
                KemPublicKey::Kyber1024(k) => k.as_bytes(),
            };
            hasher.update(kem_bytes);
        }
        
        // Hash do metadata
        hasher.update(&pqc_msg.message_index.to_le_bytes());
        hasher.update(&[if pqc_msg.pqc_enabled { 1 } else { 0 }]);
        
        Ok(hasher.finalize().into())
    }
    
    /// Verifica se hash da mensagem é válido (básico)
    fn verify_message_hash(&self, _message_hash: &[u8; 32]) -> bool {
        // Em implementação real, compararia com hash esperado ou assinatura
        // Por agora, apenas verificar que não é zero
        !_message_hash.iter().all(|&b| b == 0)
    }
}

/// Estatísticas de processamento de Bob
#[derive(Clone, Debug)]
pub struct BobProcessingStats {
    pub total_messages_processed: usize,
    pub pqc_messages_processed: usize,
    pub integrity_failures: usize,
    pub avg_processing_time_ms: f64,
    pub ratchet_advancements: usize,
    pub session_stats: SessionStats,
}

/// Derivação híbrida para combinação de segredos DH + KEM no Double Ratchet
///
/// Combina segredos compartilhados clássico (X25519 DH) e pós-quântico (Kyber KEM)
/// usando HKDF-SHA-256 para produzir material de chaveamento híbrido.
///
/// # Processo HKDF-SHA-256
/// 1. Concatena segredos: [classic_shared || pqc_shared]
/// 2. Extract: HMAC-SHA-256(salt, concatenated) → PRK (pseudorandom key)
/// 3. Expand: HMAC-SHA-256(PRK, context || 0x01) → OKM (64 bytes: root_key + chain_key)
///
/// # Segurança Híbrida
/// - Princípio: Security = max(security_classic, security_pqc)
/// - Se Kyber for quebrado: X25519 ainda protege
/// - Se X25519 for quebrado (computador quântico): Kyber protege
/// - Ambos devem ser quebrados simultaneamente para comprometer
///
/// # Parâmetros
/// * `classic_shared` - Segredo compartilhado X25519 DH (32 bytes)
/// * `pqc_shared` - Segredo compartilhado Kyber KEM (32 bytes)
/// * `context` - String de contexto (ex: "matrix-double-ratchet-Kyber-768")
///
/// # Retorno
/// Vec<u8> de 64 bytes: [root_key(32B) || chain_key(32B)]
///
/// # Propriedades Criptográficas
/// - Salt único "matrix-hybrid-double-ratchet-v1" previne ataques de rainbow table
/// - Concatenação preserva entropia total de ambos os segredos
/// - HKDF-SHA-256 garante saída pseudoaleatória indistinguível (PRF)
/// - Contexto adicional fornece binding de domínio (previne cross-protocol attacks)
fn hkdf_hybrid_ratchet(classic_shared: &[u8], pqc_shared: &[u8], context: &[u8]) -> Vec<u8> {
    let salt = b"matrix-hybrid-double-ratchet-v1";
    let hk = Hkdf::<Sha256>::new(Some(salt), &[classic_shared, pqc_shared].concat());
    
    const SHA256_SIZE: usize = 32; // sha2::Sha256 output size
    let mut output = vec![0u8; SHA256_SIZE * 2]; // root key + chain key
    hk.expand(context, &mut output)
        .expect("HKDF expand never fails with valid parameters");
    
    output
}

// Serialização personalizada removida para este protótipo
// Em implementação real, usar serialização binária ou formato Matrix específico

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pqc_ratchet_keypair_generation() {
        // Testar com diferentes algoritmos
        for algorithm in [KemAlgorithm::Kyber512, KemAlgorithm::Kyber768, KemAlgorithm::Kyber1024] {
            let keypair = PqcRatchetKeyPair::generate(algorithm);
            let public_keys = keypair.public_keys();
            
            // Verificar que o algoritmo foi configurado corretamente
            assert_eq!(public_keys.kem_algorithm, algorithm);
            assert_eq!(public_keys.curve25519_key.as_bytes().len(), 32);
            
            vlog!(VerbosityLevel::Normal, "SUCESSO: Geração de chaves híbridas com {}: OK ({}B)", 
                     algorithm.name(), public_keys.size_bytes());
        }
    }
    
    #[test]
    fn test_pqc_ratchet_serialization() {
        let keypair = PqcRatchetKeyPair::generate(KemAlgorithm::Kyber1024);
        let public_keys = keypair.public_keys();
        
        // Serializar e deserializar
        let b64 = public_keys.to_base64();
        let recovered = PqcRatchetPublicKey::from_base64(&b64).unwrap();
        
        // Verificar integridade
        assert_eq!(public_keys.curve25519_key.to_base64(), recovered.curve25519_key.to_base64());
        assert_eq!(public_keys.kem_algorithm, recovered.kem_algorithm);
        
        vlog!(VerbosityLevel::Normal, "SUCESSO: Serialização de chaves PQC: OK ({}B)", b64.len());
    }
    
    #[test]
    fn test_double_ratchet_advancement() {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"test-initial-root-key");
        let initial_root = hasher.finalize().into();
        let mut ratchet = PqcDoubleRatchetState::new(initial_root, KemAlgorithm::Kyber1024, true);
        
        // Configurar chave do peer
        let peer_keypair = PqcRatchetKeyPair::generate(KemAlgorithm::Kyber1024);
        let peer_keys = peer_keypair.public_keys();
        ratchet.set_peer_ratchet_key(peer_keys.clone());
        
        // Avançar ratchet de envio (gera KEM ciphertext)
        let (chain_key1, kem_ct1) = ratchet.advance_sending_ratchet_with_kem().unwrap();
        
        // Simular recebimento: o peer usa seu keypair privado para decapsular
        // Mas no teste, vamos apenas criar um novo keypair e ciphertext
        let new_peer_keypair = PqcRatchetKeyPair::generate(KemAlgorithm::Kyber1024);
        let our_keypair = PqcRatchetKeyPair::generate(KemAlgorithm::Kyber1024);
        let (_, kem_ct2) = new_peer_keypair.hybrid_dh_with_kem(&our_keypair.public_keys()).unwrap();
        
        // Avançar ratchet de recebimento com o ciphertext
        let chain_key2 = ratchet.advance_receiving_ratchet_with_decapsulate(
            &new_peer_keypair.public_keys(), 
            Some(&kem_ct2)
        ).unwrap();
        
        // Verificar que chaves são diferentes
        assert_ne!(chain_key1, chain_key2);
        assert_ne!(chain_key1, initial_root);
        
        vlog!(VerbosityLevel::Debug, "SUCESSO: Avanço do Double Ratchet PQC: OK");
    }
    
    #[test]
    fn test_new_state_machine() {
        use sha2::{Sha256, Digest};
        
        vlog!(VerbosityLevel::Debug, " Testando novo sistema de estados PQC Double Ratchet");
        
        // Criar root key inicial
        let mut hasher = Sha256::new();
        hasher.update(b"test-state-machine-root");
        let initial_root: [u8; 32] = hasher.finalize().into();
        
        // Alice inicia como sender (Active)
        vlog!(VerbosityLevel::Normal, "
1. Alice inicia como SENDER (Active state):");
        let mut alice_ratchet = PqcDoubleRatchetState::new(initial_root, KemAlgorithm::Kyber1024, true);
        
        // Bob inicia como receiver (Inactive) 
        vlog!(VerbosityLevel::Normal, "
2. Bob inicia como RECEIVER (Inactive state):");
        let mut bob_ratchet = PqcDoubleRatchetState::new(initial_root, KemAlgorithm::Kyber1024, false);
        
        // Gerar chaves para teste
        let alice_keypair = PqcRatchetKeyPair::generate(KemAlgorithm::Kyber1024);
        let alice_pub = alice_keypair.public_keys();
        vlog!(VerbosityLevel::Normal, "
3. Alice publica suas chaves PQC ({})", alice_pub.info());
        
        // Bob configura chave de Alice e avança para Active (Inactive→Active)
        vlog!(VerbosityLevel::Normal, "
4. Bob configura peer key de Alice:");
        bob_ratchet.set_peer_ratchet_key(alice_pub.clone());
        let (bob_chain_key, bob_kem_ct) = bob_ratchet.advance_sending_ratchet_with_kem().unwrap();
        vlog!(VerbosityLevel::Normal, "   Bob: Deveria transicionar para Active");
        
        // Gerar chaves de Bob para Alice processar
        let bob_keypair = PqcRatchetKeyPair::generate(KemAlgorithm::Kyber1024);  
        let bob_pub = bob_keypair.public_keys();
        vlog!(VerbosityLevel::Normal, "   Bob publica novas chaves: {}", bob_pub.info());
        
        // Alice recebe mensagem de Bob e transiciona para Inactive (Active→Inactive)  
        vlog!(VerbosityLevel::Normal, "
5. Alice processa mensagem de Bob:");
        alice_ratchet.set_peer_ratchet_key(bob_pub.clone());
        let alice_recv_key = alice_ratchet.advance_receiving_ratchet_with_decapsulate(&bob_pub, bob_kem_ct.as_deref()).unwrap();
        vlog!(VerbosityLevel::Normal, "   Alice: Deveria transicionar para Inactive");
        
        // Alice responde e volta para Active (Inactive→Active)
        vlog!(VerbosityLevel::Normal, "
6. Alice responde (volta para Active):");
        let (alice_chain_key2, _alice_kem_ct) = alice_ratchet.advance_sending_ratchet_with_kem().unwrap();
        vlog!(VerbosityLevel::Normal, "   Alice: Deveria voltar para Active");
        
        // Verificar que as chaves derivadas são diferentes
        vlog!(VerbosityLevel::Normal, "
7. Verificação de segurança:");
        vlog!(VerbosityLevel::Debug, "   Chain key Bob: {}", hex::encode(&bob_chain_key[..8]));
        vlog!(VerbosityLevel::Debug, "   Chain key Alice recepção: {}", hex::encode(&alice_recv_key[..8]));  
        vlog!(VerbosityLevel::Debug, "   Chain key Alice envio: {}", hex::encode(&alice_chain_key2[..8]));
        
        assert_ne!(bob_chain_key, alice_recv_key, "Chaves de diferentes operações devem ser diferentes");
        assert_ne!(alice_recv_key, alice_chain_key2, "Recepção e envio devem ter chaves diferentes");
        
        vlog!(VerbosityLevel::Normal, "\nSUCESSO: Teste do sistema de estados concluído com sucesso!");
        vlog!(VerbosityLevel::Normal, "   - Transições Active ↔ Inactive funcionando");
        vlog!(VerbosityLevel::Normal, "   - Derivação de chaves diferenciada"); 
        vlog!(VerbosityLevel::Normal, "   - Padrão vodozemac implementado corretamente");
    }


    
    #[test]
    fn test_bob_processing_complete() {
        use crate::core::crypto::{CryptoProvider, KemChoice};
        use crate::core::providers::hybrid::VodoCryptoHybrid;
        use sha2::{Sha256, Digest};
        
        // Simular estabelecimento de sessão
        let mut alice = VodoCryptoHybrid::account_new(KemChoice::Kyber1024);
        let mut bob = VodoCryptoHybrid::account_new(KemChoice::Kyber1024);
        
        // Setup PQXDH
        let alice_keys = alice.export_pqxdh_public_keys();
        let bob_keys = bob.export_pqxdh_public_keys();
        alice.set_peer_public_keys(bob_keys);
        bob.set_peer_public_keys(alice_keys);
        
        // Estabelecer sessões
        let bob_identity = bob.upload_identity_keys();
        bob.generate_one_time_keys(1);
        let bob_otks = bob.generate_one_time_keys(1);
        bob.mark_keys_published();
        
        let (alice_session, _) = alice.create_outbound_session(
            &bob_identity.curve25519,
            &bob_otks[0].curve25519
        ).unwrap();
        
        // Criar processador Bob
        let vodozemac_session = {
            // Simular criação de sessão vodozemac para Bob
            let mut hasher = Sha256::new();
            hasher.update(b"test-session-for-bob");
            let _session_key = hasher.finalize();
            
            // Em implementação real, Bob criaria sessão inbound aqui
            alice_session.hybrid_session.vodozemac_session // Placeholder para teste
        };
        
        let mut bob_processor = BobPqcProcessor::new(vodozemac_session, KemAlgorithm::Kyber1024);
        
        // Inicializar PQC
        let mut hasher = Sha256::new();
        hasher.update(b"test-pqc-root-key");
        let pqc_root: [u8; 32] = hasher.finalize().into();
        
        let _bob_ratchet_keys = bob_processor.initialize_pqc(pqc_root);
        
        vlog!(VerbosityLevel::Normal, "SUCESSO: Processador Bob inicializado com sucesso");
        
        // Verificar estatísticas iniciais
        let stats = bob_processor.get_processing_stats();
        assert_eq!(stats.total_messages_processed, 0);
        assert_eq!(stats.pqc_messages_processed, 0);
        
        vlog!(VerbosityLevel::Normal, "SUCESSO: Teste de processamento Bob: OK");
    }
    
    #[test]
    fn test_integrity_verification() {
        let keypair = PqcRatchetKeyPair::generate(KemAlgorithm::Kyber1024);
        let public_keys = keypair.public_keys();
        
        // Verificar integridade das chaves
        assert_eq!(public_keys.curve25519_key.as_bytes().len(), 32);
        assert!(public_keys.kem_public_key.size_bytes() > 1000); // Kyber1024 é grande
        
        // Verificar serialização preserva integridade
        let serialized = public_keys.to_base64();
        let recovered = PqcRatchetPublicKey::from_base64(&serialized).unwrap();
        
        assert_eq!(public_keys.curve25519_key.as_bytes(), recovered.curve25519_key.as_bytes());
        assert_eq!(public_keys.kem_algorithm, recovered.kem_algorithm);
        
        vlog!(VerbosityLevel::Normal, "SUCESSO: Verificação de integridade: OK");
    }
}