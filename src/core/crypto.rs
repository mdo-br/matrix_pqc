// Tipos e Interfaces Criptográficas Core
//
// Define tipos fundamentais, traits e enums para implementações
// criptográficas híbridas PQC + clássicas no contexto Matrix.
//
// Suporta:
// - Algoritmos clássicos: X25519, Ed25519, AES-256-CBC (vodozemac)
// - Algoritmos pós-quânticos: CRYSTALS-Kyber Round 3 (512, 768, 1024)
// - Double Ratchet híbrido com ratcheting KEM
// - Compatibilidade total com vodozemac 0.9.0

use anyhow::Result;
use serde::{Serialize, Deserialize};

/// Variantes do CRYSTALS-Kyber (Round 3) disponíveis

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum KemAlgorithm {
    /// Kyber-512 - NIST Level 1
    /// Segurança quântica: 128 bits
    /// Uso: Dispositivos com recursos limitados
    Kyber512,
    
    /// Kyber-768 - NIST Level 3
    /// Segurança quântica: 192 bits
    /// Uso: Configuração balanceada (recomendado)
    Kyber768,
    
    /// Kyber-1024 - NIST Level 5
    /// Segurança quântica: 256 bits
    /// Uso: Máxima segurança
    Kyber1024,
}

impl KemAlgorithm {
    /// Retorna nome legível do algoritmo
    pub fn name(&self) -> &'static str {
        match self {
            KemAlgorithm::Kyber512 => "Kyber-512",
            KemAlgorithm::Kyber768 => "Kyber-768", 
            KemAlgorithm::Kyber1024 => "Kyber-1024",
        }
    }
    
    /// Nível de segurança quântica em bits
    pub fn security_level(&self) -> u16 {
        match self {
            KemAlgorithm::Kyber512 => 128,
            KemAlgorithm::Kyber768 => 192,
            KemAlgorithm::Kyber1024 => 256,
        }
    }
}

/// Escolha de algoritmo KEM para configuração de provedores
/// 
/// Define qual variante do Kyber será usada no Double Ratchet após
/// o handshake PQXDH (que sempre usa Kyber-1024).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemChoice {
    /// Kyber-512: Performance otimizada
    /// - Chave pública: ~800 bytes
    /// - Ciphertext: ~768 bytes
    Kyber512,
    
    /// Kyber-768: Balanceamento ideal (padrão)
    /// - Chave pública: ~1200 bytes
    /// - Ciphertext: ~1088 bytes
    Kyber768,
    
    /// Kyber-1024: Máxima segurança
    /// - Chave pública: ~1600 bytes
    /// - Ciphertext: ~1568 bytes
    Kyber1024,
}

impl From<KemChoice> for KemAlgorithm {
    fn from(choice: KemChoice) -> Self {
        match choice {
            KemChoice::Kyber512 => KemAlgorithm::Kyber512,
            KemChoice::Kyber768 => KemAlgorithm::Kyber768,
            KemChoice::Kyber1024 => KemAlgorithm::Kyber1024,
        }
    }
}

impl From<KemAlgorithm> for KemChoice {
    fn from(alg: KemAlgorithm) -> Self {
        match alg {
            KemAlgorithm::Kyber512 => KemChoice::Kyber512,
            KemAlgorithm::Kyber768 => KemChoice::Kyber768,
            KemAlgorithm::Kyber1024 => KemChoice::Kyber1024,
        }
    }
}

/// Chaves de identidade exportadas para upload no servidor Matrix
/// 
/// Esta estrutura representa o bundle de chaves que é enviado para o servidor
/// Matrix durante o registro da conta, permitindo que outros usuários iniciem
/// Chaves de identidade exportadas para servidor Matrix
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityKeysExport {
    /// Chave pública Curve25519 para ECDH
    pub curve25519: String,
    
    /// Chave pública Ed25519 para assinaturas
    pub ed25519: String,
    
    /// Chave KEM (apenas modo híbrido)
    /// None = modo clássico, Some = PQXDH disponível
    pub kem_pub_opt: Option<String>,
}

/// Chave one-time exportada (consumida uma vez por sessão)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimeKeyExport {
    /// ID único para rastreamento
    pub key_id: String,
    
    /// Chave pública X25519 efêmera
    pub curve25519: String,
}

/// Handle de sessão Olm com capacidades híbridas
/// 
/// Encapsula vodozemac Session + Double Ratchet PQC opcional.
/// A flag `pqc_enabled` determina qual modo está ativo.
pub struct OlmSessionHandle {
    /// Wrapper híbrido sobre vodozemac Session
    pub hybrid_session: crate::core::double_ratchet_pqc::HybridOlmSession,
    
    /// Modo PQC ativo (true) ou clássico (false)
    pub pqc_enabled: bool,
    
    /// Algoritmo KEM em uso (quando pqc_enabled = true)
    #[allow(dead_code)]
    pub kem_algorithm: Option<crate::core::crypto::KemAlgorithm>,
}

impl OlmSessionHandle {
    /// Verifica se o modo PQC está habilitado
    pub fn is_pqc_enabled(&self) -> bool {
        self.pqc_enabled
    }
    
    /// Obtém número de avanços do Double Ratchet (rotações assimétricas)
    /// Retorna 0 se PQC não estiver habilitado
    pub fn get_ratchet_advances(&self) -> u32 {
        if self.pqc_enabled {
            let stats = self.hybrid_session.get_session_stats();
            stats.ratchet_stats.map(|s| s.ratchet_advances).unwrap_or(0)
        } else {
            0  // Classical não usa Double Ratchet PQC
        }
    }
    
    /// Obtém número de avanços assimétricos (apenas mudanças de direção)
    /// Retorna 0 se PQC não estiver habilitado
    pub fn get_asymmetric_advances(&self) -> u32 {
        if self.pqc_enabled {
            let stats = self.hybrid_session.get_session_stats();
            stats.ratchet_stats.map(|s| s.asymmetric_advances).unwrap_or(0)
        } else {
            0  // Classical não usa Double Ratchet PQC
        }
    }
    
    /// Força avanço assimétrico do Double Ratchet PQC
    /// 
    /// Gera novas chaves Kyber e força que a próxima mensagem realize acordo KEM.
    /// Usado durante rotações Megolm para garantir forward secrecy PQC.
    /// 
    /// Se PQC não estiver habilitado, não faz nada (compatibilidade com clássico).
    pub fn force_asymmetric_ratchet_advance(&mut self) -> Result<(), CryptoError> {
        if self.pqc_enabled {
            self.hybrid_session.force_asymmetric_ratchet_advance()
        } else {
            Ok(()) // Classical não tem ratchet PQC - noop
        }
    }
    
    /// Verifica se a sessão PQC tem peer_key definida (sessão já foi usada)
    /// 
    /// Retorna true se a sessão já trocou mensagens e tem their_ratchet_key.
    /// Retorna false para sessões "lazy" (nunca usadas) ou sem PQC habilitado.
    /// 
    /// Útil para determinar se forced_ratchet pode executar KEM imediatamente
    /// ou se deve aguardar o primeiro uso da sessão.
    pub fn has_peer_key(&self) -> bool {
        if self.pqc_enabled {
            self.hybrid_session.has_peer_key()
        } else {
            false // Classical não tem conceito de peer_key PQC
        }
    }
    
    /// Verifica se a sessão vodozemac subjacente já recebeu mensagem do peer
    /// 
    /// Retorna true se a sessão já descriptografou pelo menos uma mensagem.
    /// Útil para verificar se a sessão está pronta para operações que dependem
    /// de ter estabelecido comunicação bidirecional.
    pub fn has_received_message_classic(&self) -> bool {
        self.hybrid_session.has_received_message_classic()
    }
}

/// Sessão Megolm outbound (envio em grupo)
pub struct MegolmOutbound {
    pub inner: vodozemac::megolm::GroupSession,
}

/// Sessão Megolm inbound (recebimento em grupo)
pub struct MegolmInbound {
    pub inner: vodozemac::megolm::InboundGroupSession,
}

/// Estatísticas de acordo de chaves PQXDH
#[derive(Debug, Clone, Default)]
pub struct KeyAgreementStats {
    /// Tempo de operações KEM (ms)
    pub kem_time_ms: f64,
    
    /// Bytes de ciphertext KEM transmitidos
    pub kem_bytes: usize,
    
    /// Tempo de derivação HKDF (ms)
    #[allow(dead_code)]
    pub hkdf_time_ms: f64,
    
    /// Tempo total de overhead PQC (ms)
    pub total_time_ms: f64,
}

/// Erros de operações criptográficas
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Formato de chave inválido")]
    KeyFormat,
    
    /// Erro genérico de protocolo criptográfico
    /// Inclui falhas de verificação, estados inválidos ou operações incorretas
    #[error("Erro de protocolo: operação criptográfica falhou")]
    Protocol,
    
    /// Erro de codificação/decodificação Base64
    /// Ocorre durante serialização/deserialização de dados criptográficos
    #[error("Erro de codificação Base64: dados não puderam ser codificados/decodificados")]
    B64,
}

/// Interface comum para provedores criptográficos Matrix
/// 
/// API unificada para implementações clássica (Curve25519/Ed25519) 
/// e híbrida (+ CRYSTALS-Kyber). Mantém compatibilidade semântica com o 
/// protocolo Matrix padrão.
pub trait CryptoProvider {
    /// Cria nova conta Matrix com chaves de identidade
    /// 
    /// Gera automaticamente pares de chaves:
    /// - Curve25519 (ECDH)
    /// - Ed25519 (assinatura)  
    /// - CRYSTALS-Kyber (apenas modo híbrido)
    fn account_new() -> Self where Self: Sized;
    
    /// Configura chaves KEM de pares (apenas modo híbrido)
    /// 
    /// Implementação vazia no modo clássico.
    fn set_hybrid_kem_peer_pks(&mut self, _peer_kem_pks_b64: &[String]) {}
    
    /// Exporta chaves de identidade para servidor Matrix
    fn upload_identity_keys(&self) -> IdentityKeysExport;
    
    /// Gera lote de chaves one-time efêmeras
    /// 
    /// Cria múltiplas chaves de uso único que serão consumidas durante
    /// estabelecimento de sessões PQXDH, garantindo sigilo progressivo.
    /// 
    /// # Parâmetros  
    /// * `count` - Número de chaves one-time a gerar
    fn generate_one_time_keys(&mut self, count: usize) -> Vec<OneTimeKeyExport>;
    
    /// Marca chaves como publicadas no servidor
    /// 
    /// Atualiza estado interno para refletir que as chaves foram enviadas
    /// ao servidor Matrix e estão disponíveis para outros usuários.
    fn mark_keys_published(&mut self);
    
    /// Cria sessão Olm outbound (inicia comunicação)
    /// 
    /// Estabelece nova sessão 1-para-1 usando protocolo PQXDH, realizando
    /// acordo de chaves com outro usuário e inicializando Double Ratchet.
    /// 
    /// # Parâmetros
    /// * `their_curve25519` - Chave pública Curve25519 do destinatário
    /// * `their_one_time_key` - Chave one-time do destinatário a consumir
    /// 
    /// # Retorno
    /// Tupla contendo:
    /// - `OlmSessionHandle` - sessão criada
    /// - `Option<MatrixPqxdhInitMessage>` - init_message para transmissão (Some se híbrido, None se clássico)
    fn create_outbound_session(
        &mut self,
        their_curve25519: &str,
        their_one_time_key: &str,
    ) -> Result<(OlmSessionHandle, Option<crate::core::pqxdh::MatrixPqxdhInitMessage>), CryptoError>;
    
    /// Configura init_message PQXDH para posterior criação de sessão inbound
    /// 
    /// IMPORTANTE: Este método DEVE ser chamado ANTES de create_inbound_session()
    /// quando trabalhando com modo híbrido (PQXDH). Permite ao receiver injetar
    /// a init_message que foi transmitida pelo sender.
    /// 
    /// # Parâmetros
    /// * `init_message` - Mensagem PQXDH recebida do sender
    /// 
    /// # Modo Clássico
    /// No modo clássico, este método não faz nada (implementação vazia).
    /// 
    /// # Modo Híbrido
    /// Armazena a init_message para uso em create_inbound_session().
    fn set_pqxdh_init_message(&mut self, _init_message: crate::core::pqxdh::MatrixPqxdhInitMessage) {
        // Implementação padrão vazia (modo clássico)
    }
    
    /// Cria sessão Olm inbound (responde a comunicação)
    /// 
    /// Processa PreKeyMessage recebida, estabelece acordo PQXDH,
    /// cria sessão inbound e descriptografa mensagem inicial automaticamente.
    /// 
    /// # Parâmetros
    /// * `their_curve25519` - Chave pública do remetente
    /// * `prekey_message_b64` - PreKeyMessage codificada em Base64
    /// 
    /// # Retorno
    /// Tupla contendo (sessão_criada, mensagem_inicial_descriptografada)
    /// 
    /// # Modo Híbrido
    /// REQUER que set_pqxdh_init_message() tenha sido chamado previamente.
    /// Caso contrário, faz fallback para modo clássico com aviso.
    fn create_inbound_session(
        &mut self,
        their_curve25519: &str,
        prekey_message_b64: &str,
    ) -> Result<(OlmSessionHandle, Vec<u8>), CryptoError>;
    
    /// Criptografa mensagem usando sessão Olm
    /// 
    /// Aplica Double Ratchet para derivar chaves de mensagem e criptografa
    /// conteúdo usando AES-256-CBC com autenticação HMAC-SHA-256.
    /// 
    /// # Parâmetros
    /// * `session` - Sessão Olm para criptografia
    /// * `plaintext` - Dados a criptografar
    fn olm_encrypt(&mut self, session: &mut OlmSessionHandle, plaintext: &[u8]) -> String;
    
    /// Descriptografa mensagem usando sessão Olm
    /// 
    /// Atualiza estado Double Ratchet, deriva chaves necessárias e
    /// descriptografa mensagem com verificação de autenticidade.
    /// 
    /// # Parâmetros
    /// * `session` - Sessão Olm para descriptografia
    /// * `message_b64` - Mensagem criptografada em Base64
    fn olm_decrypt(&mut self, session: &mut OlmSessionHandle, message_b64: &str) -> Result<Vec<u8>, CryptoError>;
    
    /// Cria sessão Megolm outbound para comunicação em grupo
    /// 
    /// Inicializa nova sessão de grupo onde este dispositivo pode enviar
    /// mensagens criptografadas para múltiplos participantes.
    fn megolm_create_outbound(&mut self) -> MegolmOutbound;
    
    /// Exporta chave de sessão Megolm para distribuição
    /// 
    /// Serializa chave de sessão para distribuição segura via canais Olm
    /// individuais para cada participante do grupo.
    /// 
    /// # Parâmetros
    /// * `room_key` - Sessão Megolm outbound a exportar
    fn megolm_export_inbound(&self, room_key: &MegolmOutbound) -> String;
    
    /// Importa chave de sessão Megolm recebida
    /// 
    /// Cria sessão inbound a partir de chave recebida via canal Olm,
    /// permitindo descriptografar mensagens do grupo.
    /// 
    /// # Parâmetros
    /// * `exported_b64` - Chave de sessão exportada em Base64
    fn megolm_import_inbound(&mut self, exported_b64: &str) -> MegolmInbound;
    
    /// Criptografa mensagem para grupo usando Megolm
    /// 
    /// Deriva chave de mensagem a partir da chave de sessão e criptografa
    /// conteúdo para transmissão eficiente para múltiplos destinatários.
    /// 
    /// # Parâmetros
    /// * `outbound` - Sessão Megolm outbound
    /// * `plaintext` - Dados a criptografar
    fn megolm_encrypt(&mut self, outbound: &mut MegolmOutbound, plaintext: &[u8]) -> String;
    
    /// Descriptografa mensagem de grupo usando Megolm
    /// 
    /// Deriva chave apropriada baseada no índice da mensagem e
    /// descriptografa conteúdo com verificação de integridade.
    /// 
    /// # Parâmetros
    /// * `inbound` - Sessão Megolm inbound
    /// * `message_b64` - Mensagem criptografada em Base64
    fn megolm_decrypt(&mut self, inbound: &mut MegolmInbound, message_b64: &str) -> Result<Vec<u8>, CryptoError>;
}

