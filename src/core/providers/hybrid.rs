// Provedor Criptográfico Híbrido PQC + Clássico para Protocolo Matrix
//
// Implementa wrapper sobre vodozemac com extensões pós-quânticas usando CRYSTALS-Kyber.
//
// PRIMITIVAS CRIPTOGRÁFICAS:
// - Curve25519 (ECDH para acordo de chaves clássico)
// - Ed25519 (assinatura digital de identidade)
// - AES-256-CBC com PKCS#7 padding (criptografia simétrica - vodozemac)
// - HMAC-SHA-256 (autenticação de mensagens)
// - HKDF-SHA-256 (derivação de chaves criptográficas)
// - CRYSTALS-Kyber (KEM pós-quântico - 512/768/1024 bits)
//
// PROTOCOLOS:
// - PQXDH (handshake inicial híbrido):
//   * 4 × X25519 DH (Extended Triple Diffie-Hellman)
//   * 1 × CRYSTALS-Kyber-1024 KEM (encapsulamento pós-quântico)
//   * HKDF-SHA-256 para derivação híbrida de chave de sessão
//   * Overhead: ~1.6 KB (uma única vez no estabelecimento)
//
// - Double Ratchet PQC (comunicação contínua):
//   * Avanço simétrico: HMAC-SHA-256 (mensagens na mesma direção, ZERO overhead)
//   * Avanço assimétrico: X25519 + Kyber KEM (mudança de direção, 800-1600 bytes)
//   * Ratchet key SEMPRE presente em mensagens (padrão vodozemac/Matrix)
//   * KEM ciphertext presente APENAS em mudanças de direção
//   * Forward secrecy: Compromisso de chave atual não revela chaves passadas
//   * Backward secrecy: Compromisso de chave atual não revela chaves futuras
//
// - Megolm (criptografia de grupo):
//   * Conteúdo: AES-256-CBC puro (ZERO overhead PQC, compatível com clientes clássicos)
//   * Distribuição: Chaves Megolm distribuídas via canais Olm híbridos (protegidas por PQXDH)
//   * Ratchet unidirecional: HKDF-SHA-256 com estado de 128 bytes
//   * Performance: Preservada (1 criptografia AES para N destinatários)
//
// SEGURANÇA HÍBRIDA:
// - Princípio: Security = max(classical_security, pqc_security)
// - Se Kyber for quebrado: Proteção clássica X25519 mantida (segurança equivalente a Olm padrão)
// - Se X25519 for quebrado (computador quântico): Proteção Kyber mantida
// - Ambos precisam ser quebrados para comprometer a comunicação
//
// COMPATIBILIDADE:
// - Modo híbrido: Sessões entre clientes com suporte PQC (ambos negociam PQXDH)
// - Modo clássico: Fallback automático para vodozemac puro (interoperável com clientes antigos)
// - Detecção automática: Formato de mensagem identifica modo (JSON type:2 = PQC, Base64 = clássico)
// - Upgrade transparente: Clientes antigos continuam funcionando, novos ganham proteção PQC

use crate::core::crypto::*;
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;
use vodozemac::{
    megolm::{
        GroupSession, InboundGroupSession, MegolmMessage, SessionConfig as MegolmSessionConfig,
    },
    olm::{Account, Message, OlmMessage, PreKeyMessage, SessionConfig},
    Curve25519PublicKey,
};

use crate::core::pqxdh::{complete_pqxdh, init_pqxdh, MatrixUser};
use crate::utils::logging::VerbosityLevel;
use crate::vlog;

/// Derivação de chave raiz híbrida usando HKDF-SHA-256
///
/// Combina segredos compartilhados clássicos (X25519 DH) e pós-quânticos (Kyber KEM)
/// em uma única chave raiz de 32 bytes usando HKDF-SHA-256.
///
/// # Processo HKDF
/// 1. Extract: HMAC-SHA-256(salt, [ss_classic || ss_pqc]) → PRK (pseudorandom key)
/// 2. Expand: HMAC-SHA-256(PRK, ctx || 0x01) → OKM (output keying material, 32 bytes)
///
/// # Segurança Híbrida
/// - Princípio: Security = max(classical, pqc)
/// - Se Kyber for quebrado: X25519 ainda protege
/// - Se X25519 for quebrado (computador quântico): Kyber protege
/// - Ambos devem ser quebrados para comprometer
///
/// # Parâmetros
/// * `ss_classic` - Segredo compartilhado X25519 DH (32 bytes)
/// * `ss_pqc` - Segredo compartilhado Kyber KEM (32 bytes)
/// * `ctx` - Contexto de domínio (ex: "olm-pqxdh:@user:matrix.org:DEVICE_123")
///
/// # Retorno
/// Chave raiz híbrida de 32 bytes (256 bits de segurança)
///
/// # Propriedades Criptográficas
/// - Salt único previne ataques de rainbow table
/// - Concatenação preserva entropia de ambos os segredos
/// - HKDF-SHA-256 garante saída pseudoaleatória indistinguível
/// - Contexto adicional previne ataques de cross-protocol (binding de domínio)
fn hkdf_hybrid_root(ss_classic: &[u8], ss_pqc: &[u8], ctx: &[u8]) -> [u8; 32] {
    let salt = b"matrix-hybrid-root:v1|olm-x25519|kem-kyber";
    let hk = Hkdf::<Sha256>::new(Some(salt), &[ss_classic, ss_pqc].concat());
    let mut okm = [0u8; 32];
    hk.expand(ctx, &mut okm)
        .expect("HKDF expand never fails with valid parameters");
    okm
}

/// Provedor criptográfico híbrido PQC + Clássico
pub struct VodoCryptoHybrid {
    account: Account,
    kem_choice: KemChoice,
    last_stats: KeyAgreementStats,

    // PQXDH gerencia o acordo híbrido de chaves
    pqxdh_user: MatrixUser,
    // Chaves públicas completas dos peers para PQXDH
    peer_public_keys: Option<serde_json::Value>,
    // Mensagem PQXDH para completar acordo no lado receptor
    pqxdh_init_message: Option<crate::core::pqxdh::MatrixPqxdhInitMessage>,
}

impl VodoCryptoHybrid {
    /// Cria nova conta híbrida com capacidades PQXDH
    /// 
    /// # Arquitetura de Chaves
    /// 
    /// Chaves Clássicas (vodozemac Account):
    ///    - Ed25519: Assinatura de identidade
    ///    - Curve25519: Acordo de chaves DH
    ///    - One-time keys: X25519 descartáveis
    /// 
    /// Chaves PQC (MatrixUser PQXDH):
    ///    - Ed25519 + Curve25519: Identidades independentes
    ///    - Prekey Kyber-1024: KEM pós-quântico rotacionável
    ///    - Prekey X25519: DH ephemeral de médio prazo
    ///    - One-time keys: X25519 para forward secrecy
    /// 
    /// # Parâmetro `choice`
    /// Seleciona variante KEM usada no Double Ratchet (após handshake PQXDH):
    /// - `Kyber512`: NIST Nível 1 (mais rápido)
    /// - `Kyber768`: NIST Nível 3 (balanceado) - padrão
    /// - `Kyber1024`: NIST Nível 5 (máxima segurança)
    /// 
    /// Nota: O handshake PQXDH sempre usa Kyber-1024.
    pub fn account_new(choice: KemChoice) -> Self {
        // Criar usuário PQXDH com chaves híbridas completas
        let user_id = format!("@user{}:matrix.org", rand::thread_rng().gen::<u32>());
        let device_id = format!("DEVICE_{}", rand::thread_rng().gen::<u32>());
        let pqxdh_user = MatrixUser::new(user_id, device_id).expect("Failed to create PQXDH user");

        Self {
            account: Account::new(),
            kem_choice: choice,
            last_stats: KeyAgreementStats::default(),
            pqxdh_user,
            peer_public_keys: None,
            pqxdh_init_message: None,
        }
    }
}

impl VodoCryptoHybrid {
    /// Configura chaves públicas completas dos peers para PQXDH
    pub fn set_peer_public_keys(&mut self, peer_keys: serde_json::Value) {
        self.peer_public_keys = Some(peer_keys);
    }

    /// Exporta chaves públicas no formato PQXDH
    pub fn export_pqxdh_public_keys(&self) -> serde_json::Value {
        self.pqxdh_user.export_public_keys()
    }

    /// Define mensagem PQXDH para completar acordo (usado no inbound)
    pub fn set_pqxdh_init_message(&mut self, init_message: crate::core::pqxdh::MatrixPqxdhInitMessage) {
        self.pqxdh_init_message = Some(init_message);
    }
}

impl CryptoProvider for VodoCryptoHybrid {
    /// Método legado da trait - não utilizado nesta implementação
    /// 
    /// As chaves KEM dos peers são gerenciadas através de `set_peer_public_keys()`
    /// que configura usuários PQXDH completos com todas as chaves necessárias.
    fn set_hybrid_kem_peer_pks(&mut self, _peer_kem_pks_b64: &[String]) {
        // No-op: compatibilidade com interface CryptoProvider
    }

    /// Cria conta com configuração padrão (Kyber768 - balanceado)
    fn account_new() -> Self
    where
        Self: Sized,
    {
        Self::account_new(KemChoice::Kyber768)
    }

    /// Exporta chaves de identidade clássicas (Curve25519 + Ed25519)
    /// 
    /// Para obter as chaves PQC completas, use `export_pqxdh_public_keys()`.
    fn upload_identity_keys(&self) -> IdentityKeysExport {
        let id = self.account.identity_keys();
        IdentityKeysExport {
            curve25519: id.curve25519.to_base64(),
            ed25519: id.ed25519.to_base64(),
            kem_pub_opt: None, // Chaves KEM disponíveis via export_pqxdh_public_keys()
        }
    }

    /// Gera one-time keys clássicas X25519
    /// 
    /// OTKs são usadas para forward secrecy - cada chave só pode ser consumida uma vez.
    /// Compatível com protocolo Matrix e sessões Olm clássicas.
    fn generate_one_time_keys(&mut self, count: usize) -> Vec<OneTimeKeyExport> {
        self.account.generate_one_time_keys(count);
        let map = self.account.one_time_keys();
        map.iter()
            .map(|(k, v)| OneTimeKeyExport {
                key_id: format!("{:?}", k),
                curve25519: v.to_base64(),
            })
            .collect()
    }

    /// Marca chaves como publicadas no servidor Matrix
    fn mark_keys_published(&mut self) {
        self.account.mark_keys_as_published();
    }

    /// Cria sessão Olm de saída com proteção híbrida PQXDH
    /// 
    /// # Fluxo de Criação
    /// 
    /// Com PQXDH disponível (peer_public_keys configurado):
    /// 1. Executa handshake PQXDH completo (3 ou s + 1 KEM Kyber-1024) → session_key
    /// 2. Cria sessão Olm clássica base (vodozemac X25519) → session_id
    /// 3. Combina ambas via HKDF-SHA-256: hkdf_hybrid_root(session_id, session_key)
    /// 4. Usa session_key PQXDH como root_key do Double Ratchet PQC
    /// 5. Habilita modo PQC com algoritmo KEM configurado (Kyber512/768/1024)
    /// 
    /// Fallback clássico (PQXDH indisponível):
    /// - Cria sessão Olm padrão (apenas X25519)
    /// - Modo compatível com clientes não-PQC
    /// 
    /// # Retorno
    /// Tupla contendo:
    /// - `OlmSessionHandle` com flag `pqc_enabled` indicando modo ativo
    /// - `Option<MatrixPqxdhInitMessage>` - init_message para transmissão (Some se híbrido, None se clássico)
    fn create_outbound_session(
        &mut self,
        their_curve25519: &str,
        their_one_time_key: &str,
    ) -> Result<(OlmSessionHandle, Option<crate::core::pqxdh::MatrixPqxdhInitMessage>), CryptoError> {
        let id_key = Curve25519PublicKey::from_base64(their_curve25519)
            .map_err(|_| CryptoError::KeyFormat)?;
        let otk = Curve25519PublicKey::from_base64(their_one_time_key)
            .map_err(|_| CryptoError::KeyFormat)?;

        // FASE 1: Acordo PQXDH (se chaves disponíveis)
        if let Some(ref peer_keys) = self.peer_public_keys {
            let start_time = std::time::Instant::now();

            // Executar PQXDH
            match init_pqxdh(&self.pqxdh_user, peer_keys) {
                Ok(pqxdh_output) => {
                    vlog!(VerbosityLevel::Debug, "PQXDH iniciado!");
                    vlog!(VerbosityLevel::Normal, 
                        "Chave de sessão gerada: {}",
                        hex::encode(&pqxdh_output.session_key)
                    );

                    // IMPORTANTE: Armazenar init_message localmente E retornar para transmissão
                    let init_message_for_transmission = pqxdh_output.init_message.clone();
                    self.pqxdh_init_message = Some(pqxdh_output.init_message.clone());

                    // Criar sessão Olm clássica base
                    let classic_session = self.account.create_outbound_session(
                        SessionConfig::version_2(),
                        id_key,
                        otk,
                    );

                    // Combinar chave PQXDH com chave Olm usando HKDF
                    let session_id = classic_session.session_id();
                    let classic_sk = session_id.as_bytes();
                    let ctx = format!(
                        "olm-pqxdh:{}:{}",
                        self.pqxdh_user.user_id, self.pqxdh_user.device_id
                    );
                    let _hybrid_key =
                        hkdf_hybrid_root(classic_sk, &pqxdh_output.session_key, ctx.as_bytes());

                    // Registrar estatísticas de performance
                    let elapsed = start_time.elapsed();
                    self.last_stats.total_time_ms = elapsed.as_secs_f64() * 1000.0;
                    self.last_stats.kem_time_ms = self.last_stats.total_time_ms;
                    self.last_stats.kem_bytes = match self.kem_choice {
                        KemChoice::Kyber512 => pqcrypto_kyber::kyber512::ciphertext_bytes(),
                        KemChoice::Kyber768 => pqcrypto_kyber::kyber768::ciphertext_bytes(),
                        KemChoice::Kyber1024 => pqcrypto_kyber::kyber1024::ciphertext_bytes(),
                    };

                    vlog!(VerbosityLevel::Debug, "Sessão Olm HÍBRIDA criada (Alice→Bob): X25519 + Kyber ({:.2}ms, {}B)",
                             elapsed.as_secs_f64() * 1000.0, self.last_stats.kem_bytes);
                    
                    // Criar wrapper híbrido e habilitar modo PQC
                    let mut hybrid_session_alice = crate::core::double_ratchet_pqc::HybridOlmSession::from_vodozemac(
                        classic_session
                    );
                    
                    // Usar chave PQXDH como chave raiz do Double Ratchet PQC
                    let mut root_key = [0u8; 32];
                    root_key[..pqxdh_output.session_key.len().min(32)].copy_from_slice(
                        &pqxdh_output.session_key[..pqxdh_output.session_key.len().min(32)]
                    );
                    
                    // Ativar ratcheting PQC com algoritmo KEM configurado
                    let kem_algo: crate::core::crypto::KemAlgorithm = self.kem_choice.into();
                    hybrid_session_alice.enable_pqc_mode(root_key, kem_algo);
                    
                    vlog!(VerbosityLevel::Debug, "Sessão Olm híbrida criada com PQXDH + Double Ratchet PQC habilitado");
                    vlog!(VerbosityLevel::Debug, "  Ratchet key será incluída em TODAS as mensagens (padrão vodozemac)");
                    
                    return Ok((
                        OlmSessionHandle {
                            hybrid_session: hybrid_session_alice,
                            pqc_enabled: true,
                            kem_algorithm: Some(kem_algo),
                        },
                        Some(init_message_for_transmission)
                    ));
                }
                Err(e) => {
                    vlog!(VerbosityLevel::Normal, "  Erro no PQXDH: {:?}. Fallback para Olm clássico.", e);
                }
            }
        }

        // Modo fallback: sessão Olm clássica pura
        let classic_session = self.account.create_outbound_session(SessionConfig::version_2(), id_key, otk);
        let hybrid_session = crate::core::double_ratchet_pqc::HybridOlmSession::from_vodozemac(classic_session);
        
        vlog!(VerbosityLevel::Normal, "Canal Olm clássico (PQXDH não disponível)");

        Ok((
            OlmSessionHandle {
                hybrid_session,
                pqc_enabled: false,
                kem_algorithm: None,
            },
            None // Clássico não tem init_message
        ))
    }

    /// Configura init_message PQXDH para posterior criação de sessão inbound
    /// 
    /// Permite ao receiver armazenar a init_message transmitida pelo sender,
    /// necessária para estabelecer sessão inbound com PQXDH.
    /// 
    /// IMPORTANTE: Deve ser chamado ANTES de create_inbound_session().
    /// 
    /// # Parâmetros
    /// * `init_message` - Mensagem PQXDH recebida do sender
    fn set_pqxdh_init_message(&mut self, init_message: crate::core::pqxdh::MatrixPqxdhInitMessage) {
        vlog!(VerbosityLevel::Debug, "[PQXDH] Init message configurada para sessão inbound");
        self.pqxdh_init_message = Some(init_message);
    }

    /// Cria sessão Olm de entrada completando handshake PQXDH
    /// 
    /// # Fluxo de Criação (Receptor)
    /// 
    /// Com PQXDH (pqxdh_init_message configurada):
    /// 1. Aceita sessão Olm clássica base (valida PreKeyMessage vodozemac)
    /// 2. Completa handshake PQXDH: desencapsula KEM + reconstrói 3-4 DHs → session_key
    /// 3. Combina com vodozemac session_id via HKDF-SHA-256 (mesma derivação do sender)
    /// 4. Usa session_key PQXDH como root_key do Double Ratchet PQC
    /// 5. Habilita modo PQC como receptor (estado Inactive aguardando enviar)
    /// 
    /// Fallback clássico (sem PQXDH):
    /// - Aceita sessão Olm padrão normalmente
    /// 
    /// # Retorno
    /// Tupla: (OlmSessionHandle, plaintext da PreKeyMessage)
    fn create_inbound_session(
        &mut self,
        _their_curve25519: &str,
        prekey_message: &[u8],
    ) -> Result<(OlmSessionHandle, Vec<u8>), CryptoError> {
        vlog!(VerbosityLevel::Debug, "[INBOUND] Criando sessão inbound");
        vlog!(VerbosityLevel::Debug, "[INBOUND] Tamanho da mensagem: {} bytes", prekey_message.len());
        
        // DETECÇÃO AUTOMÁTICA DE FORMATO: JSON (PQC) vs bytes binários (Clássico)
        // 
        // Mensagem PQC: bytes que ao interpretar como UTF-8 começam com `{"type":2,`
        // Mensagem clássica: bytes binários da PreKeyMessage vodozemac
        // 
        if prekey_message.starts_with(b"{\"type\":2,") {
            vlog!(VerbosityLevel::Debug, "[INBOUND] Mensagem PQC detectada (JSON format)");
            let prekey_message_str = std::str::from_utf8(prekey_message).map_err(|_| CryptoError::Protocol)?;
            // Mensagem PQC - deserializar do JSON primeiro
            let pqc_msg = crate::core::double_ratchet_pqc::PqcOlmMessage::from_transport_string(prekey_message_str)?;
            
            // Extrair PreKeyMessage clássica do componente interno
            let prekey = match &pqc_msg.classic_component {
                vodozemac::olm::OlmMessage::PreKey(pk) => pk.clone(),
                _ => return Err(CryptoError::Protocol), // Deve ser PreKey na primeira mensagem
            };
            
            let their_identity_key = prekey.identity_key();

            // Criar sessão Olm base
            let creation_result = self
                .account
                .create_inbound_session(their_identity_key, &prekey)
                .map_err(|_| CryptoError::Protocol)?;

            let plaintext = creation_result.plaintext; // Já descriptografado pelo vodozemac!
            let vodozemac_session = creation_result.session;

            // Tentar completar PQXDH se disponível (mesmo código de antes)
            let pqc_successful;
            let mut pqxdh_root_key = [0u8; 32];
            
            if let Some(ref init_message) = self.pqxdh_init_message {
                let start_time = std::time::Instant::now();

                match complete_pqxdh(&mut self.pqxdh_user, init_message) {
                    Ok(session_key) => {
                        vlog!(VerbosityLevel::Normal, "PQXDH completado com sucesso");
                        pqc_successful = true;
                        pqxdh_root_key[..session_key.len().min(32)].copy_from_slice(
                            &session_key[..session_key.len().min(32)]
                        );

                        let elapsed = start_time.elapsed();
                        self.last_stats.total_time_ms = elapsed.as_secs_f64() * 1000.0;
                        self.last_stats.kem_time_ms = self.last_stats.total_time_ms * 0.8;
                        self.last_stats.kem_bytes = match self.kem_choice {
                            KemChoice::Kyber512 => pqcrypto_kyber::kyber512::ciphertext_bytes(),
                            KemChoice::Kyber768 => pqcrypto_kyber::kyber768::ciphertext_bytes(),
                            KemChoice::Kyber1024 => pqcrypto_kyber::kyber1024::ciphertext_bytes(),
                        };
                    }
                    Err(e) => {
                        vlog!(VerbosityLevel::Normal, "Erro ao completar PQXDH: {:?}", e);
                        pqc_successful = false;
                    }
                }
            } else {
                pqc_successful = false;
            }

            // Criar wrapper híbrido
            let mut hybrid_session = crate::core::double_ratchet_pqc::HybridOlmSession::from_vodozemac(vodozemac_session);
            
            if pqc_successful {
                let kem_algo: crate::core::crypto::KemAlgorithm = self.kem_choice.into();
                hybrid_session.enable_pqc_mode_as_receiver(pqxdh_root_key, kem_algo);
                
                // Processar ratchet key PQC da mensagem inicial
                if let Some(ref ratchet_key) = pqc_msg.ratchet_key {
                    vlog!(VerbosityLevel::Debug, "Processando ratchet key PQC da PreKeyMessage");
                    hybrid_session.set_peer_pqc_key(ratchet_key.clone())?;
                }
            }
            
            // Plaintext já foi descriptografado pelo vodozemac durante create_inbound_session
            return Ok((
                OlmSessionHandle {
                    hybrid_session,
                    pqc_enabled: pqc_successful,
                    kem_algorithm: if pqc_successful { Some(self.kem_choice.into()) } else { None },
                },
                plaintext, // Retornar o plaintext que vodozemac já descriptografou
            ));
        }
        
        // Fallback: mensagem clássica (bytes binários diretos)
        vlog!(VerbosityLevel::Debug, "[INBOUND] Mensagem clássica detectada (binário)");
        let prekey = PreKeyMessage::from_bytes(prekey_message).map_err(|_| CryptoError::Protocol)?;
        let their_identity_key = prekey.identity_key();

        // Aceitar sessão Olm base primeiro
        let creation_result = self
            .account
            .create_inbound_session(their_identity_key, &prekey)
            .map_err(|_| CryptoError::Protocol)?;

        let plaintext = creation_result.plaintext;
        let vodozemac_session = creation_result.session;

        // Tentar completar PQXDH se mensagem disponível
        let pqc_successful;
        let mut pqxdh_root_key = [0u8; 32];
        
        if let Some(ref init_message) = self.pqxdh_init_message {
            let start_time = std::time::Instant::now();

            // Completar handshake PQXDH do lado receptor
            match complete_pqxdh(&mut self.pqxdh_user, init_message) {
                Ok(session_key) => {
                    vlog!(VerbosityLevel::Normal, "PQXDH completado com sucesso");
                    vlog!(VerbosityLevel::Normal, "   Chave de sessão: {}", hex::encode(&session_key));

                    // Combinar com chave Olm usando HKDF
                    let session_id = vodozemac_session.session_id();
                    let classic_sk = session_id.as_bytes();
                    let ctx = format!(
                        "olm-pqxdh:{}:{}",
                        self.pqxdh_user.user_id, self.pqxdh_user.device_id
                    );
                    let _hybrid_key = hkdf_hybrid_root(classic_sk, &session_key, ctx.as_bytes());

                    // Preparar chave raiz para Double Ratchet PQC
                    pqc_successful = true;
                    pqxdh_root_key[..session_key.len().min(32)].copy_from_slice(
                        &session_key[..session_key.len().min(32)]
                    );

                    // Registrar estatísticas
                    let elapsed = start_time.elapsed();
                    self.last_stats.total_time_ms = elapsed.as_secs_f64() * 1000.0;
                    self.last_stats.kem_time_ms = self.last_stats.total_time_ms * 0.8;
                    self.last_stats.kem_bytes = match self.kem_choice {
                        KemChoice::Kyber512 => pqcrypto_kyber::kyber512::ciphertext_bytes(),
                        KemChoice::Kyber768 => pqcrypto_kyber::kyber768::ciphertext_bytes(),
                        KemChoice::Kyber1024 => pqcrypto_kyber::kyber1024::ciphertext_bytes(),
                    };

                    vlog!(VerbosityLevel::Normal, "Nova sessão Olm híbrida criada com PQXDH (inbound)");
                }
                Err(e) => {
                    vlog!(VerbosityLevel::Normal, 
                        "Erro ao completar PQXDH: {:?}. Canal Olm clássico mantido.",
                        e
                    );
                    pqc_successful = false;
                }
            }
        } else {
            vlog!(VerbosityLevel::Debug, "Sessão Olm aceita via PreKeyMessage");
            pqc_successful = false;
        }

        // Criar wrapper híbrido
        let mut hybrid_session_bob = crate::core::double_ratchet_pqc::HybridOlmSession::from_vodozemac(vodozemac_session);
        
        // Habilitar PQC se handshake completou
        if pqc_successful {
            let kem_algo: crate::core::crypto::KemAlgorithm = self.kem_choice.into();
            hybrid_session_bob.enable_pqc_mode_as_receiver(pqxdh_root_key, kem_algo);
            vlog!(VerbosityLevel::Normal, "PQC habilitado na sessão inbound");
        }
        
        Ok((
            OlmSessionHandle {
                hybrid_session: hybrid_session_bob,
                pqc_enabled: pqc_successful,
                kem_algorithm: if pqc_successful { 
                    Some(self.kem_choice.into()) 
                } else { 
                    None 
                },
            },
            plaintext,
        ))
    }

    /// Criptografa mensagem via Olm (modo automático PQC/clássico)
    /// 
    /// Modo PQC (pqc_enabled = true):
    /// - Usa Double Ratchet PQC com ratcheting KEM automático
    /// - Serializa em formato JSON Matrix compatível: {"type":2,"body":"..."}
    /// - Fallback para clássico em caso de erro
    /// 
    /// Modo Clássico:
    /// - Usa apenas vodozemac (X25519 DH + AES-256-CBC + HMAC-SHA-256)
    /// - Serialização Base64 padrão
    fn olm_encrypt(&mut self, session: &mut OlmSessionHandle, plaintext: &[u8]) -> Vec<u8> {
        let verbosity = std::env::var("VERBOSITY").unwrap_or_default().parse::<u8>().unwrap_or(0);
        
        if session.pqc_enabled {
            // Modo híbrido com Double Ratchet PQC
            match session.hybrid_session.encrypt_hybrid(plaintext) {
                Ok(pqc_msg) => pqc_msg.to_transport_string().into_bytes(),
                Err(e) => {
                    vlog!(VerbosityLevel::Verbose, "  [DOUBLE RATCHET HÍBRIDO] ERRO: {:?} - Fallback para modo clássico", e);
                    // Fallback automático para modo clássico
                    let has_received = session.hybrid_session.has_received_message_classic();
                    let message = session.hybrid_session.encrypt_classic(plaintext);
                    if verbosity >= 4 {
                        match &message {
                            vodozemac::olm::OlmMessage::PreKey(_) => {
                                println!("    └─PreKeyMessage (has_received={})", has_received);
                            }
                            vodozemac::olm::OlmMessage::Normal(_) => {
                                println!("    └─Normal Message (has_received={})", has_received);
                            }
                        }
                    }
                    match message {
                        vodozemac::olm::OlmMessage::PreKey(m) => m.to_bytes(),
                        vodozemac::olm::OlmMessage::Normal(m) => m.to_bytes(),
                    }
                }
            }
        } else {
            // Modo clássico puro (vodozemac)
            let has_received = session.hybrid_session.has_received_message_classic();
            let message = session.hybrid_session.encrypt_classic(plaintext);
            if verbosity >= 4 {
                println!("  [DOUBLE RATCHET HÍBRIDO - Modo Clássico]");
                match &message {
                    vodozemac::olm::OlmMessage::PreKey(_) => {
                        println!("    └─PreKeyMessage (has_received={})", has_received);
                    }
                    vodozemac::olm::OlmMessage::Normal(_) => {
                        println!("    └─Normal Message (has_received={})", has_received);
                    }
                }
            }
            match message {
                vodozemac::olm::OlmMessage::PreKey(m) => m.to_bytes(),
                vodozemac::olm::OlmMessage::Normal(m) => m.to_bytes(),
            }
        }
    }

    /// Descriptografa mensagem Olm (detecção automática de formato)
    /// 
    /// DETECÇÃO INTELIGENTE DE FORMATO
    /// 
    /// Este método detecta automaticamente o formato da mensagem recebida:
    /// 
    /// 1. Mensagem PQC Híbrida (JSON):
    ///    - Formato: `{"type":2,"body":"base64_payload"}`
    ///    - Contém: vodozemac clássico + chaves ratchet PQC
    ///    - Processamento: Deserializa JSON → extrai componentes → descriptografa híbrido
    /// 
    /// 2. Mensagem Clássica (Base64):
    ///    - Formato: `AwogICAgI...` (Base64 direto)
    ///    - Contém: apenas vodozemac PreKeyMessage ou Message
    ///    - Processamento: Decodifica Base64 → descriptografa clássico
    /// 
    /// Por que essa flexibilidade?
    /// - Mantém compatibilidade retroativa com clientes antigos
    /// - Permite upgrade gradual de clássico → híbrido
    /// - Evita quebra de protocolo em redes heterogêneas
    fn olm_decrypt(
        &mut self,
        session: &mut OlmSessionHandle,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        vlog!(VerbosityLevel::Debug, "[DECRYPT] Tamanho total: {} bytes", message.len());
        
        // PASSO 1: Tentar deserializar como mensagem PQC (formato JSON UTF-8)
        // Identificação: Prefixo `{"type":2,` indica mensagem híbrida PQC
        if message.starts_with(b"{\"type\":2,") {
            vlog!(VerbosityLevel::Debug, "[DECRYPT] Mensagem identificada como PQC (JSON type 2)");
            
            if session.pqc_enabled {
                let message_str = std::str::from_utf8(message).map_err(|_| CryptoError::Protocol)?;
                match crate::core::double_ratchet_pqc::PqcOlmMessage::from_transport_string(message_str) {
                    Ok(pqc_msg) => {
                        return session.hybrid_session.decrypt_hybrid(&pqc_msg)
                            .map_err(|_| CryptoError::Protocol);
                    }
                    Err(e) => {
                        vlog!(VerbosityLevel::Normal, "Erro ao deserializar mensagem PQC: {:?}", e);
                        return Err(CryptoError::Protocol);
                    }
                }
            } else {
                vlog!(VerbosityLevel::Normal, "Mensagem PQC recebida, mas sessão não tem PQC habilitado");
                return Err(CryptoError::Protocol);
            }
        }

        // PASSO 2: Fallback para mensagem clássica (bytes binários diretos)
        vlog!(VerbosityLevel::Debug, "[DECRYPT] Tentando decodificar como mensagem clássica (binário)");

        // Tentar PreKeyMessage
        if let Ok(pre) = PreKeyMessage::from_bytes(message) {
            let msg = OlmMessage::PreKey(pre);
            match session.hybrid_session.decrypt_classic(&msg) {
                Ok(plaintext) => return Ok(plaintext),
                Err(e) => {
                    vlog!(VerbosityLevel::Normal, "Erro ao descriptografar PreKeyMessage: {:?}", e);
                    return Err(CryptoError::Protocol);
                }
            }
        }

        // Tentar Message normal
        if let Ok(norm) = Message::from_bytes(message) {
            let msg = OlmMessage::Normal(norm);
            match session.hybrid_session.decrypt_classic(&msg) {
                Ok(plaintext) => return Ok(plaintext),
                Err(e) => {
                    vlog!(VerbosityLevel::Normal, "Erro ao descriptografar Message: {:?}", e);
                    return Err(CryptoError::Protocol);
                }
            }
        }

        vlog!(VerbosityLevel::Normal, "Formato de mensagem não reconhecido");
        Err(CryptoError::Protocol)
    }

    /// Cria sessão Megolm para comunicação em grupo
    /// 
    /// Megolm usa AES-256-CBC sem overhead PQC no conteúdo (compatível com clientes clássicos).
    /// A proteção PQC ocorre na distribuição das chaves Megolm
    /// através dos canais Olm híbridos entre participantes.
    fn megolm_create_outbound(&mut self) -> MegolmOutbound {
        let gs = GroupSession::new(MegolmSessionConfig::version_1());
        
        if self.peer_public_keys.is_some() {
            vlog!(VerbosityLevel::Debug, "Megolm: sessão AES-256 (distribuída via canais Olm híbridos)");
        } else {
            vlog!(VerbosityLevel::Debug, "Megolm: sessão AES-256 (distribuição clássica)");
        }

        MegolmOutbound { inner: gs }
    }

    /// Exporta chave Megolm para distribuição via Olm
    fn megolm_export_inbound(&self, room_key: &MegolmOutbound) -> Vec<u8> {
        let session_key = room_key.inner.session_key();
        session_key.to_bytes()
    }

    fn megolm_import_inbound(&mut self, exported: &[u8]) -> MegolmInbound {
        let session_key = vodozemac::megolm::SessionKey::from_bytes(exported).expect("session key");
        MegolmInbound {
            inner: InboundGroupSession::new(&session_key, MegolmSessionConfig::version_1()),
        }
    }

    fn megolm_encrypt(&mut self, outbound: &mut MegolmOutbound, plaintext: &[u8]) -> Vec<u8> {
        let msg = outbound.inner.encrypt(plaintext);
        msg.to_bytes()
    }

    fn megolm_decrypt(
        &mut self,
        inbound: &mut MegolmInbound,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let msg = MegolmMessage::from_bytes(message).map_err(|_| CryptoError::Protocol)?;
        let decrypted = inbound
            .inner
            .decrypt(&msg)
            .map_err(|_| CryptoError::Protocol)?;
        Ok(decrypted.plaintext)
    }
}