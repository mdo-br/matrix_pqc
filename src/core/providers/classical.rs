// Provedor Criptográfico Clássico Matrix (Vodozemac Oficial)
//
// Wrapper sobre vodozemac implementando criptografia padrão Matrix/Olm:
//
// PRIMITIVAS CRIPTOGRÁFICAS:
// - Curve25519 (ECDH para acordo de chaves)
// - Ed25519 (assinatura digital de identidade)
// - AES-256-CBC com PKCS#7 padding (criptografia simétrica de mensagens)
// - HMAC-SHA-256 (autenticação de mensagens, 32 bytes ou 8 bytes truncado)
// - HKDF-SHA-256 (derivação de chaves criptográficas)
//
// PROTOCOLOS:
// - Double Ratchet (sigilo progressivo e recuperação de comprometimento)
//   * Avanço simétrico: mensagens consecutivas na mesma direção
//   * Avanço assimétrico: mudança de direção (novo DH exchange)
// - Megolm (criptografia de grupo eficiente)
//   * Ratchet unidirecional com chave de 128 bytes
//   * Derivação: HKDF-SHA-256 com info "MEGOLM_KEYS"
//   * Criptografia: AES-256-CBC + HMAC-SHA-256 (Encrypt-then-MAC)

use crate::core::crypto::*;
use crate::utils::logging::VerbosityLevel;
use crate::vlog;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use vodozemac::{
    olm::{Account, SessionConfig, PreKeyMessage, Message, OlmMessage},
    megolm::{GroupSession, InboundGroupSession, MegolmMessage, SessionConfig as MegolmSessionConfig},
    Curve25519PublicKey,
};

/// Provedor criptográfico clássico (vodozemac oficial - sem extensões PQC)
/// 
/// Implementa o protocolo Matrix/Olm padrão conforme especificação:
/// - Olm Account: gerenciamento de chaves de identidade e one-time keys
/// - Olm Sessions: comunicação ponto-a-ponto com Double Ratchet
/// - Megolm: criptografia de grupo eficiente para salas (rooms)
pub struct VodoCrypto {
    account: Account,
}

impl CryptoProvider for VodoCrypto {
    fn account_new() -> Self {
        Self { account: Account::new() }
    }

    /// Exporta chaves de identidade do account Olm
    /// 
    /// Retorna:
    /// - curve25519: Chave pública ECDH (acordo de chaves Diffie-Hellman)
    /// - ed25519: Chave pública de assinatura (identidade verificável)
    /// - kem_pub_opt: None (modo clássico não usa KEM pós-quântico)
    fn upload_identity_keys(&self) -> IdentityKeysExport {
        let id = self.account.identity_keys();
        IdentityKeysExport {
            curve25519: id.curve25519.to_base64(),
            ed25519: id.ed25519.to_base64(),
            kem_pub_opt: None,
        }
    }

    /// Gera one-time keys Curve25519 para estabelecimento de sessões
    /// 
    /// One-time keys são usadas no protocolo X3DH (Extended Triple Diffie-Hellman):
    /// - Cada OTK só pode ser usada uma vez (garantia de Perfect Forward Secrecy)
    /// - Combinadas com identity keys e ephemeral keys no handshake inicial
    /// - Após uso, devem ser marcadas como publicadas via mark_keys_published()
    fn generate_one_time_keys(&mut self, count: usize) -> Vec<OneTimeKeyExport> {
        self.account.generate_one_time_keys(count);
        let map = self.account.one_time_keys();
        map.iter().map(|(k, v)| {
            OneTimeKeyExport { key_id: format!("{:?}", k), curve25519: v.to_base64() }
        }).collect()
    }

    /// Marca one-time keys como publicadas (consumidas)
    /// 
    /// Após upload para o servidor Matrix e uso em handshake, as OTKs devem ser
    /// removidas do account local para evitar reutilização (violaria PFS).
    fn mark_keys_published(&mut self) {
        self.account.mark_keys_as_published();
    }

    /// Cria sessão Olm outbound (iniciador da comunicação)
    /// 
    /// Implementa X3DH (Extended Triple Diffie-Hellman) clássico:
    /// 1. DH1 = nossa_identity_key × their_identity_key
    /// 2. DH2 = nossa_ephemeral_key × their_identity_key  
    /// 3. DH3 = nossa_ephemeral_key × their_one_time_key
    /// 4. shared_secret = HKDF(DH1 || DH2 || DH3)
    /// 
    /// A sessão resultante usa SessionConfig::version_2 (formato atual do Olm).
    /// Retorna None no segundo campo (modo clássico não gera PQXDH init_message).
    fn create_outbound_session(
        &mut self,
        their_curve25519: &str,
        their_one_time_key: &str,
    ) -> Result<(OlmSessionHandle, Option<crate::core::pqxdh::MatrixPqxdhInitMessage>), CryptoError> {
        let id_key = Curve25519PublicKey::from_base64(their_curve25519).map_err(|_| CryptoError::KeyFormat)?;
        let otk = Curve25519PublicKey::from_base64(their_one_time_key).map_err(|_| CryptoError::KeyFormat)?;
        let sess = self.account.create_outbound_session(SessionConfig::version_2(), id_key, otk);
        let hybrid_session = crate::core::double_ratchet_pqc::HybridOlmSession::from_vodozemac(sess);
        Ok((
            OlmSessionHandle { 
                hybrid_session,
                pqc_enabled: false,
                kem_algorithm: None,
            },
            None // Modo clássico não gera init_message
        ))
    }

    /// Cria sessão Olm inbound a partir de PreKeyMessage (receptor)
    /// 
    /// Processa a PreKeyMessage recebida do iniciador:
    /// 1. Extrai chave efêmera e identity key do remetente
    /// 2. Reconstrói o mesmo shared_secret via X3DH reverso
    /// 3. Inicializa Double Ratchet com estado sincronizado
    /// 4. Descriptografa o plaintext embutido na PreKeyMessage
    /// 
    /// Retorna a sessão estabelecida + plaintext da primeira mensagem.
    fn create_inbound_session(
        &mut self,
        _their_curve25519: &str,
        prekey_message_b64: &str,
    ) -> Result<(OlmSessionHandle, Vec<u8>), CryptoError> {
        let raw = B64.decode(prekey_message_b64).map_err(|_| CryptoError::B64)?;
        let prekey = PreKeyMessage::from_bytes(&raw).map_err(|_| CryptoError::Protocol)?;
        let their_identity_key = prekey.identity_key();
        let creation_result = self.account.create_inbound_session(their_identity_key, &prekey)
            .map_err(|_| CryptoError::Protocol)?;
        let hybrid_session = crate::core::double_ratchet_pqc::HybridOlmSession::from_vodozemac(creation_result.session);
        Ok((OlmSessionHandle { 
            hybrid_session, 
            pqc_enabled: false, 
            kem_algorithm: None 
        }, creation_result.plaintext))
    }

    /// Criptografa mensagem Olm usando Double Ratchet clássico
    /// 
    /// DOUBLE RATCHET - Tipos de mensagem:
    /// - PreKeyMessage: Primeira mensagem ou quando session está unidirecional
    ///   * Contém ratchet_key pública para estabelecer/reestabelecer sincronização
    ///   * Permite que receptor crie inbound session ou avance seu ratchet
    /// 
    /// - Normal Message: Mensagens subsequentes após Double Ratchet estabelecido
    ///   * Apenas ciphertext + MAC (sem overhead de chaves públicas)
    ///   * Usa message_key derivada da chain_key atual
    /// 
    /// ESTADOS DO RATCHET:
    /// - Avanço simétrico: mensagens consecutivas na mesma direção (só avança chain_key)
    /// - Avanço assimétrico: mudança de direção (novo DH, regenera root_key e chain_key)
    /// 
    /// CRIPTOGRAFIA:
    /// - AES-256-CBC com PKCS#7 padding (plaintext)
    /// - HMAC-SHA-256 (autenticação do ciphertext)
    /// - Encrypt-then-MAC (ordem segura)
    fn olm_encrypt(&mut self, session: &mut OlmSessionHandle, plaintext: &[u8]) -> String {
        // Verificar estado antes de encrypt
        let has_received_before = session.hybrid_session.has_received_message_classic();
        
        let message = session.hybrid_session.encrypt_classic(plaintext);
        
        // Log detalhado do tipo de mensagem e estado do Double Ratchet
        match &message {
            OlmMessage::PreKey(_) => {
                vlog!(VerbosityLevel::Debug, "  [DOUBLE RATCHET CLÁSSICO] PreKeyMessage gerada");
                vlog!(VerbosityLevel::Debug, "    └─Estado: has_received={} (primeira mensagem ou session unidirecional)", has_received_before);
            }
            OlmMessage::Normal(_) => {
                vlog!(VerbosityLevel::Debug, "  [DOUBLE RATCHET CLÁSSICO] Normal Message");
                vlog!(VerbosityLevel::Debug, "    └─Estado: has_received={} (Double Ratchet estabelecido)", has_received_before);
            }
        }
        
        match message {
            OlmMessage::PreKey(m) => B64.encode(&m.to_bytes()),
            OlmMessage::Normal(m) => B64.encode(&m.to_bytes()),
        }
    }

    /// Descriptografa mensagem Olm usando Double Ratchet clássico
    /// 
    /// PROCESSAMENTO POR TIPO:
    /// 
    /// PreKeyMessage:
    /// - Primeira mensagem recebida ou reestabelecimento de sincronização
    /// - Extrai ratchet_key do remetente e avança nosso ratchet (avanço assimétrico)
    /// - Deriva novas root_key e chain_key via DH(our_ratchet_key, their_ratchet_key)
    /// - Descriptografa com message_key derivada da nova chain_key
    /// 
    /// Normal Message:
    /// - Mensagens regulares após ratchet estabelecido
    /// - Detecta se é avanço assimétrico (nova ratchet_key) ou simétrico (mesma direção)
    /// - Avanço assimétrico: regenera root_key via DH, inicia nova sending chain
    /// - Avanço simétrico: apenas avança chain_key via HMAC-SHA-256
    /// 
    /// VERIFICAÇÃO:
    /// - HMAC-SHA-256 verificado antes da descriptografia (MAC-then-Decrypt)
    /// - Falha de MAC → rejeita mensagem (proteção contra adulteração)
    fn olm_decrypt(&mut self, session: &mut OlmSessionHandle, message_b64: &str) -> Result<Vec<u8>, CryptoError> {
        let raw = B64.decode(message_b64).map_err(|_| CryptoError::B64)?;
        if let Ok(pre) = PreKeyMessage::from_bytes(&raw) {
            vlog!(VerbosityLevel::Debug, "  [DOUBLE RATCHET CLÁSSICO] Recebendo PreKeyMessage");
            vlog!(VerbosityLevel::Debug, "    └─Criando inbound session e processando primeira mensagem");
            let msg = OlmMessage::PreKey(pre);
            return session.hybrid_session.decrypt_classic(&msg).map_err(|_| CryptoError::Protocol);
        }
        if let Ok(norm) = Message::from_bytes(&raw) {
            let had_received_before = session.hybrid_session.has_received_message_classic();
            vlog!(VerbosityLevel::Debug, "  [DOUBLE RATCHET CLÁSSICO] Recebendo Normal Message");
            if !had_received_before {
                vlog!(VerbosityLevel::Debug, "    └─AVANÇO ASSIMÉTRICO: Nova ratchet_key do peer detectada");
            } else {
                vlog!(VerbosityLevel::Debug, "    └─Mensagem consecutiva na mesma direção");
            }
            let msg = OlmMessage::Normal(norm);
            return session.hybrid_session.decrypt_classic(&msg).map_err(|_| CryptoError::Protocol);
        }
        Err(CryptoError::Protocol)
    }

    /// Cria sessão Megolm outbound para criptografia de grupo
    /// 
    /// MEGOLM RATCHET:
    /// - Ratchet unidirecional (apenas sender avança, receivers usam snapshot)
    /// - Chave de 128 bytes avançada via hash ratchet (não usa DH como Olm)
    /// - Cada avanço: HMAC-SHA-256(ratchet_data, counter) + truncate
    /// - Eficiente para broadcast: um ratchet state, múltiplos receivers
    /// 
    /// DERIVAÇÃO DE MESSAGE KEYS:
    /// - HKDF-SHA-256 com info "MEGOLM_KEYS" a partir do ratchet state (128B)
    /// - Deriva: AES-256 key (32B) + MAC key (32B) + IV (16B)
    /// 
    /// VERSÃO: SessionConfig::version_1 (formato estável do Megolm)
    fn megolm_create_outbound(&mut self) -> MegolmOutbound {
        MegolmOutbound { inner: GroupSession::new(MegolmSessionConfig::version_1()) }
    }

    /// Exporta chave de sessão Megolm para distribuição via Olm
    /// 
    /// SESSION KEY EXPORT:
    /// - Serializa ratchet state atual (128 bytes) + index
    /// - Base64 encoded para transporte seguro via canal Olm
    /// - Permite que receptores criem InboundGroupSession sincronizado
    /// 
    /// DISTRIBUIÇÃO SEGURA:
    /// - Session key enviada via Olm session criptografada (ponto-a-ponto)
    /// - Cada membro recebe sua própria cópia via canal Olm individual
    /// - Garante que apenas membros autorizados possam descriptografar mensagens da sala
    fn megolm_export_inbound(&self, room_key: &MegolmOutbound) -> String {
        let session_key = room_key.inner.session_key();
        B64.encode(&session_key.to_bytes())
    }

    /// Importa chave de sessão Megolm para descriptografia de grupo
    /// 
    /// INBOUND GROUP SESSION:
    /// - Deserializa session key recebida via Olm
    /// - Inicializa ratchet state para descriptografia de mensagens
    /// - Permite avançar ratchet forward até o index correto da mensagem
    /// 
    /// PROPRIEDADES:
    /// - Ratchet forward-only: pode avançar mas não retroceder (segurança)
    /// - Out-of-order: mensagens podem chegar fora de ordem (ratchet avança conforme needed)
    /// - Mesma session key permite descriptografar todas mensagens futuras da sessão
    fn megolm_import_inbound(&mut self, exported_b64: &str) -> MegolmInbound {
        let raw = B64.decode(exported_b64).expect("b64");
        let session_key = vodozemac::megolm::SessionKey::from_bytes(&raw).expect("session key");
        MegolmInbound {
            inner: InboundGroupSession::new(&session_key, MegolmSessionConfig::version_1()),
        }
    }

    /// Criptografa mensagem de grupo usando Megolm
    /// 
    /// PROCESSO DE CRIPTOGRAFIA:
    /// 1. Avança ratchet state (incrementa counter interno)
    /// 2. Deriva message_key via HKDF-SHA-256("MEGOLM_KEYS", ratchet_state)
    /// 3. Extrai: AES-256 key (32B), MAC key (32B), IV (16B)
    /// 4. Criptografa: AES-256-CBC com PKCS#7 padding
    /// 5. Autentica: HMAC-SHA-256 (Encrypt-then-MAC)
    /// 6. Serializa: [version|index|ciphertext|mac_truncated(8B)]
    /// 
    /// FORMATO DA MENSAGEM:
    /// - Version byte: protocolo Megolm (compatibilidade)
    /// - Message index: posição no ratchet (permite out-of-order decryption)
    /// - Ciphertext: AES-256-CBC(plaintext)
    /// - MAC: HMAC-SHA-256 truncado (primeiros 8 bytes)
    fn megolm_encrypt(&mut self, outbound: &mut MegolmOutbound, plaintext: &[u8]) -> String {
        let msg = outbound.inner.encrypt(plaintext);
        B64.encode(msg.to_bytes())
    }

    /// Descriptografa mensagem de grupo usando estado Megolm inbound
    /// 
    /// PROCESSO DE DESCRIPTOGRAFIA:
    /// 1. Deserializa mensagem: extrai version, index, ciphertext, mac
    /// 2. Avança ratchet até o index correto (permite mensagens out-of-order)
    /// 3. Deriva message_key via HKDF-SHA-256 no estado do index
    /// 4. Verifica MAC truncado (8 bytes) - rejeita se inválido
    /// 5. Descriptografa: AES-256-CBC com PKCS#7 unpadding
    /// 6. Retorna plaintext original
    /// 
    /// TRATAMENTO DE MENSAGENS FORA DE ORDEM:
    /// - Ratchet forward-only: avança até index necessário
    /// - Não retrocede: mensagens antigas podem ser perdidas se ratchet já avançou
    /// - Cache interno pode manter alguns estados antigos (implementação específica)
    fn megolm_decrypt(&mut self, inbound: &mut MegolmInbound, message_b64: &str) -> Result<Vec<u8>, CryptoError> {
        let raw = B64.decode(message_b64).map_err(|_| CryptoError::B64)?;
        let msg = MegolmMessage::from_bytes(&raw).map_err(|_| CryptoError::Protocol)?;
        let decrypted = inbound.inner.decrypt(&msg).map_err(|_| CryptoError::Protocol)?;
        Ok(decrypted.plaintext)
    }
}
