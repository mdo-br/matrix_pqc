// Tipo de mensagem híbrida PQC (PqcOlmMessage) com serialização Matrix-compatível

use crate::core::crypto::CryptoError;
use vodozemac::olm::{OlmMessage, Message, PreKeyMessage};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crate::utils::logging::VerbosityLevel;
use crate::vlog;
use super::keys::PqcRatchetPublicKey;

/// Mensagem Olm híbrida com componentes PQC adicionais
///
/// Wrapper sobre vodozemac OlmMessage que adiciona campos necessários para
/// o Double Ratchet PQC, mantendo compatibilidade com o protocolo Matrix.
///
/// # Estrutura (Hybrid Layer)
/// - `classic_component`: OlmMessage vodozemac (PreKeyMessage ou Normal Message)
/// - `ratchet_key`: Chave pública híbrida atual (Curve25519 + Kyber) — enviada em TODAS
/// - `kem_ciphertext`: Ciphertext KEM (~768-1568B) — presente APENAS em avanços assimétricos
/// - `pqc_enabled`: Flag de capacidades PQC ativas
/// - `message_index`: Contador para verificação de ordem
///
/// # Serialização JSON Matrix-Compatível
/// Formato: `{"type":2,"body":"base64_payload"}`
///
/// Payload binário interno:
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
/// - Avanço assimétrico: ~800–1600 bytes (ratchet_key + kem_ciphertext completo)
#[derive(Clone)]
pub struct PqcOlmMessage {
    /// Mensagem vodozemac clássica (base)
    pub classic_component: OlmMessage,
    /// Nova chave pública de ratchet (se ratchet avançou)
    pub ratchet_key: Option<PqcRatchetPublicKey>,
    /// Ciphertext KEM (CRÍTICO para KEM real)
    /// Contém o resultado de encapsulate() que o receptor usa para decapsulate()
    /// SEM isso o KEM não funciona — Alice e Bob teriam shared secrets diferentes
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

    /// Serializa mensagem híbrida para JSON Matrix-compatível
    ///
    /// Formato: `{"type":2,"body":"base64_payload"}`
    ///
    /// O JSON é necessário para evitar dupla codificação Base64:
    /// com JSON, apenas UMA camada de Base64 cobre o payload completo.
    pub fn to_transport_string(&self) -> String {
        let (classic_type, classic_bytes) = match &self.classic_component {
            OlmMessage::PreKey(m) => (0u8, m.to_bytes()),
            OlmMessage::Normal(m) => (1u8, m.to_bytes()),
        };

        let mut payload = Vec::new();

        // 1. Versão PQC
        payload.push(1u8);

        // 2. Tipo de mensagem clássica
        payload.push(classic_type);

        // 3. Tamanho e dados da mensagem clássica
        payload.extend_from_slice(&(classic_bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(&classic_bytes);

        // 4. Metadata PQC
        payload.extend_from_slice(&self.message_index.to_le_bytes());
        let pqc_enabled_byte = if self.pqc_enabled { 1 } else { 0 };
        vlog!(
            VerbosityLevel::Debug,
            "[SERIALIZE] pqc_enabled={}, byte={}, ratchet_key.is_some()={}",
            self.pqc_enabled,
            pqc_enabled_byte,
            self.ratchet_key.is_some()
        );
        payload.push(pqc_enabled_byte);

        // 5. Chave de ratchet PQC (se disponível)
        if let Some(ref ratchet_key) = self.ratchet_key {
            let ratchet_bytes = ratchet_key.to_bytes();
            payload.extend_from_slice(&(ratchet_bytes.len() as u32).to_le_bytes());
            payload.extend_from_slice(&ratchet_bytes);
        } else {
            payload.extend_from_slice(&0u32.to_le_bytes());
        }

        // 6. Ciphertext KEM (só presente em avanços assimétricos)
        if let Some(ref kem_ct) = self.kem_ciphertext {
            payload.extend_from_slice(&(kem_ct.len() as u32).to_le_bytes());
            payload.extend_from_slice(kem_ct);
            vlog!(
                VerbosityLevel::Debug,
                "[SERIALIZE] Incluindo KEM ciphertext ({} bytes)",
                kem_ct.len()
            );
        } else {
            payload.extend_from_slice(&0u32.to_le_bytes());
        }

        let body_b64 = B64.encode(&payload);
        vlog!(
            VerbosityLevel::Debug,
            "[SERIALIZE] Payload total: {} bytes",
            payload.len()
        );

        format!(r#"{{"type":2,"body":"{}"}}"#, body_b64)
    }

    /// Reconstrói mensagem híbrida do JSON Matrix
    pub fn from_transport_string(transport: &str) -> Result<Self, CryptoError> {
        let transport = transport.trim();
        if !transport.starts_with(r#"{"type":2,"#) {
            vlog!(
                VerbosityLevel::Debug,
                "[DESERIALIZE] Mensagem não começa com {{\"type\":2,"
            );
            return Err(CryptoError::Protocol);
        }

        let body_start = transport
            .find(r#""body":"#)
            .ok_or(CryptoError::Protocol)?
            + 8;
        let body_end = transport.rfind(r#""}"#).ok_or(CryptoError::Protocol)?;

        if body_start >= body_end {
            return Err(CryptoError::Protocol);
        }

        let body_b64 = &transport[body_start..body_end];
        let bytes = B64.decode(body_b64).map_err(|e| {
            vlog!(VerbosityLevel::Debug, "[DESERIALIZE] Erro Base64: {:?}", e);
            CryptoError::B64
        })?;

        if bytes.len() < 11 {
            return Err(CryptoError::Protocol);
        }

        let mut cursor = 0;

        // 1. Versão PQC
        let pqc_version = bytes[cursor];
        if pqc_version != 1 {
            return Err(CryptoError::Protocol);
        }
        cursor += 1;

        // 2. Tipo de mensagem clássica
        let classic_type = bytes[cursor];
        cursor += 1;

        // 3. Componente clássico
        let classic_size = u32::from_le_bytes(
            bytes[cursor..cursor + 4]
                .try_into()
                .map_err(|_| CryptoError::Protocol)?,
        ) as usize;
        cursor += 4;

        if cursor + classic_size > bytes.len() {
            return Err(CryptoError::Protocol);
        }

        let classic_bytes = &bytes[cursor..cursor + classic_size];
        cursor += classic_size;

        let classic_component = match classic_type {
            0 => OlmMessage::PreKey(
                PreKeyMessage::from_bytes(classic_bytes).map_err(|_| CryptoError::Protocol)?,
            ),
            1 => OlmMessage::Normal(
                Message::from_bytes(classic_bytes).map_err(|_| CryptoError::Protocol)?,
            ),
            _ => return Err(CryptoError::Protocol),
        };

        // 4. Metadata PQC
        if cursor + 5 > bytes.len() {
            return Err(CryptoError::Protocol);
        }

        let message_index = u32::from_le_bytes(
            bytes[cursor..cursor + 4]
                .try_into()
                .map_err(|_| CryptoError::Protocol)?,
        );
        cursor += 4;

        let pqc_enabled = bytes[cursor] != 0;
        cursor += 1;

        // 5. Chave de ratchet PQC
        if cursor + 4 > bytes.len() {
            return Err(CryptoError::Protocol);
        }

        let ratchet_key_size = u32::from_le_bytes(
            bytes[cursor..cursor + 4]
                .try_into()
                .map_err(|_| CryptoError::Protocol)?,
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
            None
        };

        // 6. Ciphertext KEM
        let kem_ciphertext = if cursor + 4 <= bytes.len() {
            let kem_ct_size = u32::from_le_bytes(
                bytes[cursor..cursor + 4]
                    .try_into()
                    .map_err(|_| CryptoError::Protocol)?,
            ) as usize;
            cursor += 4;

            if kem_ct_size > 0 {
                if cursor + kem_ct_size > bytes.len() {
                    return Err(CryptoError::Protocol);
                }
                let kem_ct = bytes[cursor..cursor + kem_ct_size].to_vec();
                vlog!(
                    VerbosityLevel::Debug,
                    "[DESERIALIZE] KEM ciphertext recuperado ({} bytes)",
                    kem_ct.len()
                );
                Some(kem_ct)
            } else {
                None
            }
        } else {
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
