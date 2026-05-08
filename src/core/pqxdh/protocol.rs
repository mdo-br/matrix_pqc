// Funções de protocolo PQXDH: init_pqxdh, complete_pqxdh e derivação de chaves

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use x25519_dalek::{PublicKey as X25519PublicKey, ReusableSecret as X25519ReusableSecret};
use pqcrypto_kyber::kyber1024::{self, PublicKey as KyberPublicKey, Ciphertext as KyberCiphertext};
use pqcrypto_traits::kem::{PublicKey, Ciphertext, SharedSecret};
use hkdf::Hkdf;
use sha2::Sha256;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::{rngs::OsRng, CryptoRng, RngCore};
use crate::utils::logging::VerbosityLevel;
use crate::vlog;
use super::message::{MatrixPqxdhInitMessage, MatrixPqxdhOutput};
use super::user::MatrixUser;

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
    rng: &mut R,
) -> Result<MatrixPqxdhOutput> {
    // Analisar chaves públicas do Bob no modelo vodozemac
    // Bob possui duas chaves independentes:
    // - Ed25519 signing_key (para verificação de assinaturas)
    // - Curve25519 diffie_hellman_key (para operações DH)

    let bob_signing_key = {
        let key_b64 = bob_public_keys["keys"]["ed25519"]
            .as_str()
            .context("Missing Bob's signing key")?;
        let key_bytes = B64.decode(key_b64)?;
        VerifyingKey::from_bytes(
            &key_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid key length"))?,
        )?
    };

    let bob_identity_key = {
        let key_b64 = bob_public_keys["keys"]["curve25519"]
            .as_str()
            .context("Missing Bob's DH identity key")?;
        let key_bytes = B64.decode(key_b64)?;

        // Verificar cross-signature: Ed25519 assina Curve25519
        let sig_b64 = bob_public_keys["keys"]["curve25519_signature"]
            .as_str()
            .context("Missing DH key signature")?;
        let sig_bytes = B64.decode(sig_b64)?;
        let signature = Signature::from_bytes(
            &sig_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid signature"))?,
        );
        bob_signing_key.verify_strict(&key_bytes, &signature)?;

        let key_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid Curve25519 key length"))?;
        X25519PublicKey::from(key_array)
    };

    let bob_x25519_prekey = {
        let prekey_data = &bob_public_keys["prekeys"]["x25519"];
        let key_b64 = prekey_data["public_key"]
            .as_str()
            .context("Missing X25519 prekey")?;
        let sig_b64 = prekey_data["signature"]
            .as_str()
            .context("Missing X25519 signature")?;

        // Verificar assinatura (assinada pela signing_key Ed25519)
        let key_bytes = B64.decode(key_b64)?;
        let sig_bytes = B64.decode(sig_b64)?;
        let signature = Signature::from_bytes(
            &sig_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid signature"))?,
        );
        bob_signing_key.verify_strict(&key_bytes, &signature)?;

        let key_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid X25519 key length"))?;
        X25519PublicKey::from(key_array)
    };

    let bob_kyber_prekey = {
        let prekey_data = &bob_public_keys["prekeys"]["kyber1024"];
        let key_b64 = prekey_data["public_key"]
            .as_str()
            .context("Missing Kyber prekey")?;
        let sig_b64 = prekey_data["signature"]
            .as_str()
            .context("Missing Kyber signature")?;

        // Verificar assinatura (assinada pela signing_key Ed25519)
        let key_bytes = B64.decode(key_b64)?;
        let sig_bytes = B64.decode(sig_b64)?;
        let signature = Signature::from_bytes(
            &sig_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid signature"))?,
        );
        bob_signing_key.verify_strict(&key_bytes, &signature)?;

        KyberPublicKey::from_bytes(&key_bytes)
            .map_err(|_| anyhow::anyhow!("Invalid Kyber public key"))?
    };

    // Selecionar uma chave one-time do Bob (se disponível)
    let (bob_one_time_key, used_otk_id) = {
        let otk_map = &bob_public_keys["one_time_keys"]["curve25519"];
        if let Some(otk_map) = otk_map.as_object() {
            if let Some((key_id, key_value)) = otk_map.iter().next() {
                let key_b64 = key_value.as_str().context("Invalid OTK format")?;
                let key_bytes = B64.decode(key_b64)?;
                let key_array: [u8; 32] = key_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid OTK length"))?;
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
    let bob_identity_x25519 = bob_identity_key;

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
        alice.dh_public_key.as_bytes(),
        bob_identity_key.as_bytes(),
        bob_x25519_prekey.as_bytes(),
        bob_kyber_prekey.as_bytes(),
        bob_one_time_key.as_ref().map(|otk| otk.as_bytes() as &[u8]),
        ephemeral_public.as_bytes(),
        // Contexto Matrix
        &alice.user_id,
        bob_public_keys["user_id"]
            .as_str()
            .unwrap_or("@unknown:matrix.org"),
    );

    let init_message = MatrixPqxdhInitMessage {
        sender_user_id: alice.user_id.clone(),
        sender_signing_key: *alice.signing_public_key.as_bytes(),
        sender_dh_public_key: *alice.dh_public_key.as_bytes(),
        sender_dh_key_signature: alice.dh_key_signature.to_bytes(),
        ephemeral_key: *ephemeral_public.as_bytes(),
        kyber_ciphertext: ciphertext.as_bytes().to_vec(),
        used_x25519_prekey_id: bob_public_keys["prekeys"]["x25519"]["key_id"]
            .as_str()
            .unwrap_or("unknown")
            .to_string(),
        used_kyber_prekey_id: bob_public_keys["prekeys"]["kyber1024"]["key_id"]
            .as_str()
            .unwrap_or("unknown")
            .to_string(),
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
/// 1. Parsing e validação da chave de identidade do remetente
/// 2. Verificação da cross-signature (Ed25519 → Curve25519 binding)
/// 3. Parsing da chave efêmera X25519
/// 4. Consumo da chave one-time usada (se aplicável)
/// 5. Desencapsulamento do ciphertext Kyber
/// 6. Execução dos mesmos 3-4 acordos DH na ordem correta:
///    - DH1: bob.x25519_prekey_private × alice.diffie_hellman_key
///    - DH2: bob.diffie_hellman_key × alice.ephemeral
///    - DH3: bob.x25519_prekey_private × alice.ephemeral
///    - DH4: bob.otk × alice.ephemeral (opcional, se disponível)
/// 7. Derivação da mesma chave de sessão usando HKDF-SHA-256
///
/// # Parâmetros
/// * `bob` - Usuário destinatário completando o acordo
/// * `init_message` - Mensagem de inicialização recebida do remetente
///
/// # Retorno
/// Chave de sessão idêntica à derivada pelo remetente
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
    let alice_signing_key = VerifyingKey::from_bytes(&init_message.sender_signing_key)?;

    // Analisar chave DH de identidade da Alice (Curve25519 INDEPENDENTE)
    let alice_dh_public_key = X25519PublicKey::from(init_message.sender_dh_public_key);

    // VALIDAÇÃO: Verificar cross-signature da chave DH
    // A Alice deve ter assinado sua chave DH (Curve25519) com sua signing key (Ed25519)
    // Isso garante binding criptográfico entre as duas chaves de identidade
    let dh_signature = Signature::from_bytes(&init_message.sender_dh_key_signature);

    match alice_signing_key.verify_strict(alice_dh_public_key.as_bytes(), &dh_signature) {
        Ok(_) => {
            vlog!(VerbosityLevel::Debug, "[PQXDH] Cross-signature validada com sucesso");
            vlog!(
                VerbosityLevel::Verbose,
                "[PQXDH]   Ed25519 signing_key verificou assinatura da Curve25519 diffie_hellman_key"
            );
        }
        Err(e) => {
            vlog!(
                VerbosityLevel::Normal,
                "[PQXDH] FALHA na validacao de cross-signature: {:?}",
                e
            );
            return Err(anyhow::anyhow!(
                "Cross-signature validation failed: Alice's DH key not signed by her signing key"
            ));
        }
    }

    // Analisar chave efêmera
    let ephemeral_key = X25519PublicKey::from(init_message.ephemeral_key);

    // Obter OTK pública do storage ANTES de consumir (para o KDF)
    let bob_otk_bytes = init_message
        .used_one_time_key_id
        .as_ref()
        .and_then(|otk_id| bob.get_one_time_key_public(otk_id));

    // Lidar com chave one-time se usada (consumir a chave privada)
    let otk_private = if let Some(ref otk_id) = init_message.used_one_time_key_id {
        bob.consume_one_time_key(otk_id)
    } else {
        None
    };

    // Desencapsular ciphertext Kyber
    let ciphertext = KyberCiphertext::from_bytes(&init_message.kyber_ciphertext)
        .map_err(|_| anyhow::anyhow!("Invalid Kyber ciphertext"))?;

    let shared_secret_kyber = kyber1024::decapsulate(&ciphertext, &bob.kyber_prekey_private);

    // Realizar as trocas Diffie-Hellman (3 ou 4 dependendo do uso de OTK)
    let dh1 = bob.x25519_prekey_private.diffie_hellman(&alice_dh_public_key);
    let dh2 = bob.diffie_hellman_key.diffie_hellman(&ephemeral_key);
    let dh3 = bob.x25519_prekey_private.diffie_hellman(&ephemeral_key);
    let dh4 = otk_private
        .as_ref()
        .map(|otk| otk.diffie_hellman(&ephemeral_key));

    // Derivar chave de sessão com Associated Data completo
    let session_key = matrix_pqxdh_kdf(
        // Segredos compartilhados
        dh1.as_bytes(),
        dh2.as_bytes(),
        dh3.as_bytes(),
        dh4.as_ref().map(|dh| dh.as_bytes() as &[u8]),
        shared_secret_kyber.as_bytes(),
        // Associated Data - binding de chaves públicas
        alice_dh_public_key.as_bytes(),
        bob.dh_public_key.as_bytes(),
        &bob.x25519_prekey.public_key,
        &bob.kyber_prekey.public_key,
        bob_otk_bytes.as_ref().map(|b| b.as_slice()),
        ephemeral_key.as_bytes(),
        // Contexto Matrix
        &init_message.sender_user_id,
        &bob.user_id,
    );

    Ok(session_key)
}

/// Função de derivação de chaves PQXDH com Associated Data
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
/// 3. Associated Data como Info do HKDF
/// 4. Extração e expansão HKDF-SHA-256
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
    bob_user_id: &str,
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
