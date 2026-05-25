//! PQXDH protocol functions: `init_pqxdh`, `complete_pqxdh`, and key derivation.

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

/// Initiates a PQXDH key agreement (initiator side).
///
/// Verifies the responder's prekey signatures, generates an ephemeral X25519 key,
/// encapsulates the Kyber-1024 prekey, performs 3–4 DH exchanges, and derives a
/// session key via HKDF-SHA-256 with all public keys bound as associated data.
/// Uses `OsRng` for the ephemeral key.
pub fn init_pqxdh(alice: &MatrixUser, bob_public_keys: &serde_json::Value) -> Result<MatrixPqxdhOutput> {
    init_pqxdh_with_rng(alice, bob_public_keys, &mut OsRng)
}

/// Initiates a PQXDH key agreement with a caller-supplied RNG.
///
/// Prefer [`init_pqxdh`] in production. This variant exists for deterministic testing.
pub fn init_pqxdh_with_rng<R: CryptoRng + RngCore>(
    alice: &MatrixUser,
    bob_public_keys: &serde_json::Value,
    rng: &mut R,
) -> Result<MatrixPqxdhOutput> {
    // Parse Bob's public key bundle. The vodozemac model uses two independent keys:
    // - Ed25519 signing key (signature verification only)
    // - Curve25519 DH key (DH operations only)

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

        // Verify cross-signature: Ed25519 signing key signs the Curve25519 DH key.
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

        // Verify Ed25519 signature over the X25519 prekey.
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

        // Verify Ed25519 signature over the Kyber prekey.
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

    // Select one of Bob's one-time keys, if any are available.
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

    // Generate ephemeral X25519 key pair.
    let ephemeral_private = X25519ReusableSecret::random_from_rng(&mut *rng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_private);

    // Encapsulate against Bob's Kyber prekey.
    // Note: pqcrypto-kyber returns (SharedSecret, Ciphertext), not (Ciphertext, SharedSecret).
    let (shared_secret_kyber, ciphertext) = kyber1024::encapsulate(&bob_kyber_prekey);

    let bob_identity_x25519 = bob_identity_key;

    // DH exchanges (3 or 4 depending on OTK availability).
    let dh1 = alice.diffie_hellman_key.diffie_hellman(&bob_x25519_prekey);
    let dh2 = ephemeral_private.diffie_hellman(&bob_identity_x25519);
    let dh3 = ephemeral_private.diffie_hellman(&bob_x25519_prekey);
    let dh4 = bob_one_time_key.map(|otk| ephemeral_private.diffie_hellman(&otk));

    // Derive session key via HKDF-SHA-256. All public keys are included as associated data
    // to prevent Key Compromise Impersonation (KCI) attacks.
    let session_key = matrix_pqxdh_kdf(
        // Shared secrets (DH + KEM)
        dh1.as_bytes(),
        dh2.as_bytes(),
        dh3.as_bytes(),
        dh4.as_ref().map(|dh| dh.as_bytes() as &[u8]),
        shared_secret_kyber.as_bytes(),
        // Associated data — public key binding
        alice.dh_public_key.as_bytes(),
        bob_identity_key.as_bytes(),
        bob_x25519_prekey.as_bytes(),
        bob_kyber_prekey.as_bytes(),
        bob_one_time_key.as_ref().map(|otk| otk.as_bytes() as &[u8]),
        ephemeral_public.as_bytes(),
        // Matrix context
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

/// Completes a PQXDH key agreement (responder side).
///
/// Validates the initiator's cross-signature, decapsulates the Kyber ciphertext,
/// performs the matching 3–4 DH exchanges, and derives the same session key as the
/// initiator. Consumes the one-time key if one was used, ensuring it cannot be reused.
pub fn complete_pqxdh(bob: &mut MatrixUser, init_message: &MatrixPqxdhInitMessage) -> Result<[u8; 32]> {
    // Parse Alice's Ed25519 signing key.
    let alice_signing_key = VerifyingKey::from_bytes(&init_message.sender_signing_key)?;

    // Parse Alice's independent Curve25519 DH key.
    let alice_dh_public_key = X25519PublicKey::from(init_message.sender_dh_public_key);

    // Verify cross-signature: Alice's Ed25519 key must have signed her Curve25519 DH key.
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

    // Parse the ephemeral key.
    let ephemeral_key = X25519PublicKey::from(init_message.ephemeral_key);

    // Retrieve the OTK public key before consuming it (needed for the KDF).
    let bob_otk_bytes = init_message
        .used_one_time_key_id
        .as_ref()
        .and_then(|otk_id| bob.get_one_time_key_public(otk_id));

    // Consume the one-time key private key if one was used.
    let otk_private = if let Some(ref otk_id) = init_message.used_one_time_key_id {
        bob.consume_one_time_key(otk_id)
    } else {
        None
    };

    // Decapsulate the Kyber ciphertext.
    let ciphertext = KyberCiphertext::from_bytes(&init_message.kyber_ciphertext)
        .map_err(|_| anyhow::anyhow!("Invalid Kyber ciphertext"))?;

    let shared_secret_kyber = kyber1024::decapsulate(&ciphertext, &bob.kyber_prekey_private);

    // DH exchanges — mirror the initiator's order exactly.
    let dh1 = bob.x25519_prekey_private.diffie_hellman(&alice_dh_public_key);
    let dh2 = bob.diffie_hellman_key.diffie_hellman(&ephemeral_key);
    let dh3 = bob.x25519_prekey_private.diffie_hellman(&ephemeral_key);
    let dh4 = otk_private
        .as_ref()
        .map(|otk| otk.diffie_hellman(&ephemeral_key));

    let session_key = matrix_pqxdh_kdf(
        // Shared secrets
        dh1.as_bytes(),
        dh2.as_bytes(),
        dh3.as_bytes(),
        dh4.as_ref().map(|dh| dh.as_bytes() as &[u8]),
        shared_secret_kyber.as_bytes(),
        // Associated data — public key binding
        alice_dh_public_key.as_bytes(),
        bob.dh_public_key.as_bytes(),
        &bob.x25519_prekey.public_key,
        &bob.kyber_prekey.public_key,
        bob_otk_bytes.as_ref().map(|b| b.as_slice()),
        ephemeral_key.as_bytes(),
        // Matrix context
        &init_message.sender_user_id,
        &bob.user_id,
    );

    Ok(session_key)
}

/// Derives a 32-byte session key from PQXDH shared secrets using HKDF-SHA-256.
///
/// Concatenates all DH and KEM shared secrets as IKM, prefixed with a 32-byte
/// Curve25519 domain separator (`0xFF × 32`). All public keys and the Matrix user
/// IDs are included in the HKDF info field as associated data, binding every
/// participant's public material and preventing Key Compromise Impersonation (KCI).
fn matrix_pqxdh_kdf(
    // Shared secrets
    dh1: &[u8],
    dh2: &[u8],
    dh3: &[u8],
    dh4: Option<&[u8]>,
    kyber_ss: &[u8],
    // Associated data (public keys)
    alice_identity: &[u8],
    bob_identity: &[u8],
    bob_x25519_prekey: &[u8],
    bob_kyber_prekey: &[u8],
    bob_one_time_key: Option<&[u8]>,
    ephemeral_key: &[u8],
    // Matrix context
    alice_user_id: &str,
    bob_user_id: &str,
) -> [u8; 32] {
    // 1. Build IKM: domain separator + DH secrets + KEM secret.
    let mut ikm = Vec::new();
    ikm.extend_from_slice(&[0xffu8; 32]); // Curve25519 domain separator
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    if let Some(dh4_bytes) = dh4 {
        ikm.extend_from_slice(dh4_bytes);
    }
    ikm.extend_from_slice(kyber_ss);

    // 2. Build HKDF info: domain label + all public keys + user IDs.
    let mut info = Vec::new();
    info.extend_from_slice(b"MATRIX_PQXDH_KDF_v1");
    info.extend_from_slice(alice_identity);
    info.extend_from_slice(bob_identity);
    info.extend_from_slice(bob_x25519_prekey);
    info.extend_from_slice(bob_kyber_prekey);
    if let Some(otk) = bob_one_time_key {
        info.extend_from_slice(otk);
    }
    info.extend_from_slice(ephemeral_key);
    let context = format!("{}|{}", alice_user_id, bob_user_id);
    info.extend_from_slice(context.as_bytes());

    // 3. HKDF-SHA-256 extract-then-expand (RFC 5869).
    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut output = [0u8; 32];
    hkdf.expand(&info, &mut output)
        .expect("HKDF-SHA-256 expand failed - info too long");

    output
}
