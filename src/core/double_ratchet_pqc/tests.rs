use crate::core::crypto::KemAlgorithm;
use crate::utils::logging::VerbosityLevel;
use crate::vlog;
use super::keys::{PqcRatchetKeyPair, PqcRatchetPublicKey};
use super::state::PqcDoubleRatchetState;

#[test]
fn test_pqc_ratchet_keypair_generation() {
    for algorithm in [
        KemAlgorithm::Kyber512,
        KemAlgorithm::Kyber768,
        KemAlgorithm::Kyber1024,
    ] {
        let keypair = PqcRatchetKeyPair::generate(algorithm);
        let public_keys = keypair.public_keys();
        assert_eq!(public_keys.kem_algorithm, algorithm);
        assert_eq!(public_keys.curve25519_key.as_bytes().len(), 32);
        vlog!(
            VerbosityLevel::Normal,
            "SUCESSO: Geração de chaves híbridas com {}: OK ({}B)",
            algorithm.name(),
            public_keys.size_bytes()
        );
    }
}

#[test]
fn test_pqc_ratchet_serialization() {
    let keypair = PqcRatchetKeyPair::generate(KemAlgorithm::Kyber1024);
    let public_keys = keypair.public_keys();
    let b64 = public_keys.to_base64();
    let recovered = PqcRatchetPublicKey::from_base64(&b64).unwrap();
    assert_eq!(
        public_keys.curve25519_key.to_base64(),
        recovered.curve25519_key.to_base64()
    );
    assert_eq!(public_keys.kem_algorithm, recovered.kem_algorithm);
    vlog!(
        VerbosityLevel::Normal,
        "SUCESSO: Serialização de chaves PQC: OK ({}B)",
        b64.len()
    );
}

#[test]
fn test_double_ratchet_advancement() {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"test-initial-root-key");
    let initial_root = hasher.finalize().into();
    let mut ratchet =
        PqcDoubleRatchetState::new(initial_root, KemAlgorithm::Kyber1024, true);

    let peer_keypair = PqcRatchetKeyPair::generate(KemAlgorithm::Kyber1024);
    let peer_keys = peer_keypair.public_keys();
    ratchet.set_peer_ratchet_key(peer_keys.clone());

    let (chain_key1, _kem_ct1) = ratchet.advance_sending_ratchet_with_kem().unwrap();

    let new_peer_keypair = PqcRatchetKeyPair::generate(KemAlgorithm::Kyber1024);
    let our_keypair = PqcRatchetKeyPair::generate(KemAlgorithm::Kyber1024);
    let (_, kem_ct2) = new_peer_keypair
        .hybrid_dh_with_kem(&our_keypair.public_keys())
        .unwrap();

    let chain_key2 = ratchet
        .advance_receiving_ratchet_with_decapsulate(
            &new_peer_keypair.public_keys(),
            Some(&kem_ct2),
        )
        .unwrap();

    assert_ne!(chain_key1, chain_key2);
    assert_ne!(chain_key1, initial_root);
    vlog!(VerbosityLevel::Debug, "SUCESSO: Avanço do Double Ratchet PQC: OK");
}

#[test]
fn test_new_state_machine() {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"test-state-machine-root");
    let initial_root: [u8; 32] = hasher.finalize().into();

    let mut alice_ratchet =
        PqcDoubleRatchetState::new(initial_root, KemAlgorithm::Kyber1024, true);
    let mut bob_ratchet =
        PqcDoubleRatchetState::new(initial_root, KemAlgorithm::Kyber1024, false);

    let alice_keypair = PqcRatchetKeyPair::generate(KemAlgorithm::Kyber1024);
    let alice_pub = alice_keypair.public_keys();

    bob_ratchet.set_peer_ratchet_key(alice_pub.clone());
    let (bob_chain_key, bob_kem_ct) =
        bob_ratchet.advance_sending_ratchet_with_kem().unwrap();

    let bob_keypair = PqcRatchetKeyPair::generate(KemAlgorithm::Kyber1024);
    let bob_pub = bob_keypair.public_keys();

    alice_ratchet.set_peer_ratchet_key(bob_pub.clone());
    let alice_recv_key = alice_ratchet
        .advance_receiving_ratchet_with_decapsulate(&bob_pub, bob_kem_ct.as_deref())
        .unwrap();

    let (alice_chain_key2, _alice_kem_ct) =
        alice_ratchet.advance_sending_ratchet_with_kem().unwrap();

    assert_ne!(
        bob_chain_key, alice_recv_key,
        "Chaves de diferentes operações devem ser diferentes"
    );
    assert_ne!(
        alice_recv_key, alice_chain_key2,
        "Recepção e envio devem ter chaves diferentes"
    );
    vlog!(
        VerbosityLevel::Normal,
        "SUCESSO: Teste do sistema de estados concluído!"
    );
}

#[test]
fn test_integrity_verification() {
    let keypair = PqcRatchetKeyPair::generate(KemAlgorithm::Kyber1024);
    let public_keys = keypair.public_keys();
    assert_eq!(public_keys.curve25519_key.as_bytes().len(), 32);
    assert!(public_keys.kem_public_key.size_bytes() > 1000);

    let serialized = public_keys.to_base64();
    let recovered = PqcRatchetPublicKey::from_base64(&serialized).unwrap();
    assert_eq!(
        public_keys.curve25519_key.as_bytes(),
        recovered.curve25519_key.as_bytes()
    );
    assert_eq!(public_keys.kem_algorithm, recovered.kem_algorithm);
    vlog!(VerbosityLevel::Normal, "SUCESSO: Verificação de integridade: OK");
}
