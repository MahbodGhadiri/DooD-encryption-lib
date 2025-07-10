use rand::rngs::OsRng;
use rand::thread_rng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::xeddsa;

pub struct X3DHKeys {
    pub identity_key: xeddsa::PrivateKey,
    pub signed_pre_key: (StaticSecret, PublicKey, [u8; 64]),
    pub one_time_pre_keys: Vec<(StaticSecret, PublicKey)>,
}

impl X3DHKeys {
    pub fn new() -> X3DHKeys {
        let identity_key = generate_identity_key();
        Self {
            signed_pre_key: generate_signed_pre_key(&identity_key),
            identity_key,
            one_time_pre_keys: generate_one_time_pre_keys(),
        }
    }

    pub fn clone(&self) -> X3DHKeys {
        Self {
            signed_pre_key: self.signed_pre_key.clone(),
            identity_key: self.identity_key.clone(),
            one_time_pre_keys: self.one_time_pre_keys.clone(),
        }
    }
}

fn generate_identity_key() -> xeddsa::PrivateKey {
    xeddsa::PrivateKey::new(&mut thread_rng())
}

fn generate_signed_pre_key(
    identity_private_key: &xeddsa::PrivateKey,
) -> (StaticSecret, PublicKey, [u8; 64]) {
    let mut csprng = OsRng;
    let private_key = x25519_dalek::StaticSecret::random_from_rng(csprng);

    let public_key = x25519_dalek::PublicKey::from(&private_key);

    let signed_pre_key =
        identity_private_key.calculate_signature(&mut csprng, &[&public_key.to_bytes()]);

    return (private_key, public_key, signed_pre_key);
}

fn generate_one_time_pre_keys() -> Vec<(StaticSecret, PublicKey)> {
    let mut keys: Vec<(StaticSecret, PublicKey)> = Vec::new();
    for _ in 0..100 {
        let private_key = x25519_dalek::StaticSecret::random_from_rng(thread_rng());
        let public_key = x25519_dalek::PublicKey::from(&private_key);
        keys.push((private_key, public_key));
    }
    keys
}
