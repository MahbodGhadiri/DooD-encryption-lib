//! double ratchet algorithm based on signal specification
//! for more info visit https://signal.org/docs/specifications/x3dh/
//! using curve X25519
//! using sha512

use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::thread_rng;
use sha2::Sha512;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

use crate::double_ratchet::DHKeyPair;
use crate::xeddsa;

const INFO: &[u8] = b"DooD-encryption-lib";

pub struct X3DH {
    keys: X3DHKeys,
    mock_server_keys: X3DHKeys,
}

pub struct X3DHKeys {
    identity_key: xeddsa::PrivateKey,
    signed_pre_key: (StaticSecret, PublicKey, [u8; 64]),
    one_time_pre_keys: Vec<(StaticSecret, PublicKey)>,
}

pub struct X3DHInitializationOutput {
    pub alice_identity_pub: PublicKey,
    pub alice_dhs: DHKeyPair,
    pub bob_public_key: PublicKey,
    pub rk: [u8; 32],
    pub associated_data: Vec<u8>,
    pub bob_one_time_pre_key: Option<PublicKey>,
}

pub struct X3DHKeyBundle {
    identity_key: [u8; 32],
    signed_pre_key: PublicKey,
    signed_pre_key_signature: [u8; 64],
    one_time_pre_key: Option<PublicKey>,
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

impl X3DH {
    pub fn new() -> X3DH {
        let keys = X3DHKeys::new();
        Self {
            mock_server_keys: keys.clone(),
            keys,
        }
    }

    //TODO: this should be only used for server, no need on client side
    pub fn get_key_bundle(&mut self) -> X3DHKeyBundle {
        println!("{}", self.mock_server_keys.one_time_pre_keys.len());
        X3DHKeyBundle {
            identity_key: self.mock_server_keys.identity_key.derive_public_key_bytes(),
            signed_pre_key: self.mock_server_keys.signed_pre_key.1.clone(),
            signed_pre_key_signature: self.mock_server_keys.signed_pre_key.2.clone(),
            one_time_pre_key: match self.mock_server_keys.one_time_pre_keys.get(7) {
                Some(key_pair) => Some(key_pair.1),
                _ => None,
            },
        }
    }

    pub fn get_pre_key_pair(&self) -> DHKeyPair {
        let signed_pre_key = &self.keys.signed_pre_key;
        DHKeyPair {
            private_key: signed_pre_key.0.clone(),
            public_key: signed_pre_key.1.clone(),
        }
    }

    pub fn initiate_key_agreement(
        self: &X3DH,
        key_bundle: X3DHKeyBundle,
    ) -> X3DHInitializationOutput {
        let ok = xeddsa::PrivateKey::verify_signature(
            &key_bundle.identity_key,
            &[&key_bundle.signed_pre_key.to_bytes()],
            &key_bundle.signed_pre_key_signature,
        );

        if ok {
            println!("signiture ok");
        } else {
            panic!("signiture not ok");
        }

        let dh_key_pair = generate_dh();

        let identity_private_key: [u8; 32] = self.keys.identity_key.private_key_bytes();
        let dh1 =
            StaticSecret::from(identity_private_key).diffie_hellman(&key_bundle.signed_pre_key);

        let bob_public_identity_key = PublicKey::from(key_bundle.identity_key);
        let dh2 = dh_key_pair
            .private_key
            .diffie_hellman(&bob_public_identity_key);
        let dh3 = dh_key_pair
            .private_key
            .diffie_hellman(&key_bundle.signed_pre_key);

        let kdf_key = match key_bundle.one_time_pre_key {
            Some(one_time_key) => {
                let dh4 = dh_key_pair.private_key.diffie_hellman(&one_time_key);
                kdf(dh1, dh2, dh3, Some(dh4))
            }
            _ => kdf(dh1, dh2, dh3, None),
        };

        let associated_data = [
            self.keys.identity_key.derive_public_key_bytes(),
            key_bundle.identity_key,
        ]
        .concat();

        X3DHInitializationOutput {
            alice_identity_pub: PublicKey::from(self.keys.identity_key.derive_public_key_bytes()),
            alice_dhs: dh_key_pair,
            bob_public_key: key_bundle.signed_pre_key,
            bob_one_time_pre_key: key_bundle.one_time_pre_key,
            rk: kdf_key,
            associated_data,
        }
    }

    pub fn respond_to_key_agreement(
        &mut self,
        alice_public_identity: PublicKey,
        alice_dh_public_key: PublicKey,
        one_time_public_key: Option<PublicKey>,
    ) -> [u8; 32] {
        let one_time_private_key = match one_time_public_key {
            Some(one_time_public_key) => Some(self.get_one_time_private_key(one_time_public_key)),
            _ => None,
        };

        let dh1 = self
            .keys
            .signed_pre_key
            .0
            .diffie_hellman(&alice_public_identity);

        let bob_private_identity_bytes: [u8; 32] = self.keys.identity_key.private_key_bytes();
        let dh2 =
            StaticSecret::from(bob_private_identity_bytes).diffie_hellman(&alice_dh_public_key);
        let dh3 = self
            .keys
            .signed_pre_key
            .0
            .diffie_hellman(&alice_dh_public_key);

        let kdf_key = match one_time_private_key {
            Some(one_time_key) => {
                println!("four way");
                let dh4 = one_time_key.diffie_hellman(&alice_dh_public_key);
                kdf(dh1, dh2, dh3, Some(dh4))
            }
            _ => {
                println!("three way");
                kdf(dh1, dh2, dh3, None)
            }
        };
        kdf_key
    }

    fn get_one_time_private_key(&mut self, public_key: PublicKey) -> StaticSecret {
        let mut index = 0;
        let mut found = false;
        for key_pair in &self.keys.one_time_pre_keys {
            if key_pair.1 == public_key {
                found = true;
                break;
            }
            index += 1;
        }
        if found {
            let key = self.keys.one_time_pre_keys[index].0.clone();
            self.keys.one_time_pre_keys.remove(index);
            return key;
        }
        panic!("invalid key was used!")
    }
}

/// Returns a new Diffie-Hellman key pair.
pub fn generate_dh() -> DHKeyPair {
    // Generate a random private key.
    let private_key = StaticSecret::random_from_rng(thread_rng());

    // Get the corresponding public key.
    let public_key = PublicKey::from(&private_key);
    DHKeyPair {
        public_key,
        private_key,
    }
}

// ------ generate keys ----------------------------------------------------------------------

pub fn generate_identity_key() -> xeddsa::PrivateKey {
    xeddsa::PrivateKey::new(&mut thread_rng())
}

pub fn generate_signed_pre_key(
    identity_private_key: &xeddsa::PrivateKey,
) -> (StaticSecret, PublicKey, [u8; 64]) {
    let mut csprng = OsRng;
    let private_key = x25519_dalek::StaticSecret::random_from_rng(csprng);

    let public_key = x25519_dalek::PublicKey::from(&private_key);

    let signed_pre_key =
        identity_private_key.calculate_signature(&mut csprng, &[&public_key.to_bytes()]);

    return (private_key, public_key, signed_pre_key);
}

pub fn generate_one_time_pre_keys() -> Vec<(StaticSecret, PublicKey)> {
    let mut keys: Vec<(StaticSecret, PublicKey)> = Vec::new();
    for _ in 0..100 {
        let private_key = x25519_dalek::StaticSecret::random_from_rng(thread_rng());
        let public_key = x25519_dalek::PublicKey::from(&private_key);
        keys.push((private_key, public_key));
    }
    keys
}

fn kdf(
    dh1: SharedSecret,
    dh2: SharedSecret,
    dh3: SharedSecret,
    dh4: Option<SharedSecret>,
) -> [u8; 32] {
    let mut key = [0u8; 32];
    let bytes_vector = match dh4 {
        Some(dh) => [
            dh1.to_bytes(),
            dh2.to_bytes(),
            dh3.to_bytes(),
            dh.to_bytes(),
        ]
        .concat(),
        _ => [dh1.to_bytes(), dh2.to_bytes(), dh3.to_bytes()].concat(),
    };
    // Create the HKDF instance with the salt and IKM
    let hkdf = Hkdf::<Sha512>::new(None, &bytes_vector);

    hkdf.expand(INFO, &mut key).unwrap();

    return key;
}
