//! double ratchet algorithm based on signal specification
//! for more info visit https://signal.org/docs/specifications/x3dh/
//! using curve X25519
//! using sha512

use base64::prelude::*;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::thread_rng;
use serde_json::{json, Value};
use sha2::Sha512;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

use crate::double_ratchet::dh::DHKeyPair;
use crate::xeddsa::{self, PrivateKey};

pub mod keys;
use keys::X3DHKeys;

const INFO: &[u8] = b"DooD-encryption-lib";

pub struct X3DH {
    keys: X3DHKeys,
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

impl X3DH {
    /// Create a new X3DH instance with random keys.
    pub fn new() -> X3DH {
        let keys = X3DHKeys::new();
        Self { keys }
    }

    /// Create a new X3DH instance from a JSON Value.
    /// The JSON Value should have the following structure:
    /// {
    ///     "identity_key": "base64",
    ///     "signed_private_pre_key": "base64",
    ///     "signed_signature_pre_key": "base64",
    ///     "one_time_keys": "base64"
    /// }
    pub fn from(v: Value) -> X3DH {
        let identity_key = v.get("identity_key").unwrap().as_str().unwrap();
        let identity_key: [u8; 32] = BASE64_STANDARD
            .decode(identity_key)
            .unwrap()
            .try_into()
            .expect("failed");
        let identity_key = xeddsa::PrivateKey::from(identity_key);

        let signed_pre_key = deserialize_signed_pre_key(
            v.get("signed_private_pre_key").unwrap().as_str().unwrap(),
            v.get("signed_signature_pre_key").unwrap().as_str().unwrap(),
        );

        let one_time_pre_keys =
            deserialize_one_time_keys(v.get("one_time_keys").unwrap().as_str().unwrap());

        let x3dh_keys = X3DHKeys {
            identity_key,
            signed_pre_key,
            one_time_pre_keys,
        };
        X3DH {
            keys: x3dh_keys.clone(),
        }
    }

    /// Export the X3DH instance as a JSON Value.
    /// The JSON Value will have the following structure:
    /// {
    ///     "identity_key": "base64",
    ///     "signed_private_pre_key": "base64",
    ///     "signed_signature_pre_key": "base64",
    ///     "one_time_keys": "base64"
    /// }
    pub fn export(&self) -> Value {
        let identity_key_bytes = &self.keys.identity_key.derive_public_key_bytes();
        let identity_key = BASE64_STANDARD.encode(identity_key_bytes);

        let pre_signed_key_bytes = &self.keys.signed_pre_key.0.to_bytes();
        let pre_signed_key = BASE64_STANDARD.encode(pre_signed_key_bytes);

        let pre_signed_key_signature_bytes = self.keys.signed_pre_key.2.clone();
        let pre_signed_key_signature = BASE64_STANDARD.encode(pre_signed_key_signature_bytes);

        let mut one_time_private_keys_bytes: Vec<[u8; 32]> = Vec::new();
        for (private, _) in &self.keys.one_time_pre_keys {
            one_time_private_keys_bytes.push(private.as_bytes().to_owned());
        }

        let one_time_private_keys_bytes: Vec<u8> =
            one_time_private_keys_bytes.into_iter().flatten().collect();

        let one_time_keys = BASE64_STANDARD.encode(one_time_private_keys_bytes);
        let v = json!({
            "identity_key": identity_key,
            "signed_private_pre_key": pre_signed_key,
            "signed_signature_pre_key": pre_signed_key_signature,
            "one_time_keys": one_time_keys
        });
        return v;
    }

    /// Get the signed pre key pair.
    pub fn get_pre_key_pair(&self) -> DHKeyPair {
        let signed_pre_key = &self.keys.signed_pre_key;
        DHKeyPair {
            private_key: signed_pre_key.0.clone(),
            public_key: signed_pre_key.1.clone(),
        }
    }

    /// initiate the key agreement.
    /// used by the client to initiate the key agreement without the need of the other party to be online.
    /// uses the other party's key bundle, generated beforehand and stored on the server.
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
            println!("signature ok");
        } else {
            panic!("signature not ok");
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

    /// Respond to the key agreement.
    /// Used by one party (bob) to respond to the other party (alice) key agreement initiation.
    /// Public keys are received from other party in their first message
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

    /// Get a one time private key.
    /// Used to get a one time private key for the key agreement.
    /// The private key is removed from the list of one time keys.
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

    pub fn generate_challenge(&mut self) -> Vec<u8> {
        // Generate a random nonce (32 bytes)
        let nonce: [u8; 32] = rand::random();

        // Get current timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        // Create challenge message: nonce + timestamp
        let mut message = Vec::with_capacity(40);
        message.extend_from_slice(&nonce);
        message.extend_from_slice(&timestamp.to_be_bytes());

        let mut rng = OsRng;
        // Sign the message with identity key
        let signature = self
            .keys
            .identity_key
            .calculate_signature(&mut rng, &[&message]);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&timestamp.to_be_bytes());
        bytes.extend_from_slice(&signature);
        bytes
    }

    pub fn verify_challenge(&self, challenge: &[u8], public_key: [u8; 32]) -> bool {
        // Verify the challenge by checking the signature
        let (message, signature) = challenge.split_at(40);
        let (nonce, timestamp) = message.split_at(32);
        let mut message = Vec::with_capacity(40);
        message.extend_from_slice(&nonce);
        message.extend_from_slice(&timestamp);
        // Prepare message as &[&[u8]]
        let message_refs: [&[u8]; 1] = [&message];
        // Ensure signature is &[u8; 64]
        let signature_array: &[u8; 64] = signature.try_into().expect("Signature must be 64 bytes");
        PrivateKey::verify_signature(&public_key, &message_refs, signature_array)
    }
}

/// Returns a new Diffie-Hellman key pair.
fn generate_dh() -> DHKeyPair {
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

fn deserialize_signed_pre_key(
    private_key: &str,
    signature: &str,
) -> (StaticSecret, PublicKey, [u8; 64]) {
    let private_key: [u8; 32] = BASE64_STANDARD
        .decode(private_key)
        .unwrap()
        .try_into()
        .expect("failed");
    let private_key = StaticSecret::from(private_key);

    let public_key = x25519_dalek::PublicKey::from(&private_key);

    let signature: [u8; 64] = BASE64_STANDARD
        .decode(signature)
        .unwrap()
        .try_into()
        .expect("failed");

    return (private_key, public_key, signature);
}

fn deserialize_one_time_keys(one_time_keys: &str) -> Vec<(StaticSecret, PublicKey)> {
    let one_time_keys: Vec<u8> = BASE64_STANDARD
        .decode(one_time_keys)
        .unwrap()
        .try_into()
        .expect("failed");

    one_time_keys
        .chunks(32)
        .map(|chunk| {
            let chunk: [u8; 32] = chunk.try_into().expect("failure");
            let secret_key = StaticSecret::from(chunk);
            let public_key = x25519_dalek::PublicKey::from(&secret_key);
            (secret_key, public_key)
        })
        .collect()
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
