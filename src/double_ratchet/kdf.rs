use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// Returns a pair (32-byte root key, 32-byte chain key) as the output of applying a KDF keyed
/// by a 32-byte root key rk to a Diffie-Hellman output dh_out.
pub fn kdf_rk(rk: [u8; 32], dh_out: [u8; 32]) -> KdfRkOut {
    let rk_bytes = rk;
    let dh_out_bytes = dh_out;
    const KEY1_INFO: &[u8] = b"root-key";
    const KEY2_INFO: &[u8] = b"chain-key";

    let mut root_key = [0u8; 32];
    let mut chain_key = [0u8; 32];

    // create a hash to concat the two keys together
    let mut hasher = Sha256::new();
    hasher.update(rk_bytes);
    hasher.update(dh_out_bytes);

    let hkdf = Hkdf::<Sha256>::new(None, &(hasher.finalize().to_vec()));
    hkdf.expand(KEY1_INFO, &mut root_key).unwrap();
    hkdf.expand(KEY2_INFO, &mut chain_key).unwrap();

    KdfRkOut {
        root_key,
        chain_key,
    }
}

///  Returns a pair (32-byte chain key, 32-byte message key)
/// as the output of applying a KDF keyed by a 32-byte chain key ck to some constant.
pub fn kdf_ck(ck: &[u8; 32]) -> KdfCkOut {
    //TODO: the module should get salt as an input
    // Your constant value used as salt
    const SALT: &[u8] = b"your_constant_value";

    // Define the info parameter (optional, can be an empty slice)
    const KEY1_INFO: &[u8] = b"chain-key";
    const KEY2_INFO: &[u8] = b"message-key";
    const KEY3_INFO: &[u8] = b"AEAD-nonce";

    let mut chain_key = [0u8; 32];
    let mut message_key = [0u8; 32];
    let mut aead_nonce = [0u8; 32];

    // Create the HKDF instance with the salt and IKM
    let hkdf = Hkdf::<Sha256>::new(Some(SALT), ck);

    hkdf.expand(KEY1_INFO, &mut chain_key).unwrap();
    hkdf.expand(KEY2_INFO, &mut message_key).unwrap();
    hkdf.expand(KEY3_INFO, &mut aead_nonce).unwrap();

    return KdfCkOut {
        chain_key,
        message_key,
        aead_nonce,
    };
}

/// output of HKDF algorithm performed on 32-byte chain key and a constant
pub struct KdfCkOut {
    /// 32-byte chained key
    pub chain_key: [u8; 32],

    /// 32-byte message key
    pub message_key: [u8; 32],

    /// 32-byte nonce, 12-byte slice of which might be used by AEAD algorithm
    /// to encrypt the message
    pub aead_nonce: [u8; 32],
}

/// output of HKDF algorithm performed on a 32-byte root key
/// and Diffie-Hellman Shared_Key.
pub struct KdfRkOut {
    /// 32-byte root key
    pub root_key: [u8; 32],

    /// 32-byte chain key
    pub chain_key: [u8; 32],
}
