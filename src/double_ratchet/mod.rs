//! double ratchet algorithm based on signal specification
//! for more info visit https://signal.org/docs/specifications/doubleratchet/

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use serde_json::{self, json, Value};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

pub mod dh;
mod encrypted_message;
mod kdf;

use dh::{dh, generate_dh, DHKeyPair};
use encrypted_message::EncryptedMessage;
use kdf::{kdf_ck, kdf_rk};

/// max number of skipped messages that this implementation of double ratchet tolerates.
/// exceeding this number cause an error and messages will be considered lost.
const MAX_SKIPPED: u64 = 100;

/// keys and required info related to a skipped message.
pub struct SkippedMessageKey {
    /// expected sender public key for this message
    /// needs to match with the actual key to initialize decryption
    pub public_key: [u8; 32],

    /// AEAD key required for decryption of message
    message_key: [u8; 32],

    /// message number in chain
    pub n: u64,
}

/// parsed message header, containing require info for decryption.
pub struct ParsedHeader {
    /// sender public key
    pub public_key: [u8; 32],

    /// number of message in sending chain
    pub n: u64,

    /// number of messages in previous sending chain
    pub pn: u64,
}

/// Current State of Double Ratchet for specific user and session
pub struct DoubleRatchet {
    is_initial_message: bool,

    /// DH Ratchet key pair (the "sending" or "self" ratchet key)
    pub dh_s: DHKeyPair,

    /// DH Ratchet public key (the "received" or "remote" key)
    pub dh_public_r: PublicKey,

    /// 32-byte Root Key
    pub rk: [u8; 32],

    /// 32-byte Chain Keys for sending
    pub cks: Option<[u8; 32]>,

    /// 32-byte Chain Keys for receiving
    ckr: Option<[u8; 32]>,

    ///  Message numbers for sending
    ns: u64,

    ///  Message numbers for receiving
    pub nr: u64,

    ///  Number of messages in previous sending chain
    pn: u64,

    /// Dictionary of skipped-over message keys, indexed by ratchet public key and message number.
    ///  Raises an exception if too many elements are stored.
    pub mk_skipped: Vec<SkippedMessageKey>,
}

impl DoubleRatchet {
    /// Returns a JSON representation of the DoubleRatchet object.
    /// The JSON object contains the following fields:
    /// - is_initial_message: a boolean value indicating whether the current message is the first message in the session.
    /// - dh_s: a JSON object containing the public and private keys of the sending DH ratchet key pair.
    /// - dh_public_r: a JSON object containing the public key of the receiving DH ratchet key pair.
    /// - rk: a base64-encoded string representation of the 32-byte root key.
    /// - cks: a base64-encoded string representation of the 32-byte chain key for sending.
    /// - ckr: a base64-encoded string representation of the 32-byte chain key for receiving.
    /// - ns: the message number for sending.
    /// - nr: the message number for receiving.
    /// - pn: the number of messages in the previous sending chain.
    /// - mk_skipped: a JSON array containing the skipped-over message keys.
    pub fn export(&self) -> Value {
        let mut mk_skipped = Vec::new();
        for skipped_message_key in &self.mk_skipped {
            let mut skipped_message_key_json = serde_json::Map::new();
            skipped_message_key_json.insert(
                "public_key".to_string(),
                serde_json::Value::String(
                    base64::engine::general_purpose::STANDARD
                        .encode(&skipped_message_key.public_key),
                ),
            );
            skipped_message_key_json.insert(
                "message_key".to_string(),
                serde_json::Value::String(
                    base64::engine::general_purpose::STANDARD
                        .encode(&skipped_message_key.message_key),
                ),
            );
            skipped_message_key_json.insert(
                "n".to_string(),
                serde_json::Value::Number(serde_json::Number::from(skipped_message_key.n)),
            );
            mk_skipped.push(serde_json::Value::Object(skipped_message_key_json));
        }

        let mut dh_s = serde_json::Map::new();
        dh_s.insert(
            "public_key".to_string(),
            serde_json::Value::String(
                base64::engine::general_purpose::STANDARD.encode(&self.dh_s.public_key.to_bytes()),
            ),
        );
        dh_s.insert(
            "private_key".to_string(),
            serde_json::Value::String(
                base64::engine::general_purpose::STANDARD.encode(&self.dh_s.private_key.to_bytes()),
            ),
        );

        let mut dh_public_r = serde_json::Map::new();
        dh_public_r.insert(
            "public_key".to_string(),
            serde_json::Value::String(
                base64::engine::general_purpose::STANDARD.encode(&self.dh_public_r.to_bytes()),
            ),
        );

        let mut json = serde_json::Map::new();
        json.insert(
            "is_initial_message".to_string(),
            serde_json::Value::Bool(self.is_initial_message),
        );
        json.insert("dh_s".to_string(), serde_json::Value::Object(dh_s));
        json.insert(
            "dh_public_r".to_string(),
            serde_json::Value::Object(dh_public_r),
        );
        json.insert(
            "rk".to_string(),
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&self.rk)),
        );
        // json.insert(
        //     "cks".to_string(),
        //     serde_json::Value::String(
        //         base64::engine::general_purpose::STANDARD.encode(&self.cks.unwrap()),
        //     ),
        // );
        // json.insert(
        //     "ckr".to_string(),
        //     serde_json::Value::String(
        //         base64::engine::general_purpose::STANDARD.encode(&self.ckr.unwrap()),
        //     ),
        // );

        if let Some(cks) = self.cks {
            json.insert(
                "cks".to_string(),
                serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&cks)),
            );
        }

        if let Some(ckr) = self.ckr {
            json.insert(
                "ckr".to_string(),
                serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&ckr)),
            );
        }

        json.insert(
            "ns".to_string(),
            serde_json::Value::Number(serde_json::Number::from(self.ns)),
        );
        json.insert(
            "nr".to_string(),
            serde_json::Value::Number(serde_json::Number::from(self.nr)),
        );
        json.insert(
            "pn".to_string(),
            serde_json::Value::Number(serde_json::Number::from(self.pn)),
        );
        json.insert(
            "mk_skipped".to_string(),
            serde_json::Value::Array(mk_skipped),
        );
        json.into()
    }

    /// Returns a DoubleRatchet object from a JSON representation.
    /// The JSON object should contain the following fields:
    /// - is_initial_message: a boolean value indicating whether the current message is the first message in the session.
    /// - dh_s: a JSON object containing the public and private keys of the sending DH ratchet key pair.
    /// - dh_public_r: a JSON object containing the public key of the receiving DH ratchet key pair.
    /// - rk: a base64-encoded string representation of the 32-byte root key.
    /// - cks: a base64-encoded string representation of the 32-byte chain key for sending.
    /// - ckr: a base64-encoded string representation of the 32-byte chain key for receiving.
    /// - ns: the message number for sending.
    /// - nr: the message number for receiving.
    /// - pn: the number of messages in the previous sending chain.
    /// - mk_skipped: a JSON array containing the skipped-over message keys.
    pub fn from(v: Value) -> DoubleRatchet {
        let is_initial_message = v["is_initial_message"].as_bool().unwrap();

        let dh_s = v["dh_s"].clone();
        let dh_s_public_key = base64::engine::general_purpose::STANDARD
            .decode(dh_s["public_key"].as_str().unwrap())
            .unwrap();
        let dh_s_private_key = base64::engine::general_purpose::STANDARD
            .decode(dh_s["private_key"].as_str().unwrap())
            .unwrap();
        let dh_s = DHKeyPair {
            public_key: PublicKey::from(<[u8; 32]>::try_from(dh_s_public_key).unwrap()),
            private_key: StaticSecret::from(<[u8; 32]>::try_from(dh_s_private_key).unwrap()),
        };

        let dh_public_r = v["dh_public_r"].clone();
        let dh_public_r = PublicKey::from(
            <[u8; 32]>::try_from(
                base64::engine::general_purpose::STANDARD
                    .decode(dh_public_r["public_key"].as_str().unwrap())
                    .unwrap()
                    .as_slice(),
            )
            .unwrap(),
        );

        let rk = base64::engine::general_purpose::STANDARD
            .decode(v["rk"].as_str().unwrap())
            .unwrap();

        let cks = v["cks"]
            .as_str()
            .filter(|s| !s.is_empty())
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());

        let ckr = v["ckr"]
            .as_str()
            .filter(|s| !s.is_empty())
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());

        let ns = v["ns"].as_u64().unwrap();
        let nr = v["nr"].as_u64().unwrap();
        let pn = v["pn"].as_u64().unwrap();

        let mk_skipped = v["mk_skipped"].as_array().unwrap();
        let mut mk_skipped_vec = Vec::new();
        for skipped_message_key in mk_skipped {
            let public_key = base64::engine::general_purpose::STANDARD
                .decode(skipped_message_key["public_key"].as_str().unwrap())
                .unwrap();
            let message_key = base64::engine::general_purpose::STANDARD
                .decode(skipped_message_key["message_key"].as_str().unwrap())
                .unwrap();
            let n = skipped_message_key["n"].as_u64().unwrap();
            mk_skipped_vec.push(SkippedMessageKey {
                public_key: public_key.try_into().unwrap(),
                message_key: message_key.try_into().unwrap(),
                n,
            });
        }

        DoubleRatchet {
            is_initial_message,
            dh_s,
            dh_public_r,
            rk: rk.try_into().unwrap(),
            cks,
            ckr,
            ns,
            nr,
            pn,
            mk_skipped: mk_skipped_vec,
        }
    }

    pub fn new_sender(sk: [u8; 32], dhs: DHKeyPair, other_public_key: PublicKey) -> Self {
        let dh_out = dh(&dhs.private_key, &other_public_key).to_bytes();

        let kdf_rk_out = kdf_rk(sk, dh_out);

        Self {
            dh_s: dhs,
            dh_public_r: other_public_key,
            rk: kdf_rk_out.root_key,
            cks: Some(kdf_rk_out.chain_key),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mk_skipped: Vec::new(),
            is_initial_message: true,
        }
    }

    pub fn new_receiver(
        sk: [u8; 32],
        self_dh_key_pair: DHKeyPair,
        other_public_key: PublicKey,
    ) -> Self {
        Self {
            dh_s: self_dh_key_pair,
            dh_public_r: other_public_key,
            rk: sk,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mk_skipped: Vec::new(),
            is_initial_message: true,
        }
    }

    /// encrypts a byte-array message "plaintext" and returns an EncryptedMessage
    pub fn ratchet_encrypt(&mut self, plaintext: &[u8]) -> EncryptedMessage {
        let kdf_out = kdf_ck(&self.cks.unwrap());
        self.cks = Some(kdf_out.chain_key);
        let message_key = kdf_out.message_key;
        let associated_data = kdf_out.aead_nonce;

        let header =
            Self::generate_header(&self.dh_s.public_key, self.pn, self.ns, &associated_data);

        self.ns += 1;

        let encrypted_data = Self::encrypt(&message_key, plaintext, &header).unwrap();
        EncryptedMessage::new(header, encrypted_data)
    }

    /// decrypts an encrypted byte-array message "cipher_text" and returns
    /// a plain string. requires the corresponding header and associated data.
    /// note: associated data is prepended to each header before message is sent.
    pub fn ratchet_decrypt(
        &mut self,
        header: &[u8],
        cipher_text: &[u8],
        associated_data: &[u8],
    ) -> String {
        let parsed_header = Self::read_header(header);
        let res =
            Self::try_skipped_message_keys(&self, &parsed_header, cipher_text, associated_data);
        match res {
            Some(data) => {
                return Self::decrypted_to_string(data);
            }
            _ => (),
        }

        if self.dh_public_r.to_bytes() != parsed_header.public_key {
            let _ = Self::skip_message_keys(self, parsed_header.pn);
            self.is_initial_message = false;
            Self::dhr_ratchet(self, &parsed_header);
        } else if self.is_initial_message {
            self.is_initial_message = false;
            Self::dhr_ratchet(self, &parsed_header);
        }

        let _ = Self::skip_message_keys(self, parsed_header.n);

        let kdf_ck_out = kdf_ck(&self.ckr.unwrap());
        self.ckr = Some(kdf_ck_out.chain_key);
        let key = kdf_ck_out.message_key;
        self.nr += 1;
        let decrypted_message = Self::decrypt(&key, cipher_text, associated_data);
        Self::decrypted_to_string(decrypted_message)
    }

    // ------------------- encryption --------------------------------------------

    /// Returns an AEAD encryption of plaintext with message key mk.
    /// The associated_data is authenticated but is not included in the ciphertext.
    /// Because each message key is only used once, the AEAD nonce may handled in several ways:
    /// 1. fixed to a constant;
    /// 2. derived from mk alongside an independent AEAD encryption key;
    /// 3. derived as an additional output from KDF_CK(); or chosen randomly and transmitted.
    fn encrypt(
        key: &[u8],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, aes_gcm::Error> {
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);

        let generic_nonce = Nonce::from_slice(&associated_data[0..12]); // 96-bit nonce
        cipher.encrypt(generic_nonce, plaintext)
    }

    /// Creates a new message header containing the DH ratchet public key from the key pair in dh_pair,
    /// the previous chain length pn, and the message number n.
    /// The returned header object contains ratchet public key dh and integers pn and n.
    fn generate_header(
        dh_public_s: &PublicKey,
        pn: u64,
        n: u64,
        associated_data: &[u8; 32],
    ) -> Vec<u8> {
        let header = json!(
            {
                "public_key":  BASE64_STANDARD.encode(dh_public_s),
                "pn": pn,
                "n": n
            }
        )
        .to_string();
        Self::concat(&associated_data, &header.into_bytes())
    }

    /// Encodes a message header into a parsable byte sequence,
    /// prepends the ad byte sequence, and returns the result.
    /// If ad is not guaranteed to be a parsable byte sequence,
    /// a length value should be prepended to the output
    /// to ensure that the output is parsable as a unique pair (ad, header).
    fn concat(associated_data: &[u8; 32], header: &Vec<u8>) -> Vec<u8> {
        let mut byte_sequence = Vec::from(associated_data);
        byte_sequence.extend_from_slice(header);

        byte_sequence
    }

    // ------------------- decryption --------------------------------------------

    /// Returns the AEAD decryption of ciphertext with message key mk.
    /// If authentication fails, an exception will be raised that terminates processing.
    fn decrypt(key: &[u8], cipher_text: &[u8], nonce: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);

        let nonce = Nonce::from_slice(&nonce[0..12]); // 96-bit nonce
        cipher.decrypt(nonce, cipher_text)
    }

    fn decrypted_to_string(decrypted_message: Result<Vec<u8>, aes_gcm::Error>) -> String {
        match decrypted_message {
            Ok(data) => match std::str::from_utf8(&data) {
                Ok(str) => str.to_owned(),
                Err(e) => panic!("Failed to parse decrypted data as UTF-8: {}", e),
            },
            Err(e) => panic!("Decryption failed: {:?}", e),
        }
    }

    fn try_skipped_message_keys(
        &self,
        header: &ParsedHeader,
        cipher_text: &[u8],
        associated_data: &[u8],
    ) -> Option<Result<Vec<u8>, aes_gcm::Error>> {
        for skipped_message_key in &self.mk_skipped {
            if skipped_message_key.public_key == header.public_key
                && skipped_message_key.n == header.n
            {
                return Some(Self::decrypt(
                    &skipped_message_key.message_key,
                    cipher_text,
                    associated_data,
                ));
            }
        }

        return None;
    }

    fn skip_message_keys(&mut self, until: u64) -> Result<(), &str> {
        if self.nr + MAX_SKIPPED < until {
            return Result::Err("Max skip reached");
        }

        while self.nr < until {
            let kdf_out = kdf_ck(&self.ckr.unwrap());
            let chain_key = kdf_out.chain_key;
            let message_key = kdf_out.message_key;

            self.ckr = Some(chain_key);
            let skipped_message = SkippedMessageKey {
                public_key: self.dh_public_r.clone().to_bytes(),
                message_key,
                n: self.nr,
            };
            self.mk_skipped.push(skipped_message);
            self.nr += 1;
        }

        return Ok(());
    }

    pub fn read_header(header: &[u8]) -> ParsedHeader {
        let json_header: serde_json::Value = serde_json::from_slice(header).unwrap();
        let public_key_b64 = match &json_header["public_key"] {
            serde_json::Value::String(s) => s,
            _ => panic!("unexpected public key format, expected base64 string"),
        };

        let public_key_bytes = BASE64_STANDARD
            .decode(public_key_b64)
            .expect("failed to decode public key from base64");

        let public_key: [u8; 32] = public_key_bytes
            .try_into()
            .expect("invalid public key length");

        let n: u64 = match &json_header["n"] {
            serde_json::Value::Number(num) => num.as_u64().unwrap(),
            _ => panic!("unexpected n value"),
        };

        let pn: u64 = match &json_header["pn"] {
            serde_json::Value::Number(num) => num.as_u64().unwrap(),
            _ => panic!("unexpected n value"),
        };

        ParsedHeader { public_key, n, pn }
    }

    fn dhr_ratchet(&mut self, header: &ParsedHeader) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dh_public_r = PublicKey::from(header.public_key);

        // new receive key chain
        let dh_out: SharedSecret;

        dh_out = dh(&self.dh_s.private_key, &self.dh_public_r);

        let kdf_rk_out = kdf_rk(self.rk, dh_out.to_bytes());
        self.rk = kdf_rk_out.root_key;
        self.ckr = Some(kdf_rk_out.chain_key);

        //new diffie-hellman key pair
        let new_key_pair = generate_dh();
        self.dh_s = new_key_pair;

        // new sending key chain
        let dh_out = dh(&self.dh_s.private_key, &self.dh_public_r);

        let kdf_rk_out = kdf_rk(self.rk, dh_out.to_bytes());
        self.rk = kdf_rk_out.root_key;
        self.cks = Some(kdf_rk_out.chain_key);
    }
}
