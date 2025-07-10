pub struct EncryptedMessage {
    /// Byte vector array containing public key, n and pn
    pub header: Vec<u8>,

    /// encrypted text using AEAD algorithm
    pub cipher_text: Vec<u8>,
}

impl EncryptedMessage {
    pub fn new(header: Vec<u8>, cipher_text: Vec<u8>) -> EncryptedMessage {
        EncryptedMessage {
            header,
            cipher_text,
        }
    }
}
