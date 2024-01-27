pub struct Encrypted {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub mac: Option<Vec<u8>>,
}
