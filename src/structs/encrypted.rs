pub struct Encrypted {
    pub salt1: [u8; 16],
    pub salt2: [u8; 16],
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub mac: Option<Vec<u8>>,
}
