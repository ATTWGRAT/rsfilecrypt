use ring::error::Unspecified;
use ring::hmac::{HMAC_SHA256, sign, verify};

pub struct Encrypted{
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub mac: Option<Vec<u8>>,
}

impl Encrypted{
    pub fn generate_mac(&mut self, key: &[u8; 32])
    {

        let key2 = ring::hmac::Key::new(HMAC_SHA256, key);

        let mut data = self.ciphertext.clone();

        let mut local_nonce = self.nonce.to_vec();

        data.append(&mut local_nonce);

        let mac = sign(&key2, data.as_slice());

        self.mac = Some(mac.as_ref().to_vec());

    }

    pub fn verify_mac(&self, key: &[u8; 32]) -> bool
    {
        let key2 = ring::hmac::Key::new(HMAC_SHA256, key);

        let mut data = self.ciphertext.clone();

        let mut local_nonce = self.nonce.to_vec();

        data.append(&mut local_nonce);

        return match verify(&key2, data.as_slice(), self.mac.as_ref().unwrap().as_slice()) {
            Ok(_) => {
                println!("Mac succesfully verified");
                true
            }
            Err(_) => {
                println!("Wrong mac!");
                false
            }
        }
    }
}