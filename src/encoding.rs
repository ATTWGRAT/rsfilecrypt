use ring::hmac::{HMAC_SHA256, sign, verify};

pub struct Encrypted{
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub mac: Option<Vec<u8>>,
}

impl Encrypted{

    ///Generates a MAC for the encrypted data
    pub fn generate_mac(&mut self, key: &[u8; 32])
    {
        let key2 = ring::hmac::Key::new(HMAC_SHA256, key);

        let mut data = self.ciphertext.clone();

        let mut local_nonce = self.nonce.to_vec();

        data.append(&mut local_nonce);

        let mac = sign(&key2, data.as_slice());

        self.mac = Some(mac.as_ref().to_vec());

    }

    /// Verifies the hash of the encrypted data using a 32 byte key
    ///
    /// SAFETY: Make sure that the method is called on a structure
    /// that already has a mac created (either by decoding or generating)
    pub unsafe fn verify_mac(&self, key: &[u8; 32]) -> bool
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


    /// Takes data in the Encrypted struct, adds them together:
    /// MAC + Ciphertext + nonce
    /// Then returns that vector.
    ///
    /// This function clones parts of the structure and doesn't change it
    pub fn encode_encrypted_data(&self) -> Vec<u8>
    {
        let mut data = self.mac.clone().expect("Please generate a mac before encoding!");

        data.append(self.ciphertext.clone().as_mut());

        data.append(self.nonce.clone().to_vec().as_mut());

        return data;
    }


    /// Takes encrypted encoded data and decodes it into the Encrypted struct.
    /// Consumes the original vector.
    ///
    /// SAFETY: The vector has to be in the correct format specified in encode_encrypted data otherwise it may panic.
    pub unsafe fn decode_encrypted_data(data: Vec<u8>) -> Encrypted
    {
        let length = data.len();

        let mac = Some(data[..32].to_vec());
        let nonce:[u8; 12] = data[length-12..].try_into().unwrap();
        let ciphertext = data[32..length-12].to_vec();

        let enc = Encrypted{
            mac,
            nonce,
            ciphertext
        };

        return enc;
    }
}