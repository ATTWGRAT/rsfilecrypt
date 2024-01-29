use crate::structs::encrypted::Encrypted;
use ring::hmac::{sign, verify, HMAC_SHA256};

///Generates a MAC for the encrypted data
pub fn generate_mac(enc: &mut Encrypted, key: &[u8; 32]) {
    let key2 = ring::hmac::Key::new(HMAC_SHA256, key);

    let mut data = enc.ciphertext.clone();

    let mut local_nonce = enc.nonce.to_vec();

    let mut salt1 = enc.salt1.to_vec();
    let mut salt2 = enc.salt2.to_vec();

    data.append(&mut local_nonce);
    data.append(&mut salt1);
    data.append(&mut salt2);

    let mac = sign(&key2, data.as_slice());

    enc.mac = Some(mac.as_ref().to_vec());
}

/// Verifies the hash of the encrypted data using a 32 byte key
///
/// SAFETY: Make sure that the method is called on a structure
/// that already has a mac created (either by decoding or generating)
pub unsafe fn verify_mac(enc: &Encrypted, key: &[u8; 32]) -> bool {
    let key2 = ring::hmac::Key::new(HMAC_SHA256, key);

    let mut data = enc.ciphertext.clone();

    let mut local_nonce = enc.nonce.to_vec();

    let mut salt1 = enc.salt1.to_vec();
    let mut salt2 = enc.salt2.to_vec();

    data.append(&mut local_nonce);
    data.append(&mut salt1);
    data.append(&mut salt2);

    return match verify(&key2, data.as_slice(), enc.mac.as_ref().unwrap().as_slice()) {
        Ok(_) => {
            println!("Mac succesfully verified");
            true
        }
        Err(_) => {
            println!("Wrong mac!");
            false
        }
    };
}
