use std::fs::File;
use std::time::{SystemTime, UNIX_EPOCH};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use argon2::{password_hash::{
    rand_core::OsRng,
    PasswordHasher,
}, Argon2, Algorithm, Version, Params};
use rand_core::RngCore;
use ring::{hmac};
use ring::hmac::{HMAC_SHA256, sign};

pub struct Encrypted{
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub mac: Option<Vec<u8>>,
}

impl Encrypted{
    pub fn generate_mac(&mut self, key: &[u8; 12])
    {

        let key2 = hmac::Key::new(HMAC_SHA256,  key);

        let mut data = self.ciphertext.clone();

        let mut local_nonce = self.nonce.to_vec();

        data.append(&mut local_nonce);

        let mac = sign(&key2, data.as_slice());

        self.mac = Some(mac.as_ref().to_vec());
    }
}

pub struct Arguments {
    pub file: File,
}

pub fn key_generation(salt: String, args: &mut Arguments, password: String) -> [u8; 64]
{
    let mut argon2 = Argon2::new(Algorithm::Argon2id,
                                 Version::V0x10,
                                 Params::new(47104, 3, 2, Some(32))
                                     .expect("Error while creating hashing parameters"));

    let mut output_key_material = [0u8; 64];

    argon2.hash_password_into(password.as_bytes(), salt.as_bytes(), &mut output_key_material).expect("Failed while hashing the password");

    return output_key_material;
}

pub fn gen_nonce() -> [u8; 12]
{
    let mut time_part = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("This is a secret message. If you see it something went really wrong!")
        .as_secs().to_ne_bytes().to_vec();

    let mut nonce = OsRng.next_u64().to_ne_bytes().to_vec();
    time_part.truncate(4);
    nonce.append(time_part.as_mut());
    let ret: [u8; 12] = nonce.try_into().expect("Something went wrong while generating nonce! Wrong sized array!");
    return ret;
}

pub fn encrypt(file_string: &String, key: &[u8; 32]) -> Encrypted
{
    let key: &Key<Aes256Gcm> = key.into();

    let cipher = Aes256Gcm::new(key);

    let nonce = gen_nonce();

    let nonce_cloned = Nonce::clone_from_slice(nonce.as_slice());

    let ciphertext = cipher.encrypt(&nonce_cloned, file_string.clone().into_bytes().as_ref()).expect("Failed while encrypting");

    let encrypted = Encrypted{ciphertext, nonce, mac: None};

    return encrypted;
}

pub unsafe fn decrypt(data: Encrypted, key: &[u8; 32]) -> String
{
    let key: &Key<Aes256Gcm> = key.into();

    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::clone_from_slice(data.nonce.as_slice());

    let value = cipher.decrypt(&nonce, data.ciphertext.as_slice()).expect("Failed while decrypting");

    let string = String::from_utf8(value).expect("Failed while changing to string");

    return string;
}
