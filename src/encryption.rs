use std::fs::File;
use aes_gcm::{AeadCore, Aes256Gcm, AesGcm, Key, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use aes_gcm::aead::consts::U12;
use aes_gcm::aes::Aes256;
use argon2::{password_hash::{
    rand_core::OsRng,
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString
}, Argon2, ParamsBuilder, Algorithm, Version, Params};

pub enum KDFType {
    Argon2,
    PBKDF2,
    Scrypt,
}

pub enum CryptType {
    AESGCM,
}

pub struct Arguments {
    pub crypt_type: CryptType,
    pub file: File,
    pub kdf_type: KDFType,
}

pub fn key_generation(args: &mut Arguments, password: String) -> [u8; 32]
{
    let salt = "example salt";

    let mut argon2 = Argon2::new(Algorithm::Argon2id,
                                 Version::V0x10,
                                 Params::new(47104, 3, 1, Some(32))
                                     .expect("Error while creating hashing parameters"));

    let mut output_key_material = [0u8; 32];

    argon2.hash_password_into(password.as_bytes(), salt.as_bytes(), &mut output_key_material).expect("Failed while hashing the password");

    return output_key_material;
}


pub fn encrypt(file_string: &String, key: &[u8; 32]) -> Vec<u8>
{
    let key: &Key<Aes256Gcm> = key.into();

    let cipher = Aes256Gcm::new(key);

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let mut ciphertext = cipher.encrypt(&nonce, file_string.clone().into_bytes().as_ref()).expect("Failed while encrypting");

    ciphertext.append(nonce.to_vec().as_mut());

    return ciphertext;
}

pub unsafe fn decrypt(data: Vec<u8>, key: &[u8; 32]) -> String
{
    let key: &Key<Aes256Gcm> = key.into();

    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::clone_from_slice( &data[data.len() - 12..]);

    let value = cipher.decrypt(&nonce, &data[..data.len()-12]).expect("Failed while decrypting");

    let string = String::from_utf8(value).expect("Failed while changing to string");

    return string;
}