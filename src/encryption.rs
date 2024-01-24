use std::time::{SystemTime, UNIX_EPOCH};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use argon2::{password_hash::{
    rand_core::OsRng,
}, Argon2, Algorithm, Version, Params};
use rand_core::RngCore;
use crate::inout::Arguments;
use crate::encoding::Encrypted;


///Function takes a salt, password and Arguments structure (for use later) and
///creates a safe key using the Argon2 hashing algo for later encryption.
pub fn key_generation(salt: String, _args: &mut Arguments, password: String) -> [u8; 32]
{
    let argon2 = Argon2::new(Algorithm::Argon2id,
                                 Version::V0x10,
                                 Params::new(47104, 3, 2, Some(32))
                                     .expect("Error while creating hashing parameters"));

    let mut output_key_material = [0u8; 32];

    argon2.hash_password_into(password.as_bytes(), salt.as_bytes(), &mut output_key_material).expect("Failed while hashing the password");

    return output_key_material;
}

/// Generates a random 12 byte nonce.
/// For nonce safety 4 bytes is always dependent
/// on the current time, and the other 8 are random.
/// That way, a single user will never have the same nonce
/// more than once (since they would have to generate it a huge amount of times
/// in a period of 1 second).
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

///Encrypts a data buffer (Vec<u8>) with the AES256-GCM algo using a 32 byte key.
pub fn encrypt(file_string: &Vec<u8>, key: &[u8; 32]) -> Encrypted
{
    let key: &Key<Aes256Gcm> = key.into();

    let cipher = Aes256Gcm::new(key);

    let nonce = gen_nonce();

    let nonce_cloned = Nonce::clone_from_slice(nonce.as_slice());

    let ciphertext = cipher.encrypt(&nonce_cloned, file_string.as_ref()).expect("Failed while encrypting");

    let encrypted = Encrypted{ciphertext, nonce, mac: None};

    return encrypted;
}

///Decrypts encrypted data using a 32 byte key
pub unsafe fn decrypt(data: &Encrypted, key: &[u8; 32]) -> Vec<u8>
{
    let key: &Key<Aes256Gcm> = key.into();

    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::clone_from_slice(data.nonce.as_slice());

    let value = cipher.decrypt(&nonce, data.ciphertext.as_slice()).expect("Failed during decryption");

    return value;
}
