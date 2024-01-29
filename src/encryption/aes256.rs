use crate::structs::arguments::Arguments;
use crate::structs::encrypted::Encrypted;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use ring::rand::{SecureRandom, SystemRandom};
use std::time::{SystemTime, UNIX_EPOCH};

///Function takes a salt, password and Arguments structure (for use later) and
///creates a safe key using the Argon2 hashing algo for later aes256.
pub fn key_generation(salt: &[u8], _args: &mut Arguments, password: &String) -> [u8; 32] {
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x10,
        Params::new(47104, 3, 2, Some(32)).expect("Error while creating hashing parameters"),
    );

    let mut output_key_material = [0u8; 32];

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output_key_material)
        .expect("Failed while hashing the password");

    return output_key_material;
}

/// Generates a random 12 byte nonce.
/// For nonce safety 4 bytes is always dependent
/// on the current time, and the other 8 are random.
/// That way, a single user will never have the same nonce
/// more than once (since they would have to generate it a huge amount of times
/// in a period of 1 second).
pub fn gen_nonce(rand: &SystemRandom) -> [u8; 12] {
    let mut time_part = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("This is a secret message. If you see it something went really wrong!")
        .as_secs()
        .to_ne_bytes()
        .to_vec();

    let mut nonce = [0u8; 8];
    rand.fill(&mut nonce).unwrap();

    let mut nonce = nonce.to_vec();

    time_part.truncate(4);
    nonce.append(time_part.as_mut());
    let ret: [u8; 12] = nonce
        .try_into()
        .expect("Something went wrong while generating nonce! Wrong sized array!");
    return ret;
}

///Encrypts a data buffer (Vec<u8>) with the AES256-GCM algo using a 32 byte key.
pub fn encrypt(
    data: Vec<u8>,
    key: &[u8; 32],
    rand: &SystemRandom,
    salt1: &[u8; 16],
    salt2: &[u8; 16],
) -> Encrypted {
    let key: &Key<Aes256Gcm> = key.into();

    let cipher = Aes256Gcm::new(key);

    let nonce = gen_nonce(rand);

    let nonce_cloned = Nonce::clone_from_slice(nonce.as_slice());

    let ciphertext = cipher
        .encrypt(&nonce_cloned, data.as_ref())
        .expect("Failed while encrypting");

    let encrypted = Encrypted {
        salt1: salt1.clone(),
        salt2: salt2.clone(),
        ciphertext,
        nonce,
        mac: None,
    };

    return encrypted;
}

///Decrypts encrypted data using a 32 byte key
pub fn decrypt(data: &Encrypted, key: &[u8; 32]) -> Vec<u8> {
    let key: &Key<Aes256Gcm> = key.into();

    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::clone_from_slice(data.nonce.as_slice());

    let value = cipher
        .decrypt(&nonce, data.ciphertext.as_slice())
        .expect("Failed during decryption");

    return value;
}

#[cfg(test)]
mod tests {
    use crate::encryption::aes256::{decrypt, encrypt, gen_nonce, key_generation};
    use crate::structs::arguments::{Action, Arguments};
    use ring::rand::SystemRandom;

    #[test]
    fn nonce_gen() {
        let rand = SystemRandom::new();
        let nonce1 = gen_nonce(&rand);
        let nonce2 = gen_nonce(&rand);
        let nonce3 = gen_nonce(&rand);

        assert_ne!(nonce1, nonce2);
        assert_ne!(nonce2, nonce3);
        assert_ne!(nonce1, nonce3);
    }

    #[test]
    fn encrypt_decrypt() {
        let rand = SystemRandom::new();

        let key = [42u8; 32];

        let data = b"hackermantest".to_vec();

        let enc = encrypt(data.clone(), &key, &rand);

        let dec = decrypt(&enc, &key);

        assert_eq!(data, dec);
    }
    #[test]
    fn keygen_exact() {
        let testarr: [u8; 32] = [
            13, 90, 29, 25, 116, 58, 12, 43, 66, 82, 52, 129, 246, 29, 178, 135, 52, 195, 91, 62,
            106, 97, 8, 20, 223, 162, 175, 74, 176, 200, 202, 248,
        ];

        assert_eq!(
            key_generation(
                b"abc321123",
                &mut Arguments {
                    action: Action::Encrypt,
                    file: "asd".parse().unwrap()
                },
                &"dfghijkl123@".to_string()
            ),
            testarr
        );
    }
}
