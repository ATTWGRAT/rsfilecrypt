use std::fs::File;
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

pub fn key_generation(args: &mut Arguments, password: String)
{
    let salt = "example salt";

    let mut argon2 = Argon2::new(Algorithm::Argon2id,
                                 Version::V0x10,
                                 Params::new(47104, 3, 1, Some(32))
                                     .expect("Error while creating hashing parameters"));

    let mut output_key_material = [0u8; 32];

    argon2.hash_password_into(password.as_bytes(), salt.as_bytes(), &mut output_key_material).expect("Failed while hashing the password");

    dbg!(output_key_material);
    println!("Created password hash with salt {salt}");
}