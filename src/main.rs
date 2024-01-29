mod encryption;
mod io;
mod structs;

use crate::encryption::aes256::{decrypt, encrypt, key_generation};
use crate::encryption::salt::generate_random_salt;
use crate::io::encoding::{decode_encrypted_data, encode_encrypted_data};
use crate::io::interface::{password_query, read_file, write_buffer_to_file};
use crate::io::mac::{generate_mac, verify_mac};
use crate::structs::arguments::{parse, Action, Arguments};
use ring::rand::SystemRandom;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    let rand = SystemRandom::new();

    let mut a: Arguments = parse(&args).expect("IoError");

    let data = read_file(&a).expect("Failure while reading file");

    let pass = password_query();

    match &a.action {
        Action::Decrypt => unsafe {
            let enc = decode_encrypted_data(data);

            let enc_key: [u8; 32] = key_generation(&enc.salt1, &mut a, &pass);

            let mac_key: [u8; 32] = key_generation(&enc.salt2, &mut a, &pass);

            if !verify_mac(&enc, &mac_key) {
                println!("Wrong password!");
                return;
            }

            let data = decrypt(&enc, &enc_key);

            write_buffer_to_file(&data, &a.file);

            println!("Successfully decrypted the file!");
        },
        Action::Encrypt => unsafe {
            let salt1 = generate_random_salt(&rand);
            let salt2 = generate_random_salt(&rand);

            let enc_key: [u8; 32] = key_generation(&salt1, &mut a, &pass);

            let mac_key: [u8; 32] = key_generation(&salt2, &mut a, &pass);

            let mut enc = encrypt(data, &enc_key, &rand, &salt1, &salt2);

            generate_mac(&mut enc, &mac_key);

            if !verify_mac(&enc, &mac_key) {
                println!("Something went wrong while encrypting!");
                return;
            }

            let data = encode_encrypted_data(&enc);

            write_buffer_to_file(&data, &a.file);

            println!("Successfully encrypted the file!");
        },
    }
}
