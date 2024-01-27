mod encryption;
mod io;
mod structs;

use crate::encryption::aes256::{decrypt, encrypt, key_generation};
use crate::io::encoding::{decode_encrypted_data, encode_encrypted_data};
use crate::io::interface::{password_query, read_file, write_buffer_to_file};
use crate::io::mac::{generate_mac, verify_mac};
use crate::structs::arguments::{parse, Action, Arguments};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut a: Arguments = parse(&args).expect("IoError");

    let pass = password_query();

    //todo: Add random salt generation

    let enc_key: [u8; 32] = key_generation(String::from("asdasd123"), &mut a, &pass);

    let mac_key: [u8; 32] = key_generation(String::from("dsadsa321"), &mut a, &pass);

    let data = read_file(&a).expect("Failure while reading file");

    match &a.action {
        Action::Decrypt => unsafe {
            let enc = decode_encrypted_data(data);

            if !verify_mac(&enc, &mac_key) {
                println!("Wrong password!");
                return;
            }

            let data = decrypt(&enc, &enc_key);

            write_buffer_to_file(&data, &a.file);

            println!("Successfully decrypted the file!");
        },
        Action::Encrypt => unsafe {
            let mut enc = encrypt(data, &enc_key);

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
