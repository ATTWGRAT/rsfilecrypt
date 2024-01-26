mod inout;
mod encryption;
mod encoding;

use std::env;
use std::ops::Add;
use crate::encoding::Encrypted;
use crate::encryption::{decrypt, encrypt, key_generation};
use crate::inout::{Action, Arguments, password_query, write_buffer_to_file};

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut a: Arguments = Arguments::parse(&args).expect("IoError");

    let pass = password_query();

    let enc_key: [u8; 32] = key_generation(String::from("asdasd123"), &mut a, &pass);

    let mac_key: [u8; 32] = key_generation(String::from("dsadsa321"), &mut a, &pass);

    let data = a.read_file().expect("Failure while reading file");

    match &a.action {
        Action::Decrypt=> unsafe {
            let enc = Encrypted::decode_encrypted_data(data);

            if !enc.verify_mac(&mac_key)
            {
                println!("Wrong password!");
                return
            }

            let data = decrypt(&enc, &enc_key);

            write_buffer_to_file(&data, &a.file);

            println!("Successfully decrypted the file!");
        }
        Action::Encrypt=> unsafe {
            let mut enc = encrypt(data, &enc_key);

            enc.generate_mac(&mac_key);

            if !enc.verify_mac(&mac_key)
            {
                println!("Something went wrong while encrypting!");
                return
            }

            let data = enc.encode_encrypted_data();

            write_buffer_to_file(&data, &a.file);

            println!("Successfully encrypted the file!");
        }

    }
}
