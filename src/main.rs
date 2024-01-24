mod inout;
mod encryption;
mod verification;

use std::env;
use crate::encryption::{Arguments, decrypt, encrypt, key_generation};
use crate::inout::{parse, read_file_to_string};

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut a: Arguments = parse(args);

    let val = read_file_to_string(&mut a);

    let enc_key: [u8; 32] = key_generation(String::from("asdasd123"), &mut a, "password".to_string());

    let mac_key: [u8; 32] = key_generation(String::from("dsadsa321"), &mut a, "password".to_string());

    let mut enc = encrypt(&val, &enc_key);

    enc.generate_mac(&mac_key);

    enc.verify_mac(&mac_key);

    let dec = unsafe {decrypt(&enc, &enc_key)};

    println!("Succesfully decrypted: \n{}", dec);
}
