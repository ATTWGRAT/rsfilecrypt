mod inout;
mod encryption;

use std::env;
use crate::encryption::{Arguments, decrypt, encrypt, gen_nonce, key_generation};
use crate::inout::{parse, read_file_to_string};

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut a: Arguments = parse(args);

    //let full_key = key_generation(&mut a, String::from("asdasd123"));

    //let enc_key: [u8; 32] = full_key[..32].try_into().unwrap();

    //let mac_key: [u8; 32] = full_key[32..].try_into().unwrap();

    //let val = read_file_to_string(&mut a);

    //let enc = encrypt(&val, &enc_key);

    //let tag = generate_mac(&enc, &mac_key);

    //let dec = unsafe {decrypt(enc, &enc_key)};

    //println!("Succesfully decrypted: \n{}", dec);
}
