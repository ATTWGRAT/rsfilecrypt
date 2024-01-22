mod inout;
mod encryption;

use std::env;
use crate::encryption::{Arguments, decrypt, encrypt, key_generation};
use crate::inout::{parse, read_file_to_string};

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut a: Arguments = parse(args);

    let key = key_generation(&mut a, String::from("asdasd123"));

    let val = read_file_to_string(&mut a);

    let enc = encrypt(&val, &key);

    let dec = unsafe {decrypt(enc, &key)};

    println!("Succesfully decrypted: \n{}", dec);
}
