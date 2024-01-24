mod inout;
mod encryption;
mod encoding;

use std::env;
use std::ops::Add;
use crate::encryption::{decrypt, encrypt, key_generation};
use crate::inout::Arguments;

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut a: Arguments = Arguments::parse(&args);

    let enc_key: [u8; 32] = key_generation(String::from("asdasd123"), &mut a, "password".to_string());

    let mac_key: [u8; 32] = key_generation(String::from("dsadsa321"), &mut a, "password".to_string());
}
