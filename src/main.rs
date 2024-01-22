mod inout;
mod encryption;

use std::env;
use crate::encryption::{Arguments, key_generation};
use crate::inout::{parse, read_file_to_string};

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut a: Arguments = parse(args);

    key_generation(&mut a, String::from(""));
}
