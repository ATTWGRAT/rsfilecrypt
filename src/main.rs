mod inout;

use std::env;
use crate::inout::{Arguments, parse, read_file_to_string};

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut a: Arguments = parse(args);

    dbg!(read_file_to_string(&mut a));
}
