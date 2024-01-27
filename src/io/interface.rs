use crate::structs::arguments::Arguments;
use std::path::Path;
use std::{fs, io};

///Reads the file bytes into a buffer and returns it. Path is taken from the arguments struct
pub fn read_file(args: &Arguments) -> io::Result<Vec<u8>> {
    fs::read(&args.file)
}

///Writes a buffer of Vec<u8> to a file with the given path string
pub fn write_buffer_to_file(buffer: &Vec<u8>, path: &String) {
    match fs::write(Path::new(path.as_str()), buffer) {
        Ok(_) => println!("Successfully written {} bytes to {}", buffer.len(), path),
        Err(_) => println!("Failed while writing to {}", path),
    }
}

pub fn password_query() -> String {
    let mut pass = String::new();
    println!("Provide a password: ");
    io::stdin().read_line(&mut pass).unwrap();
    print!("{}[2J", 27 as char);
    println!("Password provided");
    return pass;
}
