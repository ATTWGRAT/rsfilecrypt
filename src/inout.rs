use std::fs::File;
use std::io::Read;
use std::path::Path;
use crate::encryption::{Arguments, CryptType, KDFType};

pub fn parse(args: Vec<String>) -> Arguments
{
    if args.len() == 1
    {
        panic!("No arguments provided")
    }

    //todo: check if args[1] is a valid encryption method

    let path = Path::new(args[2].as_str());

    let file = match File::open(path) {
        Ok(f) => f,
        Err(err) => panic!("Couldn't open {} : {}", path.display(), err),
    };


    return Arguments {
        crypt_type: CryptType::AESGCM,
        kdf_type: KDFType::Argon2,
        file
    };

}

pub fn read_file_to_string(args: &mut Arguments) -> String
{

    let mut s = String::new();

    match args.file.read_to_string(&mut s) {
        Ok(len) => println!("Successfully read {len} bytes to buffer"),
        Err(err) => panic!("Couldn't read the file: {err}"),
    }

    return s;
}