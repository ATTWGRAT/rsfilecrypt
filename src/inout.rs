use std::fs::File;
use std::io::Read;
use std::path::Path;

pub struct Arguments {
    crypt_type: String,
    file: File,
}
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
        Err(err) => panic!("Couldn't open {} : {err}", path.display()),
    };


    return Arguments { crypt_type: args[0].clone(), file};

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