use std::{fmt, fs, io};
use std::io::{Error, Read, stdout, Write};
use std::path::Path;
use crate::encoding::Encrypted;
use crate::inout::Action::{Decrypt, Encrypt};

pub enum Action {
    Encrypt,
    Decrypt
}


pub struct Arguments {
    pub action: Action,
    pub file: String,
}

#[derive(Debug, Clone)]
pub struct IoError
{
    error: String,
}
impl fmt::Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl Arguments {
    ///Function for parsing cmd-line arguments into the Arguments structure
    pub fn parse(args: &Vec<String>) -> Result<Arguments, IoError>
    {
        if args.len() < 3
        {
            return Err(IoError{error: String::from("Not enough arguments provided!") });
        }

        let action: Action;

        match args[2].to_ascii_uppercase().as_str() {
            "D" | "DECRYPT" => action = Decrypt,
            "E" | "ENCRYPT" => action = Encrypt,
            _ => return Err(IoError{error: String::from("Wrong action argument: (ENCRYPT | E) | (DECRYPT | D)")})
        }

        return Ok(Arguments {
            file: args[1].clone(),
            action
        });
    }


    ///Reads the file bytes into a buffer and returns it. Path is taken from the arguments struct
    pub fn read_file(&self) -> io::Result<Vec<u8>>
    {
        fs::read(&self.file)
    }
}

///Writes a buffer of Vec<u8> to a file with the given path string
pub fn write_buffer_to_file(buffer: &Vec<u8>, path: &String)
{
   match fs::write(Path::new(path.as_str()), buffer)
   {
       Ok(_) => println!("Successfully written {} bytes to {}", buffer.len(), path),
       Err(_) => println!("Failed while writing to {}", path)
   }
}


pub fn password_query() -> String
{
    let mut pass = String::new();
    println!("Provide a password: ");
    io::stdin().read_line(&mut pass).unwrap();
    print!("{}[2J", 27 as char);
    println!("Password provided");
    return pass;
}
/// Takes data in the Encrypted struct, adds them together:
/// MAC + Ciphertext + nonce
/// then returns that vector.
///
/// This function consumes the original struct for the sake of performance
pub fn fast_encode_encrypted_data(enc: Encrypted) -> Vec<u8>
{
    let mut enc = enc;

    let mut data = enc.mac.expect("Please generate a mac before encoding!");

    data.append(enc.ciphertext.as_mut());

    data.append(enc.nonce.to_vec().as_mut());

    return data;
}


