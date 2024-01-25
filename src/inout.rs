use std::{fs, io};
use std::io::Read;
use std::path::Path;
use crate::encoding::Encrypted;


pub struct Arguments {
    pub file: String,
}

impl Arguments {
    ///Function for parsing cmd-line arguments into the Arguments structure
    pub fn parse(args: &Vec<String>) -> Arguments
    {
        if args.len() == 1
        {
            panic!("No arguments provided")
        }

        //todo: check if args[2] is a valid encryption method
        return Arguments {
            file: args[1].clone()
        };
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


