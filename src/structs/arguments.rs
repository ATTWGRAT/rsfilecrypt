pub enum Action {
    Encrypt,
    Decrypt,
}

pub struct Arguments {
    pub action: Action,
    pub file: String,
}

///Function for parsing cmd-line arguments into the Arguments structure
pub fn parse(args: &Vec<String>) -> Result<Arguments, crate::io::errors::IoError> {
    if args.len() < 3 {
        return Err(crate::io::errors::IoError {
            error: String::from("Not enough arguments provided!"),
        });
    }

    let action: Action;

    match args[1].to_ascii_uppercase().as_str() {
        "D" | "DECRYPT" => action = Action::Decrypt,
        "E" | "ENCRYPT" => action = Action::Encrypt,
        _ => {
            return Err(crate::io::errors::IoError {
                error: String::from("Wrong action argument: (ENCRYPT | E) | (DECRYPT | D)"),
            })
        }
    }

    return Ok(Arguments {
        file: args[2].clone(),
        action,
    });
}
