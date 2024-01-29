use ring::rand::{SecureRandom, SystemRandom};

pub fn generate_random_salt(rand: &SystemRandom) -> [u8; 16] {
    let mut salt: [u8; 16] = [0; 16];
    rand.fill(&mut salt).unwrap();
    return salt;
}
