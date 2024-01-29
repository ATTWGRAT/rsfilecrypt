use crate::structs::encrypted::Encrypted;

/// Takes data in the Encrypted struct, adds them together:
/// MAC + Ciphertext + nonce
/// Then returns that vector.
///
/// This function clones parts of the structure and doesn't change it
pub fn encode_encrypted_data(enc: &Encrypted) -> Vec<u8> {
    let mut data = enc
        .mac
        .clone()
        .expect("Please generate a mac before encoding!");

    let mut salt1 = enc.salt1.to_vec();
    let mut salt2 = enc.salt2.to_vec();

    data.append(enc.ciphertext.clone().as_mut());

    data.append(enc.nonce.clone().to_vec().as_mut());

    data.append(&mut salt1);
    data.append(&mut salt2);

    return data;
}

/// Takes encrypted encoded data and decodes it into the Encrypted struct.
/// Consumes the original vector.
///
/// SAFETY: The vector has to be in the correct format specified in encode_encrypted data otherwise it may panic.
pub unsafe fn decode_encrypted_data(data: Vec<u8>) -> Encrypted {
    let length = data.len();

    let mac = Some(data[..32].to_vec());
    let salt2: [u8; 16] = data[length - 16..].try_into().unwrap();
    let salt1: [u8; 16] = data[length - 32..length - 16].try_into().unwrap();
    let nonce: [u8; 12] = data[length - 44..length - 32].try_into().unwrap();
    let ciphertext = data[32..length - 44].to_vec();

    let enc = Encrypted {
        salt1,
        salt2,
        mac,
        nonce,
        ciphertext,
    };

    return enc;
}

/// Takes data in the Encrypted struct, adds them together:
/// MAC + Ciphertext + nonce
/// then returns that vector.
///
/// This function consumes the original struct for the sake of performance
pub fn fast_encode_encrypted_data(enc: Encrypted) -> Vec<u8> {
    let mut enc = enc;

    let mut data = enc.mac.expect("Please generate a mac before encoding!");

    data.append(enc.ciphertext.as_mut());

    data.append(enc.nonce.to_vec().as_mut());

    return data;
}
