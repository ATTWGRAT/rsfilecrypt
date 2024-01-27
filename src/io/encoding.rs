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

    data.append(enc.ciphertext.clone().as_mut());

    data.append(enc.nonce.clone().to_vec().as_mut());

    return data;
}

/// Takes encrypted encoded data and decodes it into the Encrypted struct.
/// Consumes the original vector.
///
/// SAFETY: The vector has to be in the correct format specified in encode_encrypted data otherwise it may panic.
pub unsafe fn decode_encrypted_data(data: Vec<u8>) -> Encrypted {
    let length = data.len();

    let mac = Some(data[..32].to_vec());
    let nonce: [u8; 12] = data[length - 12..].try_into().unwrap();
    let ciphertext = data[32..length - 12].to_vec();

    let enc = Encrypted {
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
