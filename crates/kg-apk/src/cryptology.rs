use std::{error::Error, fmt};

use aes::Aes128;
use cipher::{BlockModeEncrypt, KeyInit, KeyIvInit, block_padding::Pkcs7};

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128EcbEnc = ecb::Encryptor<Aes128>;

#[derive(Debug)]
pub(crate) enum PackError {
    MissingCipherParameters,
    EncryptionFailed,
}

impl fmt::Display for PackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCipherParameters => write!(f, "Required key and IV parameters were not provided"),
            Self::EncryptionFailed => write!(f, "AES encryption or padding application failed"),
        }
    }
}

impl Error for PackError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PackType {
    Standard,
    Server,
    ImageData,
}

fn get_md5_key(text: &str) -> [u8; 16] {
    let digest = format!("{:x}", md5::compute(text.as_bytes()));

    let mut key = [0u8; 16];
    key.copy_from_slice(&digest.as_bytes()[..16]);
    key
}

fn encrypt_cbc(data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>, PackError> {
    let encryptor = Aes128CbcEnc::new(key.into(), iv.into());
    let mut buffer = data.to_vec();
    let pos = buffer.len();
    buffer.resize(pos + 16, 0);

    let encrypted_slice =
        encryptor.encrypt_padded::<Pkcs7>(&mut buffer, pos).map_err(|_| PackError::EncryptionFailed)?;

    Ok(encrypted_slice.to_vec())
}

fn encrypt_ecb(data: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, PackError> {
    let encryptor = Aes128EcbEnc::new(key.into());
    let mut buffer = data.to_vec();
    let pos = buffer.len();
    buffer.resize(pos + 16, 0);

    let encrypted_slice =
        encryptor.encrypt_padded::<Pkcs7>(&mut buffer, pos).map_err(|_| PackError::EncryptionFailed)?;

    Ok(encrypted_slice.to_vec())
}

pub(crate) fn encrypt_chunk(
    data: &[u8],
    pack_type: PackType,
    key: Option<&[u8; 16]>,
    iv: Option<&[u8; 16]>,
) -> Result<Vec<u8>, PackError> {
    match pack_type {
        PackType::ImageData => Ok(data.to_vec()),
        PackType::Server => encrypt_ecb(data, &get_md5_key("battlecats")),
        PackType::Standard => {
            let (Some(cipher_key), Some(cipher_iv)) = (key, iv) else {
                return Err(PackError::MissingCipherParameters);
            };
            encrypt_cbc(data, cipher_key, cipher_iv)
        }
    }
}

pub(crate) fn encrypt_list(data: &str) -> Result<Vec<u8>, PackError> {
    encrypt_ecb(data.as_bytes(), &get_md5_key("pack"))
}
