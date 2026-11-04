use std::{error::Error, fmt};

use aes::Aes128;
use cipher::{BlockModeDecrypt, KeyInit, KeyIvInit, block_padding::Pkcs7};

type Aes128CbcDec = cbc::Decryptor<Aes128>;
type Aes128EcbDec = ecb::Decryptor<Aes128>;

#[derive(Debug, Clone, Copy)]
pub(crate) enum Region {
    Ja,
    En,
    Tw,
    Ko,
}

#[derive(Debug)]
pub(crate) enum PackError {
    InvalidHexFormat(Region),
    InvalidKeyLength(Region),
    DecryptionFailed,
    ListDecryptionFailed,
}

impl fmt::Display for PackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHexFormat(region) => {
                write!(f, "Invalid hexadecimal format in the key or IV for region {region:?}")
            }
            Self::InvalidKeyLength(region) => {
                write!(f, "Decoded key or IV for region {region:?} must be exactly 16 bytes")
            }
            Self::DecryptionFailed => write!(f, "AES decryption or padding validation failed"),
            Self::ListDecryptionFailed => write!(f, "List manifest decryption failed (Invalid keys or corrupted file)"),
        }
    }
}

impl Error for PackError {}

struct RegionalCipher {
    key: [u8; 16],
    iv: [u8; 16],
}

pub(crate) struct Keys {
    ciphers: Vec<RegionalCipher>,
}

impl Keys {
    pub(crate) fn parse(tuples: &[(Region, &str, &str)]) -> Result<Self, PackError> {
        let mut ciphers = Vec::with_capacity(tuples.len());
        for (region, hex_key, hex_iv) in tuples {
            ciphers.push(Self::parse_cipher(*region, hex_key, hex_iv)?);
        }
        Ok(Self { ciphers })
    }

    fn parse_cipher(region: Region, hex_key: &str, hex_iv: &str) -> Result<RegionalCipher, PackError> {
        let key_bytes = hex::decode(hex_key).map_err(|_| PackError::InvalidHexFormat(region))?;
        let iv_bytes = hex::decode(hex_iv).map_err(|_| PackError::InvalidHexFormat(region))?;

        let key: [u8; 16] = key_bytes.try_into().map_err(|_| PackError::InvalidKeyLength(region))?;
        let iv: [u8; 16] = iv_bytes.try_into().map_err(|_| PackError::InvalidKeyLength(region))?;

        Ok(RegionalCipher { key, iv })
    }
}

fn get_md5_key(text: &str) -> [u8; 16] {
    let digest = format!("{:x}", md5::compute(text.as_bytes()));

    let mut key = [0u8; 16];
    key.copy_from_slice(&digest.as_bytes()[..16]);
    key
}

fn final_block(data: &[u8]) -> Option<(usize, [u8; 16])> {
    let start = data.len().checked_sub(16).filter(|_| data.len().is_multiple_of(16))?;
    let mut block = [0u8; 16];
    block.copy_from_slice(&data[start..]);
    Some((start, block))
}

fn padded_cbc(data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> bool {
    let Some((start, mut block)) = final_block(data) else {
        return false;
    };

    let mut chain = *iv;
    if start >= 16 {
        chain.copy_from_slice(&data[start - 16..start]);
    }

    Aes128CbcDec::new(key.into(), (&chain).into()).decrypt_padded::<Pkcs7>(&mut block).is_ok()
}

fn padded_ecb(data: &[u8], key: &[u8; 16]) -> bool {
    final_block(data)
        .is_some_and(|(_, mut block)| Aes128EcbDec::new(key.into()).decrypt_padded::<Pkcs7>(&mut block).is_ok())
}

fn decrypt_cbc(data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>, PackError> {
    let decryptor = Aes128CbcDec::new(key.into(), iv.into());
    let mut buffer = data.to_vec();
    let length = decryptor.decrypt_padded::<Pkcs7>(&mut buffer).map_err(|_| PackError::DecryptionFailed)?.len();
    buffer.truncate(length);
    Ok(buffer)
}

fn decrypt_ecb(data: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, PackError> {
    let decryptor = Aes128EcbDec::new(key.into());
    let mut buffer = data.to_vec();
    let length = decryptor.decrypt_padded::<Pkcs7>(&mut buffer).map_err(|_| PackError::DecryptionFailed)?.len();
    buffer.truncate(length);
    Ok(buffer)
}

pub(crate) fn check_integrity(data: &[u8], filename: &str) -> bool {
    let ext = filename.rsplit_once('.').map(|(_, e)| e.to_lowercase());

    match ext.as_deref() {
        Some("png") => data.starts_with(&[0x89, 0x50, 0x4E, 0x47]),
        Some("csv" | "tsv" | "list" | "json" | "maanim" | "mamodel" | "imgcut") => std::str::from_utf8(data).is_ok(),
        _ => true,
    }
}

pub(crate) fn decrypt_chunk(data: &[u8], internal_filename: &str, keys: &Keys) -> Vec<u8> {
    for cipher in &keys.ciphers {
        if padded_cbc(data, &cipher.key, &cipher.iv)
            && let Ok(result) = decrypt_cbc(data, &cipher.key, &cipher.iv)
            && check_integrity(&result, internal_filename)
        {
            return result;
        }
    }

    let server_key = get_md5_key("battlecats");
    if padded_ecb(data, &server_key)
        && let Ok(result) = decrypt_ecb(data, &server_key)
        && check_integrity(&result, internal_filename)
    {
        return result;
    }

    data.to_vec()
}

pub(crate) fn decrypt_list(data: &[u8]) -> Result<String, PackError> {
    let pack_key = get_md5_key("pack");
    if let Ok(bytes) = decrypt_ecb(data, &pack_key)
        && let Ok(manifest_text) = String::from_utf8(bytes)
    {
        return Ok(manifest_text);
    }

    let server_key = get_md5_key("battlecats");
    if let Ok(bytes) = decrypt_ecb(data, &server_key)
        && let Ok(manifest_text) = String::from_utf8(bytes)
    {
        return Ok(manifest_text);
    }

    Err(PackError::ListDecryptionFailed)
}
