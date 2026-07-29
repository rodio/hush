use crate::traits::Find;
use crate::util;
use crate::Deserialize;
use crate::Serialize;
use crate::PBKDF_SALT_SIZE;
use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes256Gcm,
};
use hush_derive::Find;
use std::io::Read;
use std::io::Seek;

use crate::errors::HushError;

const AES_NONCE_SIZE: usize = 12;

pub(crate) struct Records<'a> {
    pub file: &'a std::fs::File, // todo ::new()
}

impl Records<'_> {
    pub fn new(file: &mut std::fs::File) -> Result<Records<'_>, HushError> {
        file.seek(std::io::SeekFrom::Start(
            (size_of::<u64>() + PBKDF_SALT_SIZE) as u64,
        ))
        .map_err(|e| HushError::file_seek_error(e, "can't iterate over records"))?;

        Ok(Records { file })
    }
}

impl Iterator for Records<'_> {
    type Item = Result<EncryptedRecord, HushError>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut len: [u8; 8] = [0u8; 8];
        match self.file.read(&mut len) {
            Ok(0) => return None,
            Ok(8) => {}
            Ok(n) => {
                return Some(Err(HushError::record_read_error(&format!(
                    "can't read length of the ciphertext; expected 8 bytes, got {n}"
                ))));
            }
            Err(e) => {
                return Some(Err(HushError::file_read_error(
                    e,
                    "error reading length of the ciphertext",
                )));
            }
        }
        let ciphertext_len = u64::from_be_bytes(len) as usize;

        let mut nonce: [u8; AES_NONCE_SIZE] = [0u8; AES_NONCE_SIZE];
        match self.file.read(&mut nonce) {
            Ok(AES_NONCE_SIZE) => {}
            Ok(n) => {
                return Some(Err(HushError::record_read_error(&format!(
                    "can't read nonce of the record; expected {AES_NONCE_SIZE} bytes, got {n}"
                ))));
            }
            Err(e) => {
                return Some(Err(HushError::file_read_error(e, "error reading nonce")));
            }
        }

        let mut ciphertext = vec![0u8; ciphertext_len];
        match self.file.read(&mut ciphertext) {
            Ok(n) if ciphertext_len == n => {}
            Ok(n) => {
                return Some(Err(HushError::record_read_error(&format!(
                    "can't read ciphertext of the record; expected {ciphertext_len} bytes, got {n}"
                ))));
            }
            Err(e) => {
                return Some(Err(HushError::file_read_error(
                    e,
                    "error reading ciphertext",
                )));
            }
        }

        Some(Ok(EncryptedRecord { nonce, ciphertext }))
    }
}

pub(crate) struct EncryptedRecord {
    nonce: [u8; AES_NONCE_SIZE],
    ciphertext: Vec<u8>,
}

impl EncryptedRecord {
    pub(crate) fn as_bytes(&self) -> Vec<u8> {
        let mut res = Vec::new();
        res.extend_from_slice(&self.len().to_be_bytes());
        res.extend_from_slice(&self.nonce);
        res.extend_from_slice(&self.ciphertext);
        res
    }

    pub(crate) fn decrypt(&self, cipher: &Aes256Gcm) -> Result<Record, HushError> {
        let decrypted = cipher.decrypt(&self.nonce.into(), self.ciphertext.as_ref())?;
        Record::deserialize(decrypted)
    }

    fn len(&self) -> u64 {
        self.ciphertext.len() as u64
    }
}

#[derive(Debug)]
pub struct SearchableString(String);
impl SearchableString {
    fn as_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}

impl From<String> for SearchableString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl AsRef<str> for SearchableString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug)]
pub struct NonSearchableString(String);
impl NonSearchableString {
    fn as_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}
impl From<String> for NonSearchableString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

#[derive(Debug, Serialize, Deserialize, Find)]
#[repr(u8)]
pub enum Record {
    KeyValue {
        deleted: u8,
        id: u64,
        key: SearchableString,
        value: NonSearchableString,
    } = 0,
    TitleKeyValue {
        deleted: u8,
        id: u64,
        title: SearchableString,
        key: SearchableString,
        value: NonSearchableString,
    } = 1, // title key value
}

impl Record {
    pub(crate) fn new_key_value(id: u64, key: &str, value: &str) -> Self {
        Self::KeyValue {
            deleted: 0,
            id,
            key: SearchableString(key.to_string()),
            value: NonSearchableString(value.to_string()),
        }
    }

    pub(crate) fn encrypt(self, cipher: &Aes256Gcm) -> Result<EncryptedRecord, HushError> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
        let plaintext: Vec<u8> = self.serialize();
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_slice())?;
        Ok(EncryptedRecord {
            nonce: nonce.into(),
            ciphertext,
        })
    }
}

impl std::fmt::Debug for EncryptedRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedRecord")
            .field("ciphertext_len", &self.len())
            .field("nonce", &self.nonce)
            .field("ciphertext", &self.ciphertext)
            .finish()
    }
}
