mod errors;
pub mod record;
mod traits;
mod util;

use crate::record::Record;
use crate::record::Records;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::path::PathBuf;

use aes_gcm::{Aes256Gcm, Key, KeyInit};
use hush_derive::{Deserialize, Serialize};
use pbkdf2::{hmac::Hmac, pbkdf2_array, sha2::Sha256};

use crate::errors::HushError;
use crate::traits::{Deserialize, Find, Serialize};

const COUNTER_SIZE: u64 = 8;
const PBKDF_SALT_SIZE: usize = 12;

pub struct Hush {
    cipher: Aes256Gcm,
    file: std::fs::File,
    file_name: PathBuf,
}

impl Hush {
    pub fn new(file_name: &Path) -> Result<Self, HushError> {
        let mut file = util::open_file(file_name)?;
        file.seek(SeekFrom::Start(COUNTER_SIZE))
            .map_err(|e| HushError::file_seek_error(e, "can't seek existing file"))?;

        let mut salt = [0u8; PBKDF_SALT_SIZE];
        file.read_exact(&mut salt)
            .map_err(|e| HushError::file_read_error(e, "can't read salt"))?;

        let key = pbkdf2_array::<Hmac<Sha256>, 32>(b"password", &salt, 400_000)
            .expect("HMAC can be initialized with any key length");
        let key = Key::<Aes256Gcm>::from_slice(&key);
        // let key = Key::<Aes256Gcm>::from_slice(&[
        //     210, 222, 84, 140, 198, 142, 75, 193, 29, 175, 14, 159, 235, 10, 142, 16, 105, 252,
        //     232, 96, 30, 88, 146, 155, 245, 121, 40, 247, 194, 186, 230, 96,
        // ]);
        let cipher = Aes256Gcm::new(key);
        Ok(Self {
            cipher,
            file,
            file_name: file_name.to_path_buf(),
        })
    }

    pub fn read_all(&mut self) -> Result<Vec<Record>, HushError> {
        let cipher = self.cipher.clone();
        self.records()?
            .map(|er| er.and_then(|r| r.decrypt(&cipher)))
            .collect()
    }

    pub fn find(&mut self, term: &str) -> Result<Vec<Record>, HushError> {
        let mut res = vec![];
        let cipher = self.cipher.clone();
        for rec in self.records()? {
            let decrypted = rec?.decrypt(&cipher)?;
            if decrypted.find(term) {
                res.push(decrypted);
            }
        }

        Ok(res)
    }

    pub fn append_key_value(&mut self, key: &str, value: &str) -> Result<(), HushError> {
        let id = self.increment_counter()?;
        let record = Record::new_key_value(id, key, value);
        self.append_record(record)
    }

    fn append_record(&mut self, record: Record) -> Result<(), HushError> {
        self.seek_file_end()?;
        self.file
            .write_all(&record.encrypt(&self.cipher)?.as_bytes())
            .map_err(|e| HushError::file_write_error(e, "can't append record"))
    }

    pub fn mark_deleted(&mut self, record_id: u64) -> Result<(), HushError> {
        let orig_filename = self.file_name.clone();
        let mut temp_filename = orig_filename.clone();
        temp_filename.as_mut_os_string().push(".temp");
        let mut bkp_filename = orig_filename.clone();
        bkp_filename.as_mut_os_string().push(".bkp");

        let mut temp = Hush::new(Path::new(&temp_filename))?;
        let cipher = self.cipher.clone();
        for res in self.records()? {
            let record = res?.decrypt(&cipher)?;
            if record.id() == record_id {
                temp.append_record(record.deleted())?;
            } else {
                temp.append_record(record)?;
            }
        }

        std::fs::rename(&orig_filename, &bkp_filename).map_err(|e| {
            HushError::file_rename_error(
                e,
                &format!(
                    "can't backup from {} to {}",
                    orig_filename.display(),
                    bkp_filename.display()
                ),
            )
        })?;

        std::fs::rename(&temp_filename, &orig_filename).map_err(|e| {
            HushError::file_rename_error(
                e,
                &format!(
                    "can't rename temporary file from {} to {}",
                    temp_filename.display(),
                    orig_filename.display()
                ),
            )
        })
    }

    fn seek_file_from_start(&mut self, offset: u64) -> Result<u64, HushError> {
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| HushError::file_seek_error(e, "can't seek file to write counter"))
    }

    fn seek_file_end(&mut self) -> Result<u64, HushError> {
        self.file
            .seek(SeekFrom::End(0))
            .map_err(|e| HushError::file_seek_error(e, "can't seek file to write counter"))
    }

    fn increment_counter(&mut self) -> Result<u64, HushError> {
        self.seek_file_from_start(0)?;
        let mut counter = [0u8; COUNTER_SIZE as usize];
        self.file
            .read_exact(&mut counter)
            .map_err(|e| HushError::file_read_error(e, "can't read records counter"))?;
        let mut counter = u64::from_be_bytes(counter);

        counter += 1;
        self.seek_file_from_start(0)?;
        self.file.write_all(&counter.to_be_bytes()).map_err(|e| {
            HushError::file_write_error(e, "can't write incremented record counter")
        })?;
        self.file.flush().unwrap(); // todo
        Ok(counter)
    }

    fn records(&mut self) -> Result<Records<'_>, HushError> {
        Records::new(&mut self.file)
    }
}
