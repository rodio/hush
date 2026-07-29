use std::io::Write;

use aes_gcm::aead::rand_core::{OsRng, RngCore};

use crate::{errors::HushError, COUNTER_SIZE, PBKDF_SALT_SIZE};

pub(crate) fn open_file(file_name: &str) -> Result<std::fs::File, HushError> {
    match std::fs::exists(file_name) {
        Ok(true) => (),
        Ok(false) => {
            let mut f = std::fs::File::options()
                .read(true)
                .write(true)
                .create_new(true)
                .open(file_name)
                .map_err(HushError::file_open_error)?;
            f.write_all(&[0; COUNTER_SIZE as usize]).map_err(|e| {
                HushError::file_write_error(e, "can't write counter to a newly created file")
            })?;
            let mut salt: [u8; PBKDF_SALT_SIZE] = [0; PBKDF_SALT_SIZE];
            OsRng.fill_bytes(&mut salt);
            f.write_all(&salt).map_err(|e| {
                HushError::file_read_error(e, "can't write salt to a newly created file")
            })?;
            return Ok(f);
        }
        Err(e) => return Err(HushError::file_open_error(e)),
    }

    std::fs::File::options()
        .read(true)
        .write(true)
        .create_new(false)
        .open(file_name)
        .map_err(HushError::file_open_error)
}

pub(crate) fn read_u8_as_usize(start: usize, from: &[u8]) -> Result<(u8, usize), HushError> {
    let end = start + size_of::<u8>();
    if from.len() < end {
        return Err(HushError::record_read_error(
            "can't read record's key length: plaintext too short",
        ));
    }
    let ret = u8::from_be_bytes(
        from[start..end]
            .try_into()
            .expect("plaintext should be long enough"),
    );

    Ok((ret, end))
}

pub(crate) fn read_u64(start: usize, from: &[u8]) -> Result<(u64, usize), HushError> {
    let end = start + size_of::<u64>();
    if from.len() < end {
        return Err(HushError::record_read_error(
            "can't read record's key length: plaintext too short",
        ));
    }
    let ret = u64::from_be_bytes(
        from[start..end]
            .try_into()
            .expect("plaintext should be long enough"),
    );

    Ok((ret, end))
}

pub(crate) fn read_len(start: usize, len: usize, from: &[u8]) -> Result<(&[u8], usize), HushError> {
    let end = start + len;
    if from.len() < end {
        return Err(HushError::record_read_error(
            "can't read record's key: plaintext too short",
        ));
    }
    Ok((&from[start..end], end))
}

pub(crate) fn read_u32_as_usize(start: usize, from: &[u8]) -> Result<(usize, usize), HushError> {
    let end = start + size_of::<u32>();
    if from.len() < end {
        return Err(HushError::record_read_error(
            "can't read record's key length: plaintext too short",
        ));
    }
    let ret = u32::from_be_bytes(
        from[start..end]
            .try_into()
            .expect("plaintext should be long enough"),
    )
    .try_into()
    .expect("only runs on 64 bit architectures");

    Ok((ret, end))
}
