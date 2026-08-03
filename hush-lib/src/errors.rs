#[derive(Debug)]
pub enum HushError {
    FileOpen {
        reason: std::io::Error,
    },
    Encryption {
        reason: aes_gcm::aead::Error,
    },
    Utf8 {
        reason: std::string::FromUtf8Error,
    },
    UnsupportedRecordType {
        type_id: u8,
    },
    RecordRead {
        reason: String,
    },
    FileRead {
        cause: std::io::Error,
        context: String,
    },
    FileWrite {
        cause: std::io::Error,
        context: String,
    },
    FileSeek {
        cause: std::io::Error,
        context: String,
    },
    FileRename {
        cause: std::io::Error,
        context: String,
    },
}

impl HushError {
    pub fn file_open_error(value: std::io::Error) -> Self {
        HushError::FileOpen { reason: value }
    }
    pub fn record_read_error(value: &str) -> Self {
        HushError::RecordRead {
            reason: value.to_string(),
        }
    }
    pub fn file_read_error(cause: std::io::Error, context: &str) -> Self {
        HushError::FileRead {
            cause,
            context: context.to_string(),
        }
    }
    pub fn file_write_error(cause: std::io::Error, context: &str) -> Self {
        HushError::FileWrite {
            cause,
            context: context.to_string(),
        }
    }
    pub fn file_seek_error(cause: std::io::Error, context: &str) -> Self {
        HushError::FileSeek {
            cause,
            context: context.to_string(),
        }
    }
    pub fn file_rename_error(cause: std::io::Error, context: &str) -> Self {
        HushError::FileRename {
            cause,
            context: context.to_string(),
        }
    }
}

impl From<std::string::FromUtf8Error> for HushError {
    fn from(value: std::string::FromUtf8Error) -> Self {
        HushError::Utf8 { reason: value }
    }
}

impl From<aes_gcm::aead::Error> for HushError {
    fn from(value: aes_gcm::aead::Error) -> Self {
        HushError::Encryption { reason: value }
    }
}

impl std::fmt::Display for HushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HushError::FileOpen { reason } => write!(f, "reason: {}", reason),
            HushError::Encryption { reason } => write!(f, "encryption error: {}", reason),
            HushError::Utf8 { reason } => write!(f, "error converting utf8 {}", reason),
            HushError::UnsupportedRecordType { type_id } => write!(f, "type id: {}", type_id),
            HushError::RecordRead { reason } => write!(f, "can't read record: {}", reason),
            HushError::FileRead { cause, context } => {
                write!(f, "can't read file: {}; context: {}", cause, context)
            }
            HushError::FileWrite { cause, context } => {
                write!(f, "can't write file: {}; context: {}", cause, context)
            }
            HushError::FileSeek { cause, context } => {
                write!(f, "can't seek file: {}; context: {}", cause, context)
            }
            HushError::FileRename { cause, context } => {
                write!(f, "can't rename file: {}; context: {}", cause, context)
            }
        }
    }
}
