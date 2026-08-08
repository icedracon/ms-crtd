use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("missing required attribute: {0}")]
    MissingAttribute(&'static str),

    #[error("attribute {0} present but value list is empty")]
    EmptyAttribute(&'static str),

    #[error("integer attribute {name} could not be decoded from {byte_len} bytes")]
    BadInteger { name: &'static str, byte_len: usize },

    #[error("string attribute {name} is not valid UTF-16LE or UTF-8")]
    BadString { name: &'static str },
}

pub type Result<T> = std::result::Result<T, Error>;
