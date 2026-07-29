use crate::HushError;

pub trait Serialize {
    fn serialize(self) -> Vec<u8>;
}

pub trait Deserialize {
    fn deserialize(from: Vec<u8>) -> Result<Self, HushError>
    where
        Self: Sized;
}

pub trait Find {
    fn find(&self, term: &str) -> bool;
}
