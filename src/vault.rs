use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Vault {
    entries: Vec<Entry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Entry {
    name: String,
    username: String,
    password: String,
}

impl Vault {
    pub fn new() -> Self {
        Vault { entries: vec![] }
    }

    pub fn from_entries(entries: Vec<Entry>) -> Self {
        Vault { entries }
    }
}

impl Entry {
    pub fn new(name: String, username: String, password: String) -> Self {
        Entry {
            name,
            username,
            password,
        }
    }
}
