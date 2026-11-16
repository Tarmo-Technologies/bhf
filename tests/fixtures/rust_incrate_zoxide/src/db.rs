// SPDX-License-Identifier: Apache-2.0

//! A directory-backed database, opened the way zoxide opens its own.

use std::path::Path;

/// The parsed database.
pub struct Database {
    pub entries: u32,
}

impl Database {
    /// Read `<data_dir>/db.zo`. Behind the `ZO` magic, version 1 trusts the
    /// file's entry count and indexes past the end of the file.
    pub fn open_dir(data_dir: impl AsRef<Path>) -> Result<Database, String> {
        let path = data_dir.as_ref().join("db.zo");
        let data = std::fs::read(&path).map_err(|e| e.to_string())?;
        if data.len() < 4 || data[0] != b'Z' || data[1] != b'O' {
            return Err("not a database".to_owned());
        }
        let count = data[3] as usize;
        let mut entries = 0;
        if data[2] == 1 {
            for i in 0..count {
                entries += u32::from(data[4 + i]);
            }
        }
        Ok(Database { entries })
    }
}
