use kanidm_hsm_crypto::LoadableMachineKey;
use rusqlite::{named_params, Connection, OptionalExtension};
use serde::de::DeserializeOwned;

#[derive(Debug)]
pub enum CacheError {
    Sqlite,
    SerdeJson,
}

pub struct Db {
    conn: Connection,
}

impl Db {
    pub fn new(path: &str) -> Result<Self, CacheError> {
        let conn = Connection::open(path).map_err(|_| CacheError::Sqlite)?;
        Ok(Db { conn })
    }

    pub fn get_hsm_machine_key(&mut self) -> Result<Option<LoadableMachineKey>, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM hsm_int_t WHERE key = 'mk'")
            .map_err(|_| CacheError::Sqlite)?;

        let data: Option<Vec<u8>> = stmt
            .query_row([], |row| row.get(0))
            .optional()
            .map_err(|_| CacheError::Sqlite)?;

        match data {
            Some(d) => serde_json::from_slice(d.as_slice()).map_err(|_| CacheError::SerdeJson),
            None => Ok(None),
        }
    }

    pub fn get_tagged_hsm_key<K: DeserializeOwned>(
        &mut self,
        tag: &str,
    ) -> Result<Option<K>, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM hsm_data_t WHERE key = :key")
            .map_err(|_| CacheError::Sqlite)?;

        let data: Option<Vec<u8>> = stmt
            .query_row(named_params! { ":key": tag }, |row| row.get(0))
            .optional()
            .map_err(|_| CacheError::Sqlite)?;

        match data {
            Some(d) => serde_json::from_slice(d.as_slice()).map_err(|_| CacheError::SerdeJson),
            None => Ok(None),
        }
    }
}
