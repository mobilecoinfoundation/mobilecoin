// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mint auditor service for handling http requests

use crate::{
    db::{MintAuditorDb, MintTx},
    http_api::routes::{CatResponse, TestResponse},
};
use displaydoc::Display;
use rocket::serde::Serialize;

/// temp
#[derive(Display, Debug, Serialize)]
pub enum AuditorServiceError {
    /// Error with auditor service
    AuditorServiceError(String),
}

/// temp
pub struct MintAuditorHttpService {}

/// temp
impl MintAuditorHttpService {
    /// temp
    pub fn get_cat(_mint_auditor_db: &MintAuditorDb) -> Result<CatResponse, AuditorServiceError> {
        Ok(CatResponse {
            cat: "meow".to_string(),
        })
    }

    /// temp
    pub fn get_db_test(
        mint_auditor_db: &MintAuditorDb,
    ) -> Result<TestResponse, AuditorServiceError> {
        let conn = mint_auditor_db.get_conn().unwrap();

        let txos = MintTx::find_unaudited_mint_txs(&conn).unwrap();

        Ok(TestResponse {
            num_mints: txos.len() as u64,
        })
    }
}
