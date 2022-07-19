// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mint auditor service for handling http requests

use crate::{db::MintAuditorDb, http_api::routes::CatResponse};
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
}
