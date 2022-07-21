// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Routing for the http server

use crate::{
    db::Counters,
    http_api::{api_types::BlockAuditDataResponse, service::MintAuditorHttpService},
};
use rocket::{get, serde::json::Json, State};

/// Index route
#[get("/")]
pub fn index() -> &'static str {
    "Welcome to the mint auditor"
}

/// Get counters
#[get("/counters")]
pub fn get_counters(service: &State<MintAuditorHttpService>) -> Result<Json<Counters>, String> {
    match service.get_counters() {
        Ok(counters) => Ok(Json(counters)),
        Err(e) => Err(e.to_string()),
    }
}

/// Get the audit data for a target block
#[get("/block_audit_data/<block_index>")]
pub fn get_block_audit_data(
    block_index: u64,
    service: &State<MintAuditorHttpService>,
) -> Result<Json<BlockAuditDataResponse>, String> {
    match service.get_block_audit_data(block_index) {
        Ok(block_audit_data) => Ok(Json(block_audit_data)),
        Err(e) => Err(e.to_string()),
    }
}

/// Get the audit data for the last (most recent) synced block.
#[get("/last_block_audit_data")]
pub fn get_last_block_audit_data(
    service: &State<MintAuditorHttpService>,
) -> Result<Json<BlockAuditDataResponse>, String> {
    match service.get_last_block_audit_data() {
        Ok(block_audit_data) => Ok(Json(block_audit_data)),
        Err(e) => Err(e.to_string()),
    }
}
