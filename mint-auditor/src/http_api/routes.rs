use crate::http_api::{
    api_types::{AuditorDb, BlockAuditDataResponse, CountersResponse},
    service::MintAuditorHttpService,
};
use rocket::{get, serde::json::Json, State};

/// index route
#[get("/")]
pub fn index() -> &'static str {
    "Welcome to the mint auditor"
}

/// get counters
#[get("/counters")]
pub fn get_counters(db: &State<AuditorDb>) -> Result<Json<CountersResponse>, String> {
    match MintAuditorHttpService::get_counters(&db.0) {
        Ok(counters) => Ok(Json(CountersResponse::from(&counters))),
        Err(e) => Err(e.to_string()),
    }
}

/// Get the audit data for a target block
#[get("/block_audit_data?<block_index>")]
pub fn get_block_audit_data(
    block_index: u64,
    db: &State<AuditorDb>,
) -> Result<Json<BlockAuditDataResponse>, String> {
    match MintAuditorHttpService::get_block_audit_data(block_index, &db.0) {
        Ok(block_audit_data) => Ok(Json(block_audit_data)),
        Err(e) => Err(e.to_string()),
    }
}

/// Get the audit data for the last (most recent) synced block.
#[get("/last_block_audit_data")]
pub fn get_last_block_audit_data(
    db: &State<AuditorDb>,
) -> Result<Json<BlockAuditDataResponse>, String> {
    match MintAuditorHttpService::get_last_block_audit_data(&db.0) {
        Ok(block_audit_data) => Ok(Json(block_audit_data)),
        Err(e) => Err(e.to_string()),
    }
}
