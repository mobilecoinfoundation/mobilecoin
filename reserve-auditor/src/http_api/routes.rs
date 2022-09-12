// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Routing for the http server

use crate::{
    db::Counters,
    http_api::{
        api_types::{AuditedBurnResponse, AuditedMintResponse, BlockAuditDataResponse},
        service::ReserveAuditorHttpService,
    },
};
use rocket::{get, serde::json::Json, State};

/// Index route
#[get("/")]
pub fn index() -> &'static str {
    "Welcome to the reserve auditor"
}

/// Get counters
#[get("/counters")]
pub fn get_counters(service: &State<ReserveAuditorHttpService>) -> Result<Json<Counters>, String> {
    match service.get_counters() {
        Ok(counters) => Ok(Json(counters)),
        Err(e) => Err(e.to_string()),
    }
}

/// Get the audit data for a target block
#[get("/block_audit_data/<block_index>")]
pub fn get_block_audit_data(
    block_index: u64,
    service: &State<ReserveAuditorHttpService>,
) -> Result<Json<BlockAuditDataResponse>, String> {
    match service.get_block_audit_data(block_index) {
        Ok(block_audit_data) => Ok(Json(block_audit_data)),
        Err(e) => Err(e.to_string()),
    }
}

/// Get the audit data for the last (most recent) synced block.
#[get("/last_block_audit_data")]
pub fn get_last_block_audit_data(
    service: &State<ReserveAuditorHttpService>,
) -> Result<Json<BlockAuditDataResponse>, String> {
    match service.get_last_block_audit_data() {
        Ok(block_audit_data) => Ok(Json(block_audit_data)),
        Err(e) => Err(e.to_string()),
    }
}

/// Get a paginated list of audited mints, along with corresponding mint tx and
/// gnosis safe deposit
#[get("/audited_mints?<offset>&<limit>")]
pub fn get_audited_mints(
    offset: Option<u64>,
    limit: Option<u64>,
    service: &State<ReserveAuditorHttpService>,
) -> Result<Json<Vec<AuditedMintResponse>>, String> {
    match service.get_audited_mints(offset, limit) {
        Ok(audited_mints) => Ok(Json(audited_mints)),
        Err(e) => Err(e.to_string()),
    }
}

/// Get a paginated list of audited burns, along with corresponding burn tx and
/// gnosis safe withdrawal
#[get("/audited_burns?<offset>&<limit>")]
pub fn get_audited_burns(
    offset: Option<u64>,
    limit: Option<u64>,
    service: &State<ReserveAuditorHttpService>,
) -> Result<Json<Vec<AuditedBurnResponse>>, String> {
    match service.get_audited_burns(offset, limit) {
        Ok(audited_burns) => Ok(Json(audited_burns)),
        Err(e) => Err(e.to_string()),
    }
}
