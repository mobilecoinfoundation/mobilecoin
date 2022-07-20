use crate::{
    db::MintAuditorDb,
    http_api::service::{BlockAuditDataResponse, CountersResponse, MintAuditorHttpService},
};
use rocket::{get, State};

use rocket::serde::{json::Json, Serialize};

/// temp
pub struct AuditorDb(pub MintAuditorDb);

/// temp index route
#[get("/")]
pub fn index() -> &'static str {
    "Hello, world!"
}

/// temp
#[derive(Serialize)]
pub struct CatResponse {
    /// temp
    pub cat: String,
}
/// temp cat route
#[get("/cat")]
pub fn get_cat(db: &State<AuditorDb>) -> Json<CatResponse> {
    Json(MintAuditorHttpService::get_cat(&db.0).expect("woops"))
}

/// temp
#[derive(Serialize)]
pub struct TestResponse {
    /// temp
    pub num_mints: u64,
}
/// temp cat route
#[get("/db-test")]
pub fn get_db_test(db: &State<AuditorDb>) -> Json<TestResponse> {
    Json(MintAuditorHttpService::get_db_test(&db.0).expect("woops"))
}

/// get counters
#[get("/counters")]
pub fn get_counters(db: &State<AuditorDb>) -> Json<CountersResponse> {
    Json(CountersResponse::from(
        &MintAuditorHttpService::get_counters(&db.0).expect("woops"),
    ))
}

/// get counters
#[get("/block_audit_data?<block_index>")]
pub fn get_block_audit_data(
    block_index: u64,
    db: &State<AuditorDb>,
) -> Json<BlockAuditDataResponse> {
    Json(MintAuditorHttpService::get_block_audit_data(block_index, &db.0).expect("woops"))
}

/// get counters
#[get("/last_block_audit_data")]
pub fn get_last_block_audit_data(db: &State<AuditorDb>) -> Json<BlockAuditDataResponse> {
    Json(MintAuditorHttpService::get_last_block_audit_data(&db.0).expect("woops"))
}
