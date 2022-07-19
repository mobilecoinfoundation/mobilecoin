use crate::{db::MintAuditorDb, http_api::service::MintAuditorHttpService};
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
