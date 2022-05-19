// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Server object that exposes HTTP methods that allow the client to access
//! the [service::OverseerService].
//!
//! HTTP Client -> *Overseer Rocket Server* -> OverseerService -> OverseerWorker

use crate::{
    error::OverseerError, responses::GetIngestSummariesResponse, service::OverseerService,
};
use mc_fog_recovery_db_iface::RecoveryDb;
use mc_fog_sql_recovery_db::SqlRecoveryDb;
use rocket::{get, post, routes, serde::json::Json};

#[post("/enable")]
fn enable(state: &rocket::State<OverseerState<SqlRecoveryDb>>) -> Result<String, String> {
    state.overseer_service.enable()
}

#[post("/disable")]
fn disable(state: &rocket::State<OverseerState<SqlRecoveryDb>>) -> Result<String, String> {
    state.overseer_service.disable()
}

#[get("/status")]
fn get_status(state: &rocket::State<OverseerState<SqlRecoveryDb>>) -> Result<String, String> {
    state.overseer_service.get_status()
}

#[get("/ingest_summaries")]
fn get_ingest_summaries(
    state: &rocket::State<OverseerState<SqlRecoveryDb>>,
) -> Result<Json<GetIngestSummariesResponse>, String> {
    state.overseer_service.get_ingest_summaries().map(Json)
}

/// Produces metrics for Prometheus.
///
/// Meant to be called only by the Prometheus pull mechanism.
#[get("/metrics")]
fn get_metrics(state: &rocket::State<OverseerState<SqlRecoveryDb>>) -> Result<String, String> {
    state.overseer_service.get_metrics()
}

/// State managed by rocket. As of right now, it's just the OverseerService.
/// Rocket can be viewed as a thin wrapper over this service, allowing it
/// to be exposed via HTTPS APIs.
pub struct OverseerState<DB: RecoveryDb + Clone + Send + Sync + 'static>
where
    OverseerError: From<DB::Error>,
{
    /// The OverseerService implementation.
    pub overseer_service: OverseerService<DB>,
}

/// Returns an instance of a Rocket server.
#[must_use = "Use with a Client or call launch"]
pub fn initialize_rocket_server<T: rocket::figment::Provider>(
    rocket_config: T,
    state: OverseerState<SqlRecoveryDb>,
) -> rocket::Rocket<rocket::Build> {
    rocket::custom(rocket_config)
        .mount(
            "/",
            routes![
                enable,
                disable,
                get_status,
                get_metrics,
                get_ingest_summaries
            ],
        )
        .manage(state)
}
