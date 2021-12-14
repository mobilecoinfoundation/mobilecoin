// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::{error::OverseerError, service::OverseerService};
use mc_fog_recovery_db_iface::RecoveryDb;
use mc_fog_sql_recovery_db::SqlRecoveryDb;
use rocket::{post, routes};

#[post("/arm")]
fn arm(state: rocket::State<OverseerState<SqlRecoveryDb>>) -> Result<String, String> {
    state.overseer_service.arm()
}

#[allow(dead_code)]
#[post("/disarm")]
fn disarm(state: rocket::State<OverseerState<SqlRecoveryDb>>) -> Result<String, String> {
    state.overseer_service.disarm()
}

/// State managed by rocket.
pub struct OverseerState<DB: RecoveryDb + Clone + Send + Sync + 'static>
where
    OverseerError: From<DB::Error>,
{
    /// The Wallet Service implementation.
    pub overseer_service: OverseerService<DB>,
}

/// Returns an instance of a Rocket server.
pub fn initialize_rocket_server(
    rocket_config: rocket::Config,
    state: OverseerState<SqlRecoveryDb>,
) -> rocket::Rocket {
    rocket::custom(rocket_config)
        .mount("/", routes![arm, disarm])
        .manage(state)
}
