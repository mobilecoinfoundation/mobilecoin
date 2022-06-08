// Copyright (c) 2018-2022 The MobileCoin Foundation

//! HTTP faucet service backed by mobilecoind

#![deny(missing_docs)]
#![feature(proc_macro_hygiene, decl_macro)]

use clap::Parser;
use mc_common::logger::{create_app_logger, log, o};
use mc_mobilecoind_dev_faucet::{data_types::*, Config, State};
use rocket::{get, post, routes, serde::json::Json};

/// Request payment from the faucet, and map the rust result onto json for
/// rocket appropriately
#[post("/", format = "json", data = "<req>")]
async fn post(
    state: &rocket::State<State>,
    req: Json<JsonFaucetRequest>,
) -> Json<JsonSubmitTxResponse> {
    Json(state.handle_post(&req).await.into())
}

/// Request status of the faucet, and map the rust result onto json for rocket
/// apporpriately
#[get("/status")]
async fn status(state: &rocket::State<State>) -> Json<JsonFaucetStatus> {
    Json(state.handle_status().await.into())
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    mc_common::setup_panic_handler();
    let _sentry_guard = mc_common::sentry::init();

    let config = Config::parse();

    let (logger, _global_logger_guard) = create_app_logger(o!());
    log::info!(
        logger,
        "Starting mobilecoind-dev-faucet HTTP on {}:{}, connecting to {}",
        config.listen_host,
        config.listen_port,
        config.mobilecoind_uri,
    );

    let figment = rocket::Config::figment()
        .merge(("port", config.listen_port))
        .merge(("address", config.listen_host.clone()));

    let state = State::new(&config, &logger);

    let _rocket = rocket::custom(figment)
        .mount("/", routes![post, status])
        .manage(state)
        .launch()
        .await?;
    Ok(())
}
