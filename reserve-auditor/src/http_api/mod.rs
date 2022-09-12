// Copyright (c) 2018-2022 The MobileCoin Foundation

//! HTTP server for reserve auditor

mod api_types;
mod routes;
mod service;

use crate::db::ReserveAuditorDb;
use rocket::{custom, routes, Config};
use std::{net::Ipv4Addr, str::FromStr};

/// Start the http server
pub async fn start_http_server(db: ReserveAuditorDb, port: u16, host: String) {
    let service = service::ReserveAuditorHttpService::new(db);

    let config = Config {
        address: std::net::IpAddr::V4(Ipv4Addr::from_str(&host).unwrap()),
        port,
        ..Config::debug_default()
    };

    if let Err(e) = custom(&config)
        .manage(service)
        .mount(
            "/",
            routes![
                routes::index,
                routes::get_counters,
                routes::get_block_audit_data,
                routes::get_last_block_audit_data,
                routes::get_audited_mints,
                routes::get_audited_burns,
            ],
        )
        .launch()
        .await
    {
        println!("Whoops! Rocket didn't launch!");
        // We drop the error to get a Rocket-formatted panic.
        drop(e);
    }
}
