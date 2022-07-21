// Copyright (c) 2018-2022 The MobileCoin Foundation

//! HTTP server for mint auditor

mod api_types;
mod routes;
mod service;

use crate::db::MintAuditorDb;
use rocket::{custom, routes, Config};
use std::{net::Ipv4Addr, str::FromStr};

/// Start the http server
pub async fn start_http_server(db: MintAuditorDb, port: Option<u16>, host: Option<String>) {
    let service = service::MintAuditorHttpService::new(db);

    let port = port.unwrap_or(8080);
    let host = host.unwrap_or("127.0.0.1".to_string());

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
