// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A simple binary that creates a Fog View Router Client and sends off
//! requests to the Fog View Router server.

use mc_fog_uri::FogViewRouterUri;
use mc_fog_view_connection::fog_view_router_client::FogViewRouterGrpcClient;
use std::{str::FromStr, sync::Arc};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), grpcio::Error> {
    let fog_view_router_uri = FogViewRouterUri::from_str("insecure-fog-view-router://127.0.0.1/")
        .expect("failed to connect to fog view router uri");
    let env = Arc::new(
        grpcio::EnvBuilder::new()
            .name_prefix("Main-RPC".to_string())
            .build(),
    );
    let (logger, _global_logger_guard) =
        mc_common::logger::create_app_logger(mc_common::logger::o!());

    let fog_view_router_client =
        FogViewRouterGrpcClient::new(fog_view_router_uri.clone(), env.clone(), logger.clone());

    fog_view_router_client.request().await
}
