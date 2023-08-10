// Copyright (c) 2018-2023 The MobileCoin Foundation

use lazy_static::lazy_static;
use prometheus::{
    histogram_opts, register_histogram, register_histogram_vec, register_int_counter, Histogram,
    HistogramVec, IntCounter,
};

// Initialize global metrics
lazy_static! {
    pub static ref STORE_QUERY_REQUESTS: HistogramVec = register_histogram_vec!(
        histogram_opts!(
            "fog_view_router_store_query_requests",
            "Queries to individual stores"
        ),
        &["store_uri", "status"]
    )
    .expect("metric cannot be created");
    pub static ref CLIENT_QUERY_RETRIES: IntCounter = register_int_counter!(
        "fog_view_router_bulk_query_retry",
        "Query retries per client request"
    )
    .expect("metric cannot be created");
    pub static ref ROUTER_QUERY_REQUESTS: Histogram = register_histogram!(histogram_opts!(
        "fog_view_router_bulk_query_requests",
        "Queries to router"
    ))
    .expect("metric cannot be created");
    pub static ref AUTH_CLIENT_REQUESTS: IntCounter = register_int_counter!(
        "fog_view_router_auth_client_requests",
        "Auth requests to stores"
    )
    .expect("metric cannot be created");
}
