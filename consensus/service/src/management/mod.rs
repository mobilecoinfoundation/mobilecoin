// Copyright (c) 2018-2020 MobileCoin Inc.

use crate::config::Config;
use handlebars::Handlebars;
use lazy_static::lazy_static;
use mc_common::logger::{log, o, Logger};
use mc_util_build_info;
use mc_util_metrics::OpMetrics;
use prometheus::{self, Encoder};
use rouille::{router, Request, Response, Server};
use serde_json::json;
use std::{
    env,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

lazy_static! {
    static ref OP_COUNTER: OpMetrics =
        OpMetrics::new_and_registered("consensus_service_management");
}

pub struct ManagementServer {
    stop_requested: Arc<AtomicBool>,
    thread_handle: Option<thread::JoinHandle<()>>,
    config: Config,
    logger: Logger,
}

impl ManagementServer {
    pub fn new(config: Config, logger: Logger) -> Self {
        let stop_requested = Arc::new(AtomicBool::new(false));

        Self {
            stop_requested,
            thread_handle: None,
            config,
            logger,
        }
    }

    pub fn start(&mut self) {
        let server_config = self.config.clone();
        let server_logger = self.logger.clone();
        let listen_addr =
            self.config.management_listen_addr.clone().expect(
                "attempt to start management server without a configured listening address",
            );

        let server = Server::new(listen_addr.clone(), move |request| {
            let log_ok = |req: &Request, _resp: &Response, _elapsed: std::time::Duration| {
                log::trace!(
                    server_logger,
                    "Management Request: {} {}",
                    req.method(),
                    req.raw_url()
                );
            };
            let log_err = |req: &Request, _elap: std::time::Duration| {
                log::error!(
                    server_logger,
                    "Management Request handler failed: {} {}",
                    req.method(),
                    req.raw_url()
                );
            };

            let req_method = request.method().to_string();
            let req_url = request.raw_url().to_string();
            let handler_config = server_config.clone();
            let handler_logger =
                server_logger.new(o!("req_method" => req_method, "req_url" => req_url));

            rouille::log_custom(request, log_ok, log_err, || {
                OP_COUNTER.inc("requests");
                Self::handle_request(request, handler_config, handler_logger)
            })
        })
        .expect("failed creating management web server");

        let thread_stop_requested = self.stop_requested.clone();
        let thread_logger = self.logger.clone();
        self.thread_handle = Some(
            thread::Builder::new()
                .name("ManagementServer".to_string())
                .spawn(move || {
                    log::info!(
                        thread_logger,
                        "Management thread started, serving requests on {}",
                        listen_addr,
                    );
                    loop {
                        if thread_stop_requested.load(Ordering::SeqCst) {
                            log::info!(thread_logger, "Stop requested");
                            break;
                        }

                        server.poll_timeout(std::time::Duration::from_secs(1));
                    }
                })
                .expect("failed spawning ManagementServer"),
        );
    }

    pub fn stop(&mut self) {
        self.stop_requested.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread_handle.take() {
            thread.join().expect("ManagementServer join failed");
        }
    }

    fn handle_request(request: &Request, config: Config, logger: Logger) -> Response {
        let reg = Handlebars::new();

        router!(request,
             (GET) (/) => {
                let local_node_id = config.node_id();
                let body = reg.render_template(
                    include_str!("templates/index.html"),
                    &json!({
                        "node_id": local_node_id,
                    })
                ).expect("Could not render template");
                Response::html(body)
            },
            (GET) (/set-rust-log) => {
                if let Some(val) = request.get_param("rust_log") {
                    log::info!(logger, "Updating RUST_LOG to '{}'", val);
                    env::set_var("RUST_LOG", val);
                    mc_common::logger::recreate_app_logger();
                }

                Response::redirect_302("/")
            },
            (GET) (/info) => {
                let build : serde_json::Value = {
                    let mut buf = String::new();
                    mc_util_build_info::write_report(&mut buf).unwrap();
                    serde_json::from_str(&buf).expect("build_info wrote a bad json")
                };
                Self::json(&json!({
                    "build": build,
                    "rust_log": env::var("RUST_LOG").unwrap_or_else(|_| "".to_string()),
                    "config": json!({
                        "public_key": config.node_id().public_key,
                        "peer_responder_id": config.peer_responder_id,
                        "client_responder_id": config.client_responder_id,
                        "message_pubkey": config.msg_signer_key.public_key(),
                        "network": config.network_path,
                        "ias_api_key": config.ias_api_key,
                        "ias_spid": config.ias_spid,
                        "peer_listen_uri": config.peer_listen_uri,
                        "client_listen_uri": config.client_listen_uri,
                        "management_listen_addr": config.management_listen_addr,
                        "ledger_path": config.ledger_path,
                        "scp_debug_dump": config.scp_debug_dump,
                    }),
                    "network": config.network(),
                }))
            },
            (GET) (/metrics) => {
                let metric_families = prometheus::gather();
                let encoder = prometheus::TextEncoder::new();
                let mut buffer = vec![];
                encoder.encode(&metric_families, &mut buffer).unwrap();
                Response::text(String::from_utf8(buffer).unwrap_or_else(|_| "from_utf8 failed".to_string()))
            },
            (GET) (/metrics-json) => {
                let metric_families = prometheus::gather();
                let encoder = mc_util_metrics::MetricsJsonEncoder {};
                let mut buffer = vec![];
                encoder.encode(&metric_families, &mut buffer).unwrap();
                Response::text(
                    String::from_utf8(buffer).unwrap_or_else(|_| "from_utf8 failed".to_string())
                ).with_unique_header("Content-Type", "application/json; charset=utf-8")
            },

            // TODO: Debug endpoints, remove those once no longer needed.
            (GET) (/debug/log-error) => {
                log::error!(logger, "Test log message!");
                Response::text("OK")
            },
            (GET) (/debug/panic) => {
                // Need to panic in a thread to avoid unreachable code error.
                std::thread::spawn(|| {
                    panic!("test panic!");
                });
                Response::text("OK")
            },
            _ => Response::empty_404()
        )
    }

    // Copied from rouille::Response::json, changed to return pretty JSON
    #[inline]
    fn json<T>(content: &T) -> Response
    where
        T: serde::Serialize,
    {
        let data = serde_json::to_string_pretty(content).unwrap();

        Response {
            status_code: 200,
            headers: vec![(
                "Content-Type".into(),
                "application/json; charset=utf-8".into(),
            )],
            data: rouille::ResponseBody::from_data(data),
            upgrade: None,
        }
    }

    /*fn lock(&self) -> MutexGuard<ManagementInterfaceInner> {
        self.inner.lock().expect("lock poisoned")
    }*/
}
