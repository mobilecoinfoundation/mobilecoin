// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A GRPC server that implements the `RemoteWallet` service using the sample
//! paykit. This can be used by the fog conformance tests to run tests against
//! the sample paykit.

use grpcio::{RpcContext, RpcStatus, UnarySink};
use mc_account_keys::{AccountKey, RootEntropy, RootIdentity};
use mc_common::logger::{create_root_logger, log, Logger};
use mc_fog_sample_paykit::{
    empty::Empty,
    remote_wallet::{
        BalanceCheckResponse, DebugRequest, DebugResponse, FollowupBalanceCheckRequest,
        FreshBalanceCheckRequest, StopRequest,
    },
    remote_wallet_grpc::{create_remote_wallet_api, RemoteWalletApi},
    Client, ClientBuilder,
};
use mc_util_grpc::{
    rpc_internal_error, rpc_invalid_arg_error, send_result, ConnectionUriGrpcioServer,
};
use mc_util_uri::{ConsensusClientUri, Uri, UriScheme};
use std::{
    convert::TryFrom,
    str::FromStr,
    sync::{Arc, Mutex},
    thread::sleep,
    time::Duration,
};
use structopt::StructOpt;

/// Remote Wallet Uri Scheme
#[derive(Debug, Hash, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct RemoteWalletScheme {}
impl UriScheme for RemoteWalletScheme {
    /// The part before the '://' of a URL.
    const SCHEME_SECURE: &'static str = "remote-wallet";
    const SCHEME_INSECURE: &'static str = "insecure-remote-wallet";

    /// Default port numbers
    const DEFAULT_SECURE_PORT: u16 = 9443;
    const DEFAULT_INSECURE_PORT: u16 = 9090;
}

/// Uri used when talking to the remote wallet service, with the right default
/// ports and scheme.
pub type RemoteWalletUri = Uri<RemoteWalletScheme>;

/// State shared between GRPC calls.
#[derive(Default)]
struct State {
    /// A list of clients we are keeping track of.
    clients: Vec<Option<Client>>,
}

#[derive(Debug, StructOpt)]
struct Config {
    /// gRPC listening URI for client requests.
    #[structopt(long, default_value = "insecure-remote-wallet://127.0.0.1:9090")]
    pub listen_uri: RemoteWalletUri,
}

#[derive(Clone)]
struct RemoteWalletService {
    state: Arc<Mutex<State>>,
    logger: Logger,
}

impl RemoteWalletService {
    pub fn new(state: Arc<Mutex<State>>, logger: Logger) -> Self {
        Self { state, logger }
    }

    fn fresh_balance_check_impl(
        &self,
        request: FreshBalanceCheckRequest,
    ) -> Result<BalanceCheckResponse, RpcStatus> {
        let root_entropy = RootEntropy::try_from(&request.root_entropy[..])
            .map_err(|err| rpc_invalid_arg_error("root_entropy", err, &self.logger))?;

        let root_identity = RootIdentity::from(&root_entropy);

        let account_key = AccountKey::from(&root_identity);

        // Note: The balance check program is not supposed to submit anything to
        // consensus or talk to consensus, so this is just a dummy value
        let consensus_client_uri = ConsensusClientUri::from_str("mc://127.0.0.1")
            .expect("Could not create dummy consensus client uri");

        // Figure out the view/ledger URIs and adapt the scheme to match what the Rust
        // clients expect.
        let fog_uri = request.get_fog_uri();
        let (fog_view_uri, fog_ledger_uri) = if fog_uri.starts_with("fog://") {
            (
                fog_uri.replace("fog://", "fog-view://"),
                fog_uri.replace("fog://", "fog-ledger://"),
            )
        } else if fog_uri.starts_with("insecure-fog://") {
            (
                fog_uri.replace("insecure-fog://", "insecure-fog-view://"),
                fog_uri.replace("insecure-fog://", "insecure-fog-ledger://"),
            )
        } else {
            return Err(rpc_internal_error(
                "fog_uri",
                "Unknown fog uri scheme, must be fog:// or insecure-fog://",
                &self.logger,
            ));
        };

        // Create client and perform balance check.
        let mut client = ClientBuilder::new(
            consensus_client_uri,
            fog_view_uri,
            fog_ledger_uri,
            account_key,
            self.logger.clone(),
        )
        .build();

        let (balance, block_count) = client
            .check_balance()
            .map_err(|err| rpc_internal_error("check_balance", err, &self.logger))?;

        let mut state = self.state.lock().expect("mutex poisoned");
        let client_id = state.clients.len();
        state.clients.push(Some(client));

        let response = BalanceCheckResponse {
            client_id: client_id as u32,
            balance,
            block_count: block_count.into(),
            ..Default::default()
        };
        log::info!(self.logger, "Fresh balance check: {:?}", response);
        Ok(response)
    }

    fn followup_balance_check_impl(
        &self,
        request: FollowupBalanceCheckRequest,
    ) -> Result<BalanceCheckResponse, RpcStatus> {
        let mut state = self.state.lock().expect("mutex poisoned");
        match state.clients.get_mut(request.client_id as usize) {
            Some(Some(client)) => {
                let (balance, block_count) = client
                    .check_balance()
                    .map_err(|err| rpc_internal_error("check_balance", err, &self.logger))?;

                let response = BalanceCheckResponse {
                    client_id: request.client_id,
                    balance,
                    block_count: block_count.into(),
                    ..Default::default()
                };
                log::info!(self.logger, "Followup balance check: {:?}", response);
                Ok(response)
            }

            _ => Err(rpc_invalid_arg_error(
                "client_id",
                "invalid client id",
                &self.logger,
            )),
        }
    }

    fn debug_impl(&self, request: DebugRequest) -> Result<DebugResponse, RpcStatus> {
        let mut state = self.state.lock().expect("mutex poisoned");
        match state.clients.get_mut(request.client_id as usize) {
            Some(Some(client)) => {
                let debug_info = client.debug_balance();

                let response = DebugResponse {
                    debug_info,
                    ..Default::default()
                };
                log::info!(self.logger, "Debug info: {:?}", response);
                Ok(response)
            }

            _ => Err(rpc_invalid_arg_error(
                "client_id",
                "invalid client id",
                &self.logger,
            )),
        }
    }
}

impl RemoteWalletApi for RemoteWalletService {
    fn fresh_balance_check(
        &mut self,
        ctx: RpcContext,
        request: FreshBalanceCheckRequest,
        sink: UnarySink<BalanceCheckResponse>,
    ) {
        send_result(
            ctx,
            sink,
            self.fresh_balance_check_impl(request),
            &self.logger,
        )
    }

    fn followup_balance_check(
        &mut self,
        ctx: RpcContext,
        request: FollowupBalanceCheckRequest,
        sink: UnarySink<BalanceCheckResponse>,
    ) {
        send_result(
            ctx,
            sink,
            self.followup_balance_check_impl(request),
            &self.logger,
        )
    }

    fn stop(&mut self, ctx: RpcContext, request: StopRequest, sink: UnarySink<Empty>) {
        let mut state = self.state.lock().expect("mutex poisoned");
        if request.client_id as usize >= state.clients.len() {
            send_result(
                ctx,
                sink,
                Err(rpc_invalid_arg_error(
                    "client_id",
                    "Invalid client id",
                    &self.logger,
                )),
                &self.logger,
            )
        } else {
            state.clients[request.client_id as usize] = None;
            send_result(ctx, sink, Ok(Empty::default()), &self.logger)
        }
    }

    fn debug(&mut self, ctx: RpcContext, request: DebugRequest, sink: UnarySink<DebugResponse>) {
        send_result(ctx, sink, self.debug_impl(request), &self.logger)
    }

    fn reset(&mut self, ctx: RpcContext, _request: Empty, sink: UnarySink<Empty>) {
        let mut state = self.state.lock().expect("mutex poisoned");
        state.clients.clear();

        send_result(ctx, sink, Ok(Empty::default()), &self.logger)
    }
}

fn main() {
    let config = Config::from_args();
    let logger = create_root_logger();

    log::info!(logger, "Starting RPC server.");

    let grpc_env = Arc::new(
        grpcio::EnvBuilder::new()
            .name_prefix("RemoteWallet-RPC".to_string())
            .build(),
    );

    let remote_wallet_service = create_remote_wallet_api(RemoteWalletService::new(
        Arc::new(Mutex::new(State::default())),
        logger.clone(),
    ));

    let server_builder = grpcio::ServerBuilder::new(grpc_env)
        .register_service(remote_wallet_service)
        .bind_using_uri(&config.listen_uri, logger.clone());

    let mut server = server_builder.build().expect("failed building grpc server");
    server.start();

    log::info!(logger, "Server started");

    loop {
        sleep(Duration::from_secs(1));
    }
}
