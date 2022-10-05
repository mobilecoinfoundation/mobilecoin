use grpcio::{RpcContext, RpcStatus, RpcStatusCode};

/// The string used for the chain id GRPC header
/// Note that a corresponding HTTP header is defined by the go-grpc-gateway
/// code: Chain-Id
pub const CHAIN_ID_GRPC_HEADER: &str = "chain-id";

/// The error message used when a chain id mismatch occurs
pub const CHAIN_ID_MISMATCH_ERR_MSG: &str = "chain-id mismatch:";

/// Test the chain id of a request against the value on the server side.
/// This does nothing if the client does not supply a chain-id header.
pub fn check_request_chain_id(server_chain_id: &str, ctx: &RpcContext) -> Result<(), RpcStatus> {
    for (header, value) in ctx.request_headers().iter() {
        if header == CHAIN_ID_GRPC_HEADER && server_chain_id.as_bytes() != value {
            return Err(RpcStatus::with_message(
                RpcStatusCode::FAILED_PRECONDITION,
                format!("{} '{}'", CHAIN_ID_MISMATCH_ERR_MSG, server_chain_id),
            ));
        }
    }
    Ok(())
}
