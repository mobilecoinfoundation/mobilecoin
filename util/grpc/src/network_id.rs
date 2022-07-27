use grpcio::{RpcContext, RpcStatus, RpcStatusCode};

/// The string used for the network id GRPC header
/// Note that a corresponding HTTP header is defined by the go-grpc-gateway
/// code: Network-Id
pub const NETWORK_ID_GRPC_HEADER: &str = "network-id";

/// The error message used when a network id mismatch occurs
pub const NETWORK_ID_MISMATCH_ERR_MSG: &str = "network-id mismatch:";

/// Test the network id of a request against the expected value on the server
/// side. This does nothing if the client does not supply a NETWORK_ID header.
pub fn check_request_network_id(
    server_network_id: &str,
    ctx: &RpcContext,
) -> Result<(), RpcStatus> {
    for (header, value) in ctx.request_headers().iter() {
        if header == NETWORK_ID_GRPC_HEADER && server_network_id.as_bytes() != value {
            return Err(RpcStatus::with_message(
                RpcStatusCode::FAILED_PRECONDITION,
                format!("{} '{}'", NETWORK_ID_MISMATCH_ERR_MSG, server_network_id),
            ));
        }
    }
    Ok(())
}
