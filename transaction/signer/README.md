# mc-transaction-signer

This crate defines the API for communication with external transaction-signer implementations such as the offline signer (see `src/main.rs`) or hardware wallets, and provides helpers for the implementation of external transaction-signers.

### Layout

- `src/lib.rs` provides a standard transaction signer interface, parsing objects, executing a transaction using the provided signer implementation, then returning encoded responses
- `src/traits.rs` provides a set of traits that must be implemented by transaction-signers
- `src/types.rs` provides encodable types for interaction between full-service and external signer implementations
- `src/main.rs` is the offline-signer implementation, using the standard interface and types defined in this crate

### Types

Types are provided for interaction between full-service and an external transaction-signer.

- `AccountInfo` describes an view-only account for importing
- Recovering an existing account requires support for key image scanning
  - `TxoSyncReq` provides a list of unsynced txouts to the external transaction signer
  - `TxoSyncResp` provides a list of synced txouts back to full-service
- Transaction signing is, well the whole point really
  - `TxSignReq` is an unsigned transaction request from full-service
  - `TxSignResp` is a signed transaction response to full-service
