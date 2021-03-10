// Copyright (c) 2018-2021 The MobileCoin Foundation

/// Trait for user-defined EnclaveIdentity objects that produce data that must
/// go into Reports. An AkeEnclaveState contains an EnclaveIdentity object and
/// queries it when it needs to make a report.
///
/// Note: EnclaveIdentity should ALWAYS return the same 32 bytes, and should not
/// exhibit any interior mutability, or your reports will not be stable and you
/// will have a very bad time.
pub trait EnclaveIdentity {
    fn get_bytes_for_report(&self) -> [u8; 32];
}

/// The null identity is used for enclaves that have no extra stuff to go in the
/// reports
#[derive(Default, Clone)]
pub struct NullIdentity {}

impl EnclaveIdentity for NullIdentity {
    fn get_bytes_for_report(&self) -> [u8; 32] {
        [0u8; 32]
    }
}
