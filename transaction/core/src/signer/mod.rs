//! Interfaces for signing transactions

mod traits;
pub use traits::{Error, RingSigner};

mod local_signer;
pub use local_signer::LocalRingSigner;
