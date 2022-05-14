//! Interfaces for signing transactions

mod dummy_signer;
pub use dummy_signer::DummyRingSigner;

mod local_signer;
pub use local_signer::LocalRingSigner;

mod traits;
pub use traits::{Error, InputSecret, OneTimeKeyOrAlternative, RingSigner, SignableInputRing};
