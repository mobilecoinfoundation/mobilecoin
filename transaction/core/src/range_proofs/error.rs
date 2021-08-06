// Copyright (c) 2018-2021 The MobileCoin Foundation

use bulletproofs_og::ProofError;
use displaydoc::Display;

#[derive(Debug, Display, PartialEq)]
pub enum Error {
    /// ProofError: `{0:?}`
    ProofError(ProofError),

    /// Resize error
    ResizeError,
}

impl From<ProofError> for Error {
    fn from(e: ProofError) -> Self {
        Error::ProofError(e)
    }
}
