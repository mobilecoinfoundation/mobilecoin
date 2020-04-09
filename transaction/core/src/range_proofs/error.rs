// Copyright (c) 2018-2020 MobileCoin Inc.

use failure::Fail;

#[derive(Debug, Fail, PartialEq)]
pub enum Error {
    #[fail(display = "ProofError: {:?}", _0)]
    ProofError(bulletproofs::ProofError),

    #[fail(display = "ResizeError")]
    ResizeError,
}

impl From<bulletproofs::ProofError> for Error {
    fn from(e: bulletproofs::ProofError) -> Self {
        Error::ProofError(e)
    }
}
