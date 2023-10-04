// Copyright (c) 2023 The MobileCoin Foundation

//! A hardware implementation of DCAP quote generation.

use crate::TargetInfoError;
use mc_attest_core::QuoteError;
use mc_sgx_core_types::{Report, TargetInfo};
use mc_sgx_dcap_ql::{Error, QeTargetInfo, TryFromReport};
use mc_sgx_dcap_quoteverify::{Collateral as CollateralTrait, Error as QuoteVerifyError};
use mc_sgx_dcap_types::{Collateral, QlError, Quote3};

pub struct HwQuotingEnclave;

impl HwQuotingEnclave {
    /// Get a quote based on the application enclave's `report`.
    pub fn quote_report(report: &Report) -> Result<Quote3<Vec<u8>>, QuoteError> {
        let quote = Quote3::try_from_report(report.clone()).map_err(|error| match error {
            Error::Quote3(error) => QuoteError::Quote3(error),
            Error::QuoteLibrary(error) => QuoteError::QlError(error),
            _ => QuoteError::QlError(QlError::UnsupportedLoadingPolicy),
        })?;
        Ok(quote)
    }

    /// Get the target info for the quoting enclave.
    pub fn target_info() -> Result<TargetInfo, TargetInfoError> {
        Ok(TargetInfo::for_quoting_enclave()?)
    }

    /// Get the `Collateral` for the quote.
    pub fn collateral<Q: AsRef<[u8]>>(quote: &Quote3<Q>) -> Result<Collateral, QuoteVerifyError> {
        quote.collateral()
    }
}
