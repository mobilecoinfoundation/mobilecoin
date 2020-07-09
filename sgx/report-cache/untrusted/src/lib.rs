// Copyright (c) 2018-2020 MobileCoin Inc.

//! The untrusted side of enclave report caching.

use displaydoc::Display;
use mc_attest_core::{
    IasQuoteError, PibError, ProviderId, QuoteError, QuoteSignType, TargetInfoError,
    VerificationReport, VerificationReportData, VerifyError,
};
use mc_attest_enclave_api::Error as AttestEnclaveError;
use mc_attest_net::{Error as RaError, RaClient};
use mc_attest_untrusted::QuotingEnclave;
use mc_common::logger::{log, Logger};
use mc_sgx_report_cache_api::{Error as ReportableEnclaveError, ReportableEnclave};
use retry::{delay::Fibonacci, retry, Error as RetryError, OperationResult};
use std::convert::TryFrom;

#[derive(Debug, Display)]
pub enum Error {
    /// Error getting quoting enclave target info: {0}
    TargetInfo(TargetInfoError),

    /// Failed to communicate with IAS: {0}
    RaClient(RaError),

    /// Quoting enclave failure: {0}
    Quote(QuoteError),

    /// Failed to update TCB in response to a PIB: {0}
    TcbUpdate(PibError),

    /// Attest verify report error: {0}
    Verify(VerifyError),

    /// Reportable enclave error: {0}
    ReportableEnclave(ReportableEnclaveError),
}

impl From<TargetInfoError> for Error {
    fn from(src: TargetInfoError) -> Self {
        Self::TargetInfo(src)
    }
}

impl From<RaError> for Error {
    fn from(src: RaError) -> Self {
        Self::RaClient(src)
    }
}

impl From<QuoteError> for Error {
    fn from(src: QuoteError) -> Self {
        Self::Quote(src)
    }
}

impl From<PibError> for Error {
    fn from(src: PibError) -> Self {
        Self::TcbUpdate(src)
    }
}

impl From<VerifyError> for Error {
    fn from(src: VerifyError) -> Self {
        Self::Verify(src)
    }
}

impl From<ReportableEnclaveError> for Error {
    fn from(src: ReportableEnclaveError) -> Self {
        Self::ReportableEnclave(src)
    }
}

pub struct ReportCache<E: ReportableEnclave, R: RaClient /* + Send + Sync + 'static*/> {
    enclave: E,
    ra_client: R,
    ias_spid: ProviderId,
    logger: Logger,
}

impl<E: ReportableEnclave, R: RaClient> ReportCache<E, R> {
    pub fn start_report_cache(&self) -> Result<VerificationReport, Error> {
        log::debug!(
            self.logger,
            "Starting remote attestation report process, getting QE enclave targeting info..."
        );
        let (qe_info, gid) =
            retry(
                Fibonacci::from_millis(1000).take(7),
                || match QuotingEnclave::target_info() {
                    Ok((qe_info, gid)) => OperationResult::Ok((qe_info, gid)),
                    Err(ti_err) => match ti_err {
                        TargetInfoError::QeBusy => OperationResult::Retry(TargetInfoError::QeBusy),
                        other => OperationResult::Err(other),
                    },
                },
            )
            .map_err(|e| match e {
                RetryError::Operation {
                    error,
                    total_delay,
                    tries,
                } => match error {
                    TargetInfoError::QeBusy => TargetInfoError::Retry(format!(
                        "Attempted to retrieve TargetInfo {} times over {:?}, giving up...",
                        tries, total_delay
                    )),
                    other_ti_err => other_ti_err,
                },
                RetryError::Internal(s) => TargetInfoError::Retry(s),
            })?;
        log::debug!(self.logger, "Getting EREPORT from node enclave...");
        let (report, quote_nonce) = self.enclave.new_ereport(qe_info)?;
        log::debug!(self.logger, "Downloading SigRL for GID '{}'...", &gid);
        let sigrl = self.ra_client.get_sigrl(gid)?;
        log::debug!(self.logger, "Quoting report...");
        let (quote, qe_report) = QuotingEnclave::quote_report(
            &report,
            QuoteSignType::Linkable,
            &self.ias_spid,
            &quote_nonce,
            &sigrl,
        )?;
        log::debug!(self.logger, "Double-checking quoted report with enclave...");
        let ias_nonce = self.enclave.verify_quote(quote.clone(), qe_report)?;
        log::debug!(
            self.logger,
            "Verifying quote with remote attestation service..."
        );
        let retval = self.ra_client.verify_quote(&quote, Some(ias_nonce))?;
        log::debug!(
            self.logger,
            "Quote verified by remote attestation service..."
        );
        Ok(retval)
    }

    /// Update the IAS report cached within the enclave.
    pub fn update_enclave_report_cache(&mut self) -> Result<(), Error> {
        log::debug!(
            self.logger,
            "Starting enclave report cache update process..."
        );
        let mut ias_report = self.start_report_cache()?;
        log::debug!(self.logger, "Verifying IAS report with enclave...");
        let retval = match self.enclave.verify_ias_report(ias_report.clone()) {
            Ok(()) => {
                log::debug!(self.logger, "Enclave accepted report as valid...");
                Ok(())
            }
            Err(ReportableEnclaveError::AttestEnclave(AttestEnclaveError::Verify(
                VerifyError::IasQuote(IasQuoteError::GroupRevoked(_, pib)),
            )))
            | Err(ReportableEnclaveError::AttestEnclave(AttestEnclaveError::Verify(
                VerifyError::IasQuote(IasQuoteError::ConfigurationNeeded(_, pib)),
            )))
            | Err(ReportableEnclaveError::AttestEnclave(AttestEnclaveError::Verify(
                VerifyError::IasQuote(IasQuoteError::GroupOutOfDate(_, pib)),
            ))) => {
                // To get here, we've gotten an error back from the enclave telling us
                // the TCB is out-of-date.
                log::debug!(
                    self.logger,
                    "IAS requested TCB update, attempting to update..."
                );
                QuotingEnclave::update_tcb(&pib)?;
                log::debug!(
                    self.logger,
                    "TCB update complete, restarting reporting process"
                );
                ias_report = self.start_report_cache()?;
                log::debug!(self.logger, "Verifying IAS report with enclave (again)...");
                self.enclave.verify_ias_report(ias_report.clone())?;
                log::debug!(self.logger, "Enclave accepted new report as valid...");
                Ok(())
            }
            Err(other) => Err(other.into()),
        };

        if retval.is_ok() {
            let ias_report_data = VerificationReportData::try_from(&ias_report)?;
            let timestamp = ias_report_data.parse_timestamp()?;

            // counters::ENCLAVE_REPORT_TIMESTAMP.set(timestamp.timestamp());

            log::debug!(
                self.logger,
                "Enclave accepted report as valid, report generated at {:?}...",
                timestamp
            );
        }

        retval
    }
}
