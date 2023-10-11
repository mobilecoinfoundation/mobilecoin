// Copyright (c) 2018-2022 The MobileCoin Foundation

//! The untrusted side of enclave report caching.

#![allow(clippy::result_large_err)]
use displaydoc::Display;
use mc_attest_core::{DcapEvidence, QuoteError, VerifyError};
use mc_attest_untrusted::{DcapQuotingEnclave, TargetInfoError};
use mc_common::logger::{log, o, Logger};
use mc_sgx_report_cache_api::{Error as ReportableEnclaveError, ReportableEnclave};
use retry::{delay::Fibonacci, retry, OperationResult};
use std::{
    io::Error as IOError,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{sleep, Builder as ThreadBuilder, JoinHandle},
    time::{Duration, Instant},
};

/// How long to wait between report refreshes.
pub const REPORT_REFRESH_INTERVAL: Duration = Duration::from_secs(18 * 60 * 60); // 18 hours.

/// Possible errors.
#[derive(Debug, Display)]
pub enum Error {
    /// Error getting quoting enclave target info: {0}
    TargetInfo(TargetInfoError),

    /// Quoting enclave failure: {0}
    Quote(QuoteError),

    /// Quote library error: {0}
    Ql(mc_sgx_dcap_ql::Error),

    /// Quote verification library error: {0}
    QuoteVerifyLibrary(mc_sgx_dcap_quoteverify::Error),

    /// Attest verify report error: {0}
    Verify(VerifyError),

    /// Reportable enclave error: {0}
    ReportableEnclave(ReportableEnclaveError),

    /// IO error: {0}
    IO(IOError),

    /// Thread join error
    ThreadJoin,
}

impl From<TargetInfoError> for Error {
    fn from(src: TargetInfoError) -> Self {
        Self::TargetInfo(src)
    }
}

impl From<QuoteError> for Error {
    fn from(src: QuoteError) -> Self {
        Self::Quote(src)
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

impl From<IOError> for Error {
    fn from(src: IOError) -> Self {
        Self::IO(src)
    }
}

impl From<mc_sgx_dcap_ql::Error> for Error {
    fn from(src: mc_sgx_dcap_ql::Error) -> Self {
        Self::Ql(src)
    }
}

impl From<mc_sgx_dcap_quoteverify::Error> for Error {
    fn from(src: mc_sgx_dcap_quoteverify::Error) -> Self {
        Self::QuoteVerifyLibrary(src)
    }
}

pub struct ReportCache<E: ReportableEnclave> {
    enclave: E,
    logger: Logger,
}

impl<E: ReportableEnclave> ReportCache<E> {
    pub fn new(enclave: E, logger: Logger) -> Self {
        Self { enclave, logger }
    }

    pub fn start_report_cache(&self) -> Result<DcapEvidence, Error> {
        log::debug!(
            self.logger,
            "Starting remote attestation report process, getting QE enclave targeting info..."
        );
        let qe_info =
            retry(
                Fibonacci::from_millis(1000).take(7),
                || match DcapQuotingEnclave::target_info() {
                    Ok(qe_info) => OperationResult::Ok(qe_info),
                    Err(ti_err) => match ti_err {
                        TargetInfoError::QeBusy => OperationResult::Retry(TargetInfoError::QeBusy),
                        other => OperationResult::Err(other),
                    },
                },
            )
            .map_err(|e| match e.error {
                TargetInfoError::QeBusy => TargetInfoError::Retry(format!(
                    "Attempted to retrieve TargetInfo {} times over {:?}, giving up...",
                    e.tries, e.total_delay
                )),
                other_ti_err => other_ti_err,
            })?;
        log::warn!(self.logger, "Getting EREPORT from node enclave...");
        let (report, report_data_contents) = self.enclave.new_ereport(qe_info)?;
        log::warn!(self.logger, "Quoting report...");
        let quote = DcapQuotingEnclave::quote_report(&report)?;
        log::warn!(self.logger, "Double-checking quoted report with enclave...");

        let report_body = quote.app_report_body();
        let mr_signer = report_body.mr_signer();
        let mr_enclave = report_body.mr_enclave();
        let evidence = DcapEvidence {
            collateral: DcapQuotingEnclave::collateral(&quote)?,
            quote,
            report_data: report_data_contents,
        };

        // log::warn!(self.logger, "Verifying attestation evidence");
        // self.enclave.verify_attestation_evidence(evidence.clone())?;

        log::warn!(
            self.logger,
            "Measurements: MrEnclave: {} MrSigner: {}",
            mr_enclave,
            mr_signer
        );

        Ok(evidence)
    }

    /// Update the attestation evidence cached within the enclave.
    pub fn update_enclave_report_cache(&self) -> Result<(), Error> {
        log::warn!(
            self.logger,
            "Starting enclave report cache update process..."
        );
        let attestation_evidence = self.start_report_cache()?;

        log::warn!(
            self.logger,
            "Verifying attestation evidence with enclave..."
        );
        Ok(self
            .enclave
            .verify_attestation_evidence(attestation_evidence)?)
    }
}

pub struct ReportCacheThread {
    /// Join handle used to wait for the thread to terminate.
    join_handle: Option<JoinHandle<()>>,

    /// Stop request trigger, used to signal the thread to stop.
    stop_requested: Arc<AtomicBool>,
}

impl ReportCacheThread {
    pub fn start<E: ReportableEnclave + Send + 'static>(
        enclave: E,
        logger: Logger,
    ) -> Result<Self, Error> {
        let logger = logger.new(o!("mc.enclave_type" => std::any::type_name::<E>()));

        let report_cache = ReportCache::new(enclave, logger.clone());
        log::warn!(logger, "Du Hast");
        report_cache.update_enclave_report_cache()?;
        log::warn!(logger, "No Hast");

        let stop_requested = Arc::new(AtomicBool::new(false));
        let thread_stop_requested = stop_requested.clone();

        let join_handle = Some(
            ThreadBuilder::new()
                .name(format!("ReportCache-{}", std::any::type_name::<E>()))
                .spawn(move || {
                    Self::thread_entrypoint(report_cache, thread_stop_requested, logger)
                })?,
        );

        Ok(Self {
            join_handle,
            stop_requested,
        })
    }

    pub fn stop(&mut self) -> Result<(), Error> {
        if let Some(join_handle) = self.join_handle.take() {
            self.stop_requested.store(true, Ordering::SeqCst);
            join_handle.join().map_err(|_| Error::ThreadJoin)?;
        }

        Ok(())
    }

    fn thread_entrypoint<E: ReportableEnclave>(
        report_cache: ReportCache<E>,
        stop_requested: Arc<AtomicBool>,
        logger: Logger,
    ) {
        log::debug!(logger, "Report cache thread started");

        let mut last_refreshed_at = Instant::now();

        loop {
            if stop_requested.load(Ordering::SeqCst) {
                log::debug!(logger, "Report cache thread stop requested.");
                break;
            }

            let now = Instant::now();
            if now - last_refreshed_at > REPORT_REFRESH_INTERVAL {
                log::info!(logger, "Report refresh internal exceeded, refreshing...");
                match report_cache.update_enclave_report_cache() {
                    Ok(()) => {
                        last_refreshed_at = now;
                    }
                    Err(err) => {
                        log::error!(logger, "update_enclave_report_cache failed: {:?}", err);
                    }
                }
            }

            sleep(Duration::from_secs(1));
        }
    }
}

impl Drop for ReportCacheThread {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
