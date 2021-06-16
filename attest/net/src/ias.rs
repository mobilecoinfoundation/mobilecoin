// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This module contains traits to support remote attestation using the
//! Intel Attestation Service.

use crate::traits::{Error, RaClient, Result};
use cfg_if::cfg_if;
use mc_attest_core::{
    EpidGroupId, IasNonce, Quote, SigRL, VerificationReport, VerificationSignature,
};
use mc_common::logger::global_log;
use mc_util_encodings::{FromBase64, FromHex, ToBase64};
use pem::parse_many;
use percent_encoding::percent_decode;
use reqwest::{
    blocking::Client,
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
};
use serde_json::json;

cfg_if! {
    if #[cfg(feature = "ias-dev")] {
        const IAS_BASEURI: &str = "https://api.trustedservices.intel.com/sgx/dev/attestation/v4";
    } else {
        const IAS_BASEURI: &str = "https://api.trustedservices.intel.com/sgx/attestation/v4";
    }
}

/// The header used to transmit our IAS querier credentials
const OCP_APIM_SUBSCRIPTION_KEY: &str = "Ocp-Apim-Subscription-Key";
/// The header used for the IAS verification report signature
const IAS_SIGNATURE: &str = "x-iasreport-signature";
/// The header used to store the certificate chain of the signer
const IAS_SIGNING_CERTS: &str = "x-iasreport-signing-certificate";

/// A data type for communicating with the Intel Attestation Service
#[derive(Clone)]
pub struct IasClient {
    client: Client,
    api_key: String,
    json_headers: HeaderMap,
}

impl RaClient for IasClient {
    /// Create a new IAS client, using the PEM-encoded certificate data
    /// as the client credentials.
    fn new(api_key: &str) -> Result<Self> {
        let client = Client::builder().gzip(true).use_rustls_tls().build()?;
        let mut json_headers = HeaderMap::new();
        json_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        json_headers.insert(
            OCP_APIM_SUBSCRIPTION_KEY,
            HeaderValue::from_str(api_key).or(Err(Error::BadApiKey))?,
        );
        Ok(Self {
            client,
            json_headers,
            api_key: api_key.to_owned(),
        })
    }

    /// Retrieve the SigRL for the given EPID Group ID.
    fn get_sigrl(&self, gid: EpidGroupId) -> Result<SigRL> {
        let response = self
            .client
            .get(format!("{}/sigrl/{}", IAS_BASEURI, gid).as_str())
            .header(OCP_APIM_SUBSCRIPTION_KEY, &self.api_key)
            .send()?
            .error_for_status()?;

        Ok(SigRL::from_base64(response.text()?.as_str())?)
    }

    /// Submit the given quote to IAS and parse the response into a
    /// VerificationReport.
    fn verify_quote(
        &self,
        quote: &Quote,
        ias_nonce: Option<IasNonce>,
    ) -> Result<VerificationReport> {
        let quote_base64 = quote.to_base64_owned();
        let jsvalue = match ias_nonce {
            Some(nonce) => json!({ "isvEnclaveQuote": quote_base64, "nonce": nonce.to_string() }),
            None => json!({"isvEnclaveQuote": quote_base64,}),
        };

        global_log::trace!(
            "Submitting JSON request for {:?} to IAS: '{}' at {}",
            quote,
            jsvalue.to_string(),
            format!("{}/report", IAS_BASEURI),
        );

        let response = self
            .client
            .post(format!("{}/report", IAS_BASEURI).as_str())
            .headers(self.json_headers.clone())
            .body(jsvalue.to_string())
            .send()?
            .error_for_status()?;

        let headers = response.headers();
        let sig_str = headers
            .get(IAS_SIGNATURE)
            .ok_or(Error::MissingSignatureError)?;
        let sig = VerificationSignature::from_hex(sig_str.to_str()?)?;

        let pem_str = percent_decode(
            headers
                .get(IAS_SIGNING_CERTS)
                .ok_or(Error::MissingSigningCertsError)?
                .to_str()
                .map_err(|_e| Error::BadSigningCertsError)?
                .as_bytes(),
        )
        .decode_utf8()
        .map_err(|_e| Error::BadSigningCertsError)?;

        // It would be nice to eliminate the double-copy here, but... meh.
        let chain: Vec<Vec<u8>> = parse_many(pem_str.as_bytes())
            .iter()
            .map(|p| p.contents.clone())
            .collect();
        let http_body = response.text()?;

        let retval = VerificationReport {
            sig,
            chain,
            http_body,
        };

        global_log::trace!("Received report from IAS: {:?}", &retval);

        Ok(retval)
    }
}
