// Copyright (c) 2018-2021 The MobileCoin Foundation

//! An implementation of the IAS client for simulation purposes

use crate::traits::{RaClient, Result};
use alloc::sync::Arc;
use mbedtls::{
    hash::Type as HashType,
    pk::Pk,
    rng::{CtrDrbg, OsEntropy},
};
use mc_attest_core::{
    EpidGroupId, IasNonce, Quote, QuoteSignType, SigRL, VerificationReport, VerificationSignature,
    IAS_SIM_SIGNING_CHAIN, IAS_SIM_SIGNING_KEY,
};
use mc_util_encodings::ToBase64;
use pem::parse_many;
use serde_json::json;
use sha2::{digest::Digest, Sha256};

#[derive(Clone)]
pub struct SimClient;

/// The mock remote attestation client implementation
impl RaClient for SimClient {
    fn new(_credentials: &str) -> Result<Self> {
        Ok(Self)
    }
    /// Return a default SigRL, regardless of the given EpidGroupId
    fn get_sigrl(&self, _gid: EpidGroupId) -> Result<SigRL> {
        Ok(SigRL::default())
    }

    /// Creates a fake IAS verification report signed by the ephemeral
    /// signing authority created at build-time in the attest crate.
    fn verify_quote(
        &self,
        quote: &Quote,
        ias_nonce: Option<IasNonce>,
    ) -> Result<VerificationReport> {
        // FIXME: This is wrong, we should be signing/returning a report, not a request.
        let jsvalue = match ias_nonce {
            Some(nonce) => {
                if quote.sign_type() == Ok(QuoteSignType::Linkable) {
                    json!({
                        "id": "0",
                        "version": 4,
                        "timestamp": "2020-06-30T22:16:41.409742",
                        "isvEnclaveQuoteStatus": "OK",
                        "isvEnclaveQuoteBody": quote.to_base64_owned(),
                        "nonce": nonce.to_string(),
                        "epidPseudonym": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                    })
                } else {
                    json!({
                        "id": "0",
                        "version": 4,
                        "timestamp": "2020-06-30T22:16:41.409742",
                        "isvEnclaveQuoteStatus": "OK",
                        "isvEnclaveQuoteBody": quote.to_base64_owned(),
                        "nonce": nonce.to_string()
                    })
                }
            }
            None => {
                if quote.sign_type() == Ok(QuoteSignType::Linkable) {
                    json!({
                        "id": "0",
                        "version": 4,
                        "timestamp": "2020-06-30T22:16:41.409742",
                        "isvEnclaveQuoteStatus": "OK",
                        "isvEnclaveQuoteBody": quote.to_base64_owned(),
                        "epidPseudonym": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                    })
                } else {
                    json!({
                        "id": "0",
                        "version": 4,
                        "timestamp": "2020-06-30T22:16:41.409742",
                        "isvEnclaveQuoteStatus": "OK",
                        "isvEnclaveQuoteBody": quote.to_base64_owned()
                    })
                }
            }
        };

        let http_body = jsvalue.to_string();
        let hash = Sha256::digest(http_body.as_bytes());

        let entropy = OsEntropy::new();
        let mut csprng = CtrDrbg::new(Arc::new(entropy), None).expect("Could not create CtrDrbg");

        let mut signer = Pk::from_private_key(IAS_SIM_SIGNING_KEY.as_bytes(), None)
            .expect("Could not load signing key.");
        let mut signature = vec![0u8; 1024];
        let bytes_signed = signer
            .sign(
                HashType::Sha256,
                hash.as_slice(),
                &mut signature,
                &mut csprng,
            )
            .expect("Could not sign data");
        signature.truncate(bytes_signed);

        let sig = VerificationSignature::from(signature);
        let chain: Vec<Vec<u8>> = parse_many(IAS_SIM_SIGNING_CHAIN.as_bytes())
            .iter()
            .map(|p| p.contents.clone())
            .collect();

        Ok(VerificationReport {
            sig,
            chain,
            http_body,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_attest_core::{Verifier, IAS_SIM_ROOT_ANCHORS};
    use mc_util_encodings::FromBase64;

    const QUOTE_TEST: &str = include_str!("../data/quote_out_of_date.txt");

    #[test]
    fn test_sign() {
        let client = SimClient::new("").expect("Could not create SimClient");
        let quote = Quote::from_base64(QUOTE_TEST).expect("Could not parse quote");
        let report = client
            .verify_quote(&quote, None)
            .expect("Could not generate IAS report");

        Verifier::new(&[IAS_SIM_ROOT_ANCHORS])
            .expect("Could not initialize new verifier")
            .debug(true)
            .verify(&report)
            .expect("Could not verify IAS report");
    }
}
