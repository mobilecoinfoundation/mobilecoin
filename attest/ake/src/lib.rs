// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MobileCoin SGX-Attested Transport
//!
//! This crate defines the enclave-layer transport protocol state machine,
//! used to perform an attestation-authenticated key exchange for initiators
//! (client) and responders (server).

#![allow(clippy::type_complexity)]
#![allow(clippy::result_large_err)]
#![no_std]
extern crate alloc;

mod error;
mod event;
mod initiator;
mod mealy;
mod responder;
mod shared;
mod state;

pub use crate::{
    error::Error,
    event::{
        AuthRequestOutput, AuthResponseInput, AuthResponseOutput, Ciphertext,
        ClientAuthRequestInput, ClientInitiate, NodeAuthRequestInput, NodeInitiate, Plaintext,
        UnverifiedAttestationEvidence,
    },
    mealy::Transition,
    state::{AuthPending, Ready, Start, Terminated},
};

#[cfg(test)]
#[cfg(feature = "sgx-sim")]
mod test {
    //! Unit tests for Attested Key Exchange
    use super::*;
    use aes_gcm::Aes256Gcm;
    use mc_attest_core::Report;
    use mc_attest_untrusted::DcapQuotingEnclave;
    use mc_attest_verifier_types::{DcapEvidence, EnclaveReportDataContents};
    use mc_attestation_verifier::{TrustedIdentity, TrustedMrSignerIdentity};
    use mc_crypto_keys::{X25519Private, X25519Public, X25519};
    use mc_util_from_random::FromRandom;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;
    use sha2::Sha512;

    const RESPONDER_ID_STR: &str = "node1.unittest.mobilenode.com";

    #[test]
    fn ix_handshake() {
        // Create a new identity pubkey for our "enclave"
        let mut csprng = Hc128Rng::seed_from_u64(0);
        let identity = X25519Private::from_random(&mut csprng);
        let pubkey = X25519Public::from(&identity);

        let report_data = EnclaveReportDataContents::new([0x2au8; 16].into(), pubkey, [0x36u8; 32]);
        let mut report = Report::default();
        report.as_mut().body.report_data.d[..32].copy_from_slice(&report_data.sha256());

        let quote = DcapQuotingEnclave::quote_report(&report).expect("Failed to create quote");
        let collateral = DcapQuotingEnclave::collateral(&quote).expect("Failed to get collateral");
        let attestation_evidence = DcapEvidence {
            quote,
            collateral,
            report_data,
        };

        let report_body = attestation_evidence.quote.app_report_body();

        let mr_signer = TrustedIdentity::from(TrustedMrSignerIdentity::new(
            report_body.mr_signer(),
            report_body.isv_product_id(),
            report_body.isv_svn(),
            [] as [&str; 0],
            [] as [&str; 0],
        ));
        let identities = [mr_signer];

        let initiator = Start::new(RESPONDER_ID_STR.into());
        let responder = Start::new(RESPONDER_ID_STR.into());

        let node_init = NodeInitiate::<X25519, Aes256Gcm, Sha512>::new(
            identity.clone(),
            attestation_evidence.clone(),
        );
        let (initiator, auth_request_output) = initiator
            .try_next(&mut csprng, node_init)
            .expect("Initiator could not be initiated");

        // initiator = authpending, responder = start

        let auth_request_input = NodeAuthRequestInput::new(
            auth_request_output,
            identity,
            attestation_evidence,
            identities.clone(),
        );
        let (responder, auth_response_output) = responder
            .try_next(&mut csprng, auth_request_input)
            .expect("Responder could not process auth request");

        // initiator = authpending, responder = ready

        let auth_response_input = AuthResponseInput::new(auth_response_output, identities, None);
        let (initiator, _) = initiator
            .try_next(&mut csprng, auth_response_input)
            .expect("Initiator could not process auth response");

        // initiator = ready, responder = ready

        let challenge = "What problem does cryptocurrency solve? Don’t just try to shout down the skeptics with a mixture of technobabble and libertarian derp.";
        let aad = "Paul Krugman, Transaction Costs and Tethers: Why I'm a Crypto Skeptic";

        let (initiator, ciphertext) = initiator
            .try_next(
                &mut csprng,
                Plaintext::new(aad.as_bytes(), challenge.as_bytes()),
            )
            .expect("Could not encrypt initial payload");

        // initiator = ready, responder = ready

        let (responder, plaintext) = responder
            .try_next(&mut csprng, Ciphertext::new(aad.as_bytes(), &ciphertext))
            .expect("Could not decrypt intial payload");

        // initiator = ready, responder = ready

        assert_eq!(plaintext.as_slice(), challenge.as_bytes());

        let aad2 = "Al Gore";
        let response = "In digital era, privacy must be a priority. Is it just me, or is secret blanket surveillance obscenely outrageous?";

        let (_, ciphertext2) = responder
            .try_next(
                &mut csprng,
                Plaintext::new(aad2.as_bytes(), response.as_bytes()),
            )
            .expect("Could not encrypt reply");

        let (_, plaintext2) = initiator
            .try_next(&mut csprng, Ciphertext::new(aad2.as_bytes(), &ciphertext2))
            .expect("Could not decrypt reply");

        assert_eq!(plaintext2.as_slice(), response.as_bytes());
    }
}
