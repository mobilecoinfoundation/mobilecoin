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
    use mc_attest_core::Quote;
    use mc_attest_net::{Client, RaClient};
    use mc_attestation_verifier::{TrustedIdentity, TrustedMrSignerIdentity};
    use mc_crypto_keys::{X25519Private, X25519Public, X25519};
    use mc_util_encodings::{FromBase64, ToX64};
    use mc_util_from_random::FromRandom;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;
    use sha2::Sha512;

    const RESPONDER_ID_STR: &str = "node1.unittest.mobilenode.com";

    #[test]
    fn ix_handshake() {
        // Read an existing, valid quote
        let data = include_str!("../test_data/ok_quote.txt");
        let quote = Quote::from_base64(data.trim()).expect("Could not parse quote");

        // Create a new identity pubkey for our "enclave"
        let mut csprng = Hc128Rng::seed_from_u64(0);
        let identity = X25519Private::from_random(&mut csprng);
        let pubkey = X25519Public::from(&identity);

        // Get the bytes from our quote
        let mut quote_data = quote.to_x64_vec();

        // Overwrite the cached quote's report_data contents with our pubkey
        quote_data[368..400].copy_from_slice(pubkey.as_ref());

        // Re-assemble a quote from the munged version
        let quote = Quote::try_from(quote_data.as_ref())
            .expect("Could not parse quote from modified bytes");

        // Sign the forged quote with the sim client
        let ra_client = Client::new("").expect("Could not create sim client");
        let attestation_evidence = ra_client
            .verify_quote(&quote, None)
            .expect("Could not sign our bogus report");

        let report_body = quote
            .report_body()
            .expect("Could not retrieve report body from cached report");

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

        let auth_response_input = AuthResponseInput::new(auth_response_output, identities);
        let (initiator, _) = initiator
            .try_next(&mut csprng, auth_response_input)
            .expect("Initiator not process auth response");

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
