// Copyright (c) 2018-2020 MobileCoin Inc.

//! MobileCoin SGX-Attested Transport
//!
//! This crate defines the enclave-layer transport protocol state machine,
//! used to perform an attestation-authenticated key exchange for initiators
//! (client) and responders (server).

#![allow(clippy::type_complexity)]
#![no_std]
extern crate alloc;

mod error;
mod event;
mod initiator;
mod mealy;
mod responder;
mod shared;
mod state;

pub use self::{
    error::Error,
    event::{
        AuthRequestInput, AuthRequestOutput, AuthResponse, AuthSuccess, Ciphertext, ClientInitiate,
        NodeInitiate, Plaintext,
    },
    mealy::Transition,
    state::{AuthPending, Ready, Start},
};

#[cfg(test)]
#[cfg(feature = "sgx-sim")]
mod test {
    //! Unit tests for Attested Key Exchange
    extern crate std;

    use alloc::vec;

    use super::*;
    use aes_gcm::Aes256Gcm;
    use alloc::string::String;
    use core::convert::TryFrom;
    use mc_attest_core::{Quote, IAS_SIM_ROOT_ANCHORS};
    use mc_attest_net::{Client, RaClient};
    use mc_crypto_keys::{X25519Private, X25519Public, X25519};
    use mc_util_encodings::{FromBase64, ToX64};
    use mc_util_from_random::FromRandom;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;
    use sha2::Sha512;

    const RESPONDER_ID_STR: &str = "node1.unittest.mobilenode.com";
    const PRODUCT_ID: u16 = 0u16;
    const MIN_SVN: u16 = 0u16;

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
        (&mut quote_data[368..400]).copy_from_slice(pubkey.as_ref());

        // Re-assemble a quote from the munged version
        let quote = Quote::try_from(quote_data.as_ref())
            .expect("Could not parse quote from modified bytes");

        std::println!("new quote = {:?}", &quote);

        // Sign the forged quote with the sim client
        let ra_client = Client::new("").expect("Could not create sim client");
        let ias_report = ra_client
            .verify_quote(&quote, None)
            .expect("Could not sign our bogus report");

        let mr_signer = quote
            .report_body()
            .expect("Could not retrieve report body from cached report")
            .mr_signer();

        let mut initiator = Start::new(
            RESPONDER_ID_STR.into(),
            vec![mr_signer.into()],
            PRODUCT_ID,
            MIN_SVN,
            true,
        );

        let mut responder = Start::new(
            RESPONDER_ID_STR.into(),
            vec![mr_signer.into()],
            PRODUCT_ID,
            MIN_SVN,
            true,
        );

        let trust_anchors = Some(vec![String::from(IAS_SIM_ROOT_ANCHORS)]);
        initiator.trust_anchors = trust_anchors.clone();
        responder.trust_anchors = trust_anchors;

        let node_init =
            NodeInitiate::<X25519, Aes256Gcm, Sha512>::new(identity.clone(), ias_report.clone());
        let (initiator, auth_request_output) = initiator
            .try_next(&mut csprng, node_init)
            .expect("Initiator could not be initiated");

        // initiator = authpending, responder = start

        let auth_request_input = AuthRequestInput::new(auth_request_output, identity, ias_report);
        let (responder, auth_response) = responder
            .try_next(&mut csprng, auth_request_input)
            .expect("Responder could not process auth request");

        // initiator = authpending, responder = ready

        let (initiator, _) = initiator
            .try_next(&mut csprng, auth_response)
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
