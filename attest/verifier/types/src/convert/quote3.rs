// Copyright (c) 2023 The MobileCoin Foundation

//! Conversions from prost message types into common crate rust types.

use crate::{prost, ConversionError};
use alloc::vec::Vec;
use mc_sgx_dcap_types::Quote3;

impl TryFrom<prost::Quote3> for Quote3<Vec<u8>> {
    type Error = ConversionError;

    fn try_from(value: prost::Quote3) -> Result<Self, Self::Error> {
        Ok(Quote3::try_from(value.data)?)
    }
}

impl<T: AsRef<[u8]>> From<&Quote3<T>> for prost::Quote3 {
    fn from(value: &Quote3<T>) -> Self {
        prost::Quote3 {
            data: value.as_ref().to_vec(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::{prost, *};
    use ::prost::Message;
    use alloc::vec;
    use assert_matches::assert_matches;
    use mc_attest_untrusted::DcapQuotingEnclave;
    use mc_crypto_digestible::{DigestTranscript, Digestible, MerlinTranscript};
    use mc_sgx_core_types::Report;

    #[test]
    fn quote_back_and_forth() {
        let report = Report::default();
        let quote = DcapQuotingEnclave::quote_report(&report).expect("Failed to create quote");
        let prost_quote = prost::Quote3::from(&quote);
        let bytes = prost_quote.encode_to_vec();
        let new_quote = Quote3::try_from(
            prost::Quote3::decode(bytes.as_slice()).expect("Failed to decode prost bytes"),
        )
        .expect("failed to decode prost quote");

        assert_eq!(quote, new_quote);
    }

    #[test]
    fn try_from_prost_quote_fails_on_bad_bytes() {
        let report = Report::default();
        let quote = DcapQuotingEnclave::quote_report(&report).expect("Failed to create quote");
        let mut prost_quote = prost::Quote3::from(&quote);
        // Corrupting the quote type
        prost_quote.data[1] += 1;
        let bytes = prost_quote.encode_to_vec();
        let error = Quote3::try_from(
            prost::Quote3::decode(bytes.as_slice()).expect("Failed to decode prost bytes"),
        );

        assert_matches!(error, Err(ConversionError::InvalidContents(_)));
    }

    #[test]
    fn digest() {
        // Some notes about this test:
        // - We use simple vectors as we don't need to test the actual quote format,
        //   just the digesting of the bytes.
        // - We manually build up the digest here, to help ensure that the digest order
        //   of fields is maintained in the future.
        let data = vec![100; 283];

        let context = b"it was a dark and stormy night";

        // The `digestible` byte string is used in the `DigestTranscript`
        // implementation for `MerlinTranscript`. It shouldn't change or else
        // historical digests would fail to be reproduced.
        let mut transcript = MerlinTranscript::new(b"digestible");
        transcript.append_agg_header(context, b"Quote3");

        // As mentioned above the order of these calls should not change after
        // release. Only items added or removed. This is because the digest
        // will be stored on the block chain and someone will need to be able
        // to reproduce it.
        data.append_to_transcript(b"data", &mut transcript);

        transcript.append_agg_closer(context, b"Quote3");

        let mut expected_digest = [0u8; 32];
        transcript.extract_digest(&mut expected_digest);

        let quote = prost::Quote3 { data };

        let quote_digest = quote.digest32::<MerlinTranscript>(context);
        assert_eq!(quote_digest, expected_digest);
    }
}
