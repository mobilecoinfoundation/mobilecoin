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
    use assert_matches::assert_matches;
    use mc_attest_untrusted::DcapQuotingEnclave;
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
}
