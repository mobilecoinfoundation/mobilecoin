// Copyright (c) 2023 The MobileCoin Foundation

//! Convert to/from attest::Quote3

use crate::{attest, ConversionError};
use mc_sgx_dcap_types::Quote3;

impl<T: AsRef<[u8]>> From<&Quote3<T>> for attest::Quote3 {
    fn from(src: &Quote3<T>) -> Self {
        let mut dst = Self::new();
        dst.set_data(src.as_ref().to_vec());

        dst
    }
}

impl TryFrom<attest::Quote3> for Quote3<Vec<u8>> {
    type Error = ConversionError;
    fn try_from(src: attest::Quote3) -> Result<Self, Self::Error> {
        Ok(Quote3::try_from(src.data)?)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use assert_matches::assert_matches;
    use mc_attest_untrusted::DcapQuotingEnclave;
    use mc_sgx_core_types::Report;

    #[test]
    fn quote_back_and_forth() {
        let report = Report::default();
        let quote = DcapQuotingEnclave::quote_report(&report).expect("Failed to create quote");
        let proto_quote = attest::Quote3::from(&quote);
        let new_quote = Quote3::try_from(proto_quote).expect("failed to decode proto quote");
        assert_eq!(quote, new_quote);
    }

    #[test]
    fn try_from_prost_quote_fails_on_bad_bytes() {
        let report = Report::default();
        let quote = DcapQuotingEnclave::quote_report(&report).expect("Failed to create quote");
        let mut proto_quote = attest::Quote3::from(&quote);
        // Corrupting the quote type
        proto_quote.data[1] += 1;
        let error = Quote3::try_from(proto_quote);

        assert_matches!(error, Err(ConversionError::InvalidContents(_)));
    }
}
