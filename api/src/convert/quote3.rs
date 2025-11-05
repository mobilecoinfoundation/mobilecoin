// Copyright (c) 2023 The MobileCoin Foundation

//! Convert to/from external::Quote3

use crate::{external, ConversionError};
use mc_attest_verifier_types::prost;
use mc_sgx_dcap_types::Quote3;

impl<T: AsRef<[u8]>> From<&Quote3<T>> for external::Quote3 {
    fn from(src: &Quote3<T>) -> Self {
        Self {
            data: src.as_ref().to_vec(),
        }
    }
}

impl TryFrom<&external::Quote3> for Quote3<Vec<u8>> {
    type Error = ConversionError;
    fn try_from(src: &external::Quote3) -> Result<Self, Self::Error> {
        Ok(Quote3::try_from(&prost::Quote3::from(src))?)
    }
}

impl From<&external::Quote3> for prost::Quote3 {
    fn from(value: &external::Quote3) -> Self {
        Self {
            data: value.data.clone(),
        }
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
        let proto_quote = external::Quote3::from(&quote);
        let new_quote = Quote3::try_from(&proto_quote).expect("failed to decode proto quote");
        assert_eq!(quote, new_quote);
    }

    #[test]
    fn try_from_proto_quote_fails_on_bad_bytes() {
        let report = Report::default();
        let quote = DcapQuotingEnclave::quote_report(&report).expect("Failed to create quote");
        let mut proto_quote = external::Quote3::from(&quote);
        // Corrupting the quote type
        proto_quote.data[1] += 1;
        let error = Quote3::try_from(&proto_quote);

        assert_matches!(error, Err(ConversionError::InvalidContents));
    }
}
