// Copyright (c) 2023 The MobileCoin Foundation

//! Convert to/from external::Collateral

use crate::{external, ConversionError};
use mc_attest_verifier_types::prost;
use mc_sgx_dcap_types::Collateral;
use mc_util_serial::Message;
use protobuf::Message as ProtoMessage;

impl TryFrom<&Collateral> for external::Collateral {
    type Error = ConversionError;
    fn try_from(src: &Collateral) -> Result<Self, Self::Error> {
        let prost = prost::Collateral::try_from(src)?;
        let bytes = prost.encode_to_vec();
        let mut proto = Self::default();
        proto
            .merge_from_bytes(&bytes)
            .expect("failure to merge means prost and protobuf are out of sync");
        Ok(proto)
    }
}

impl TryFrom<&external::Collateral> for Collateral {
    type Error = ConversionError;
    fn try_from(src: &external::Collateral) -> Result<Self, Self::Error> {
        let prost = prost::Collateral::from(src);
        Ok((&prost).try_into()?)
    }
}

impl From<&external::Collateral> for prost::Collateral {
    fn from(src: &external::Collateral) -> Self {
        Self {
            pck_crl_issuer_chain: src.pck_crl_issuer_chain.clone().into_vec(),
            root_ca_crl: src.root_ca_crl.clone(),
            pck_crl: src.pck_crl.clone(),
            tcb_info_issuer_chain: src.tcb_info_issuer_chain.clone().into_vec(),
            tcb_info: src.tcb_info.clone(),
            qe_identity_issuer_chain: src.qe_identity_issuer_chain.clone().into_vec(),
            qe_identity: src.qe_identity.clone(),
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
    fn collateral_back_and_forth() {
        let report = Report::default();
        let quote = DcapQuotingEnclave::quote_report(&report).expect("Failed to create quote");
        let collateral = DcapQuotingEnclave::collateral(&quote).expect("Failed to get collateral");
        let proto_collateral = external::Collateral::try_from(&collateral)
            .expect("Failed to convert collateral to proto");
        let new_collateral = Collateral::try_from(&proto_collateral)
            .expect("Failed to convert proto collateral to collateral");

        assert_eq!(collateral, new_collateral);
    }

    #[test]
    fn bad_collateral_fails_to_decode() {
        let report = Report::default();
        let quote = DcapQuotingEnclave::quote_report(&report).expect("Failed to create quote");
        let collateral = DcapQuotingEnclave::collateral(&quote).expect("Failed to get collateral");
        let mut proto_collateral = external::Collateral::try_from(&collateral)
            .expect("Failed to convert collateral to proto");
        proto_collateral.root_ca_crl[0] += 1;
        let error = Collateral::try_from(&proto_collateral);

        assert_matches!(error, Err(ConversionError::InvalidContents));
    }
}
