// Copyright (c) 2023 The MobileCoin Foundation

//! Conversions from prost message types into common crate rust types.

use crate::{prost, ConversionError};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use mc_sgx_dcap_sys_types::sgx_ql_qve_collateral_t;
use mc_sgx_dcap_types::Collateral;
use x509_cert::{
    der::{pem::LineEnding, Decode, Encode, EncodePem},
    Certificate,
};

impl TryFrom<prost::Collateral> for Collateral {
    type Error = ConversionError;

    fn try_from(value: prost::Collateral) -> Result<Self, Self::Error> {
        // Note: sgx_collateral uses null bytes at the end of most arrays.

        let mut sgx_collateral = version_3_1_empty_collateral();

        let mut pck_crl_issuer_chain = der_chain_to_pem(&value.pck_crl_issuer_chain)?;
        sgx_collateral.pck_crl_issuer_chain =
            pck_crl_issuer_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.pck_crl_issuer_chain_size = pck_crl_issuer_chain.as_bytes().len() as u32;

        let mut root_ca_crl = value.root_ca_crl.clone();
        root_ca_crl.push(b'\0');
        sgx_collateral.root_ca_crl = root_ca_crl.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.root_ca_crl_size = root_ca_crl.len() as u32;

        let mut pck_crl = value.pck_crl.clone();
        pck_crl.push(b'\0');
        sgx_collateral.pck_crl = pck_crl.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.pck_crl_size = pck_crl.len() as u32;

        let mut tcb_info_issuer_chain = der_chain_to_pem(&value.tcb_info_issuer_chain)?;
        sgx_collateral.tcb_info_issuer_chain =
            tcb_info_issuer_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.tcb_info_issuer_chain_size = tcb_info_issuer_chain.as_bytes().len() as u32;

        let mut tcb_info = value.tcb_info.clone();
        sgx_collateral.tcb_info = tcb_info.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.tcb_info_size = tcb_info.as_bytes().len() as u32;

        let mut qe_identity_issuer_chain = der_chain_to_pem(&value.qe_identity_issuer_chain)?;
        sgx_collateral.qe_identity_issuer_chain =
            qe_identity_issuer_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.qe_identity_issuer_chain_size =
            qe_identity_issuer_chain.as_bytes().len() as u32;

        let mut qe_identity = value.qe_identity;
        sgx_collateral.qe_identity = qe_identity.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.qe_identity_size = qe_identity.as_bytes().len() as u32;

        Ok(Collateral::try_from(&sgx_collateral)?)
    }
}

/// Converts a vector of DER Certificates to newline separated PEMs.
fn der_chain_to_pem(der: &[Vec<u8>]) -> Result<String, ConversionError> {
    let pems = der
        .iter()
        .map(|c| Certificate::from_der(c)?.to_pem(LineEnding::LF))
        .collect::<Result<Vec<_>, _>>()?;
    let mut single_pem_chain = pems.join("\n");
    // This is to work with sgx_ql_qve_collateral_t, which assumes a null byte at
    // the end.
    single_pem_chain.push('\0');
    Ok(single_pem_chain)
}

impl TryFrom<&Collateral> for prost::Collateral {
    type Error = ConversionError;
    fn try_from(collateral: &Collateral) -> Result<Self, Self::Error> {
        // Note: This entire function would only fail if the certificates or CRLs could
        // not be encoded as DER. This shouldn't happen with a valid Collateral.

        let pck_crl_issuer_chain = collateral
            .pck_crl_issuer_chain()
            .iter()
            .map(|c| c.to_der())
            .collect::<Result<Vec<_>, _>>()?;

        let root_ca_crl = collateral.root_ca_crl().to_der()?;

        let pck_crl = collateral.pck_crl().to_der()?;

        let tcb_info_issuer_chain = collateral
            .tcb_issuer_chain()
            .iter()
            .map(|c| c.to_der())
            .collect::<Result<Vec<_>, _>>()?;

        let qe_identity_issuer_chain = collateral
            .qe_identity_issuer_chain()
            .iter()
            .map(|c| c.to_der())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(prost::Collateral {
            pck_crl_issuer_chain,
            root_ca_crl,
            pck_crl,
            tcb_info_issuer_chain,
            tcb_info: collateral.tcb_info().to_string(),
            qe_identity_issuer_chain,
            qe_identity: collateral.qe_identity().to_string(),
        })
    }
}

fn version_3_1_empty_collateral() -> sgx_ql_qve_collateral_t {
    let mut collateral = sgx_ql_qve_collateral_t::default();
    // Version 3.1 is the common default.
    //
    // The versions are documented in the default PCCS config file,
    // <https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/e7604e02331b3377f3766ed3653250e03af72d45/QuoteGeneration/qcnl/linux/sgx_default_qcnl.conf#L15>
    let (major, minor) = (3, 1);

    // SAFETY: The version fields are a union, which is inherently unsafe.
    #[allow(unsafe_code)]
    unsafe {
        collateral
            .__bindgen_anon_1
            .__bindgen_anon_1
            .as_mut()
            .major_version = major;
        collateral
            .__bindgen_anon_1
            .__bindgen_anon_1
            .as_mut()
            .minor_version = minor;
    }
    collateral
}

#[cfg(test)]
mod test {
    use super::{prost, *};
    use ::prost::Message;
    use assert_matches::assert_matches;
    use mc_attest_untrusted::DcapQuotingEnclave;
    use mc_sgx_core_types::Report;

    fn collateral() -> Collateral {
        let report = Report::default();
        let quote = DcapQuotingEnclave::quote_report(&report).expect("Failed to create quote");
        DcapQuotingEnclave::collateral(&quote)
    }

    #[test]
    fn collateral_back_and_forth() {
        let collateral = collateral();
        let prost_collateral = prost::Collateral::try_from(&collateral)
            .expect("Failed to convert collateral to prost");
        let bytes = prost_collateral.encode_to_vec();
        let new_collateral = Collateral::try_from(
            prost::Collateral::decode(bytes.as_slice()).expect("Failed to decode prost bytes"),
        )
        .expect("Failed to convert prost collateral to collateral");

        assert_eq!(collateral, new_collateral);
    }

    #[test]
    fn try_from_prost_collateral_fails_on_missing_pck_crl_issuer_chain() {
        let collateral = collateral();
        let mut prost_collateral = prost::Collateral::try_from(&collateral)
            .expect("Failed to convert collateral to prost");
        prost_collateral.pck_crl_issuer_chain.clear();
        let bytes = prost_collateral.encode_to_vec();
        let error = Collateral::try_from(
            prost::Collateral::decode(bytes.as_slice()).expect("Failed to decode prost bytes"),
        );

        assert_matches!(error, Err(ConversionError::InvalidContents(_)));
    }

    #[test]
    fn try_from_prost_collateral_fails_on_missing_pck_crl() {
        let collateral = collateral();
        let mut prost_collateral = prost::Collateral::try_from(&collateral)
            .expect("Failed to convert collateral to prost");
        prost_collateral.pck_crl.clear();
        let bytes = prost_collateral.encode_to_vec();
        let error = Collateral::try_from(
            prost::Collateral::decode(bytes.as_slice()).expect("Failed to decode prost bytes"),
        );

        assert_matches!(error, Err(ConversionError::InvalidContents(_)));
    }

    #[test]
    fn try_from_prost_collateral_fails_on_missing_root_ca_crl() {
        let collateral = collateral();
        let mut prost_collateral = prost::Collateral::try_from(&collateral)
            .expect("Failed to convert collateral to prost");
        prost_collateral.root_ca_crl.clear();
        let bytes = prost_collateral.encode_to_vec();
        let error = Collateral::try_from(
            prost::Collateral::decode(bytes.as_slice()).expect("Failed to decode prost bytes"),
        );

        assert_matches!(error, Err(ConversionError::InvalidContents(_)));
    }

    #[test]
    fn try_from_prost_collateral_fails_on_missing_tcb_info_issuer_chain() {
        let collateral = collateral();
        let mut prost_collateral = prost::Collateral::try_from(&collateral)
            .expect("Failed to convert collateral to prost");
        prost_collateral.tcb_info_issuer_chain.clear();
        let bytes = prost_collateral.encode_to_vec();
        let error = Collateral::try_from(
            prost::Collateral::decode(bytes.as_slice()).expect("Failed to decode prost bytes"),
        );

        assert_matches!(error, Err(ConversionError::InvalidContents(_)));
    }

    #[test]
    fn try_from_prost_collateral_fails_on_missing_tcb_info() {
        let collateral = collateral();
        let mut prost_collateral = prost::Collateral::try_from(&collateral)
            .expect("Failed to convert collateral to prost");
        prost_collateral.tcb_info.clear();
        let bytes = prost_collateral.encode_to_vec();
        let error = Collateral::try_from(
            prost::Collateral::decode(bytes.as_slice()).expect("Failed to decode prost bytes"),
        );

        assert_matches!(error, Err(ConversionError::InvalidContents(_)));
    }

    #[test]
    fn try_from_prost_collateral_fails_on_missing_qe_identity_issuer_chain() {
        let collateral = collateral();
        let mut prost_collateral = prost::Collateral::try_from(&collateral)
            .expect("Failed to convert collateral to prost");
        prost_collateral.qe_identity_issuer_chain.clear();
        let bytes = prost_collateral.encode_to_vec();
        let error = Collateral::try_from(
            prost::Collateral::decode(bytes.as_slice()).expect("Failed to decode prost bytes"),
        );

        assert_matches!(error, Err(ConversionError::InvalidContents(_)));
    }

    #[test]
    fn try_from_prost_collateral_fails_on_missing_qe_identity() {
        let collateral = collateral();
        let mut prost_collateral = prost::Collateral::try_from(&collateral)
            .expect("Failed to convert collateral to prost");
        prost_collateral.qe_identity.clear();
        let bytes = prost_collateral.encode_to_vec();
        let error = Collateral::try_from(
            prost::Collateral::decode(bytes.as_slice()).expect("Failed to decode prost bytes"),
        );

        assert_matches!(error, Err(ConversionError::InvalidContents(_)));
    }
}
