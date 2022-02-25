// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::Ed25519SignerSet/Ed25519MultiSig.

use crate::{convert::ConversionError, external};
use mc_crypto_keys::{Ed25519Public, Ed25519Signature};
use mc_crypto_multisig::{MultiSig, SignerSet};
use protobuf::RepeatedField;
use std::convert::TryFrom;

/// Convert MultiSig<Ed25519Signature> --> external::Ed25519MultiSig.
impl From<&MultiSig<Ed25519Signature>> for external::Ed25519MultiSig {
    fn from(src: &MultiSig<Ed25519Signature>) -> Self {
        let mut dst = external::Ed25519MultiSig::new();
        dst.set_signatures(RepeatedField::from_vec(
            src.signatures()
                .iter()
                .map(external::Ed25519Signature::from)
                .collect(),
        ));
        dst
    }
}

/// Convert external::Ed25519MultiSig --> MultiSig<Ed25519Signature>.
impl TryFrom<&external::Ed25519MultiSig> for MultiSig<Ed25519Signature> {
    type Error = ConversionError;

    fn try_from(source: &external::Ed25519MultiSig) -> Result<Self, Self::Error> {
        let signatures: Vec<Ed25519Signature> = source
            .get_signatures()
            .iter()
            .map(|s| Ed25519Signature::try_from(s))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self::new(signatures))
    }
}

/// Convert SignerSet<Ed25519Public> --> external::Ed25519SignerSet.
impl From<&SignerSet<Ed25519Public>> for external::Ed25519SignerSet {
    fn from(src: &SignerSet<Ed25519Public>) -> Self {
        let mut dst = external::Ed25519SignerSet::new();
        dst.set_signers(RepeatedField::from_vec(
            src.signers()
                .iter()
                .map(external::Ed25519Public::from)
                .collect(),
        ));
        dst
    }
}

/// Convert external::Ed25519SignerSet --> SignerSet<Ed25519Public>.
impl TryFrom<&external::Ed25519SignerSet> for SignerSet<Ed25519Public> {
    type Error = ConversionError;

    fn try_from(source: &external::Ed25519SignerSet) -> Result<Self, Self::Error> {
        let signers: Vec<Ed25519Public> = source
            .get_signers()
            .iter()
            .map(|s| Ed25519Public::try_from(s))
            .collect::<Result<Vec<_>, _>>()?;

        let threshold = source.get_threshold();

        Ok(Self::new(signers, threshold))
    }
}
