// Copyright (c) 2018-2020 MobileCoin Inc.

//! Conversions between "API types" and "domain/persistence types".
//!
//! gRPC and Protobuf provide a reduced selection of types, and so there are some differences between
//! values stored in the ledger and values transmitted over the API. This module provides conversions
//! between "equivalent" types, such as `mobilecoin_api::blockchain::Block` and `transaction::Block`.

use crate::{blockchain, consensus_common::ProposeTxResult, external, transaction as tx_grpc};
use common::HashMap;
use keys::{
    CompressedRistrettoPublic, Ed25519Public, Ed25519Signature, RistrettoPrivate, RistrettoPublic,
};
use mcserial::ReprBytes32;
use protobuf::RepeatedField;
use std::{
    convert::{From, TryFrom, TryInto},
    error::Error,
    fmt::{self, Formatter},
    path::PathBuf,
};
use transaction::{
    amount::Amount,
    encrypted_fog_hint::EncryptedFogHint,
    range::Range,
    ring_signature::{
        Blinding, ChallengeResponse, Commitment, CurvePoint, CurveScalar, Error as RingSigError,
        KeyImage, SignatureRctFull,
    },
    tx,
    tx::{TxOutMembershipElement, TxOutMembershipHash, TxOutMembershipProof},
    validation::TransactionValidationError,
    BlockSignature, RedactedTx,
};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum ConversionError {
    NarrowingCastError,
    ArrayCastError,
    KeyCastError,
    Other,
}

// This is needed for some code to compile, due to TryFrom being derived from From
impl From<core::convert::Infallible> for ConversionError {
    fn from(_src: core::convert::Infallible) -> Self {
        unreachable!();
    }
}

impl From<core::array::TryFromSliceError> for ConversionError {
    fn from(_: core::array::TryFromSliceError) -> Self {
        Self::ArrayCastError
    }
}

impl From<RingSigError> for ConversionError {
    fn from(src: RingSigError) -> Self {
        match src {
            RingSigError::LengthMismatch(_, _) => Self::ArrayCastError,
            _ => Self::KeyCastError,
        }
    }
}

impl From<transaction::ConvertError> for ConversionError {
    fn from(_src: transaction::ConvertError) -> Self {
        Self::ArrayCastError
    }
}

impl Error for ConversionError {}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "ConversionError")
    }
}

/// Convert transaction::Block --> blockchain::Block.
impl From<&transaction::Block> for blockchain::Block {
    fn from(other: &transaction::Block) -> Self {
        let mut block = blockchain::Block::new();
        block.set_id(other.id.as_ref().to_vec());
        block.set_version(other.version);
        block.set_parent_id(other.parent_id.as_ref().to_vec());
        block.set_index(other.index);
        block.set_root_element((&other.root_element).into());
        block.set_contents_hash(other.contents_hash.as_ref().to_vec());
        block
    }
}

/// Convert blockchain::Block --> transaction::Block.
impl TryFrom<&blockchain::Block> for transaction::Block {
    type Error = ConversionError;

    fn try_from(value: &blockchain::Block) -> Result<Self, Self::Error> {
        let block_id = transaction::BlockID::try_from(value.id.as_slice())?;
        let parent_id = transaction::BlockID::try_from(value.parent_id.as_slice())?;
        let root_element = TxOutMembershipElement::try_from(value.get_root_element())?;
        let contents_hash =
            transaction::BlockContentsHash::try_from(value.contents_hash.as_slice())?;

        let block = transaction::Block {
            id: block_id,
            version: value.version,
            parent_id,
            index: value.index,
            root_element,
            contents_hash,
        };
        Ok(block)
    }
}

/// Convert ledger_types::TxHash --> tx_grpc::TxHash.
impl From<&tx::TxHash> for tx_grpc::TxHash {
    fn from(other: &tx::TxHash) -> Self {
        let mut tx_hash = tx_grpc::TxHash::new();
        tx_hash.set_hash(other.to_vec());
        tx_hash
    }
}

/// Convert  tx_grpc::TxHash --> ledger_types::TxHash.
impl TryFrom<&tx_grpc::TxHash> for tx::TxHash {
    type Error = ConversionError;

    fn try_from(value: &tx_grpc::TxHash) -> Result<Self, Self::Error> {
        let hash_bytes: &[u8] = value.get_hash();
        tx::TxHash::try_from(hash_bytes).or(Err(ConversionError::ArrayCastError))
    }
}

/// Convert CurvePoint --> external::CurvePoint.
impl From<&CurvePoint> for external::CurvePoint {
    fn from(other: &CurvePoint) -> Self {
        let mut point = external::CurvePoint::new();
        point.set_data(other.to_bytes().to_vec());
        point
    }
}

/// Convert external::CurvePoint --> CurvePoint.
impl TryFrom<&external::CurvePoint> for CurvePoint {
    type Error = ConversionError;

    fn try_from(source: &external::CurvePoint) -> Result<Self, Self::Error> {
        let bytes: &[u8] = source.get_data();
        CurvePoint::try_from(bytes).map_err(|_| ConversionError::ArrayCastError)
    }
}

/// Convert CurveScalar --> external::CurveScalar.
impl From<&CurveScalar> for external::CurveScalar {
    fn from(other: &CurveScalar) -> Self {
        let mut scalar = external::CurveScalar::new();
        scalar.set_data(other.as_bytes().to_vec());
        scalar
    }
}

/// Convert RistrettoPrivate --> external::CurveScalar.
impl From<&RistrettoPrivate> for external::CurveScalar {
    fn from(other: &RistrettoPrivate) -> Self {
        let mut scalar = external::CurveScalar::new();
        let privbytes: &[u8] = other.as_ref();
        scalar.set_data(Vec::from(privbytes));
        scalar
    }
}

/// Convert RistrettoPublic --> external::RistrettoPublic
impl From<&RistrettoPublic> for external::RistrettoPublic {
    fn from(other: &RistrettoPublic) -> Self {
        let mut key = external::RistrettoPublic::new();
        key.set_data(other.into());
        key
    }
}

/// Convert CompressedRistrettoPublic --> external::RistrettoPublic
impl From<CompressedRistrettoPublic> for external::RistrettoPublic {
    fn from(other: CompressedRistrettoPublic) -> Self {
        let mut key = external::RistrettoPublic::new();
        key.set_data(other.as_bytes().to_vec());
        key
    }
}

/// Convert RistrettoPrivate --> external::RistrettoPrivate
impl From<&RistrettoPrivate> for external::RistrettoPrivate {
    fn from(other: &RistrettoPrivate) -> Self {
        let mut key = external::RistrettoPrivate::new();
        key.set_data(other.to_bytes().to_vec());
        key
    }
}

/// Convert external::RistrettoPrivate --> RistrettoPrivate.
impl TryFrom<&external::RistrettoPrivate> for RistrettoPrivate {
    type Error = ConversionError;

    fn try_from(source: &external::RistrettoPrivate) -> Result<Self, Self::Error> {
        let bytes: &[u8] = source.get_data();
        RistrettoPrivate::try_from(bytes).map_err(|_| ConversionError::ArrayCastError)
    }
}

/// Convert external::CurveScalar --> CurveScalar.
impl TryFrom<&external::CurveScalar> for CurveScalar {
    type Error = ConversionError;

    fn try_from(source: &external::CurveScalar) -> Result<Self, Self::Error> {
        let bytes: &[u8] = source.get_data();
        CurveScalar::try_from(bytes).map_err(|_| ConversionError::ArrayCastError)
    }
}

/// Convert KeyImage --> external::KeyImage.
impl From<&KeyImage> for external::KeyImage {
    fn from(other: &KeyImage) -> Self {
        let mut point = external::KeyImage::new();
        point.set_data(other.to_vec());
        point
    }
}

/// Convert external::KeyImage --> KeyImage.
impl TryFrom<&external::KeyImage> for KeyImage {
    type Error = ConversionError;

    fn try_from(source: &external::KeyImage) -> Result<Self, Self::Error> {
        let bytes: &[u8] = source.get_data();
        Ok(KeyImage::try_from(bytes)?)
    }
}

/// Convert Ed25519Signature --> external::Ed25519Signature.
impl From<&Ed25519Signature> for external::Ed25519Signature {
    fn from(src: &Ed25519Signature) -> Self {
        let mut dst = external::Ed25519Signature::new();
        dst.set_data(src.to_bytes().to_vec());
        dst
    }
}

/// Convert external::Ed25519Signature --> Ed25519Signature.
impl TryFrom<&external::Ed25519Signature> for Ed25519Signature {
    type Error = ConversionError;

    fn try_from(source: &external::Ed25519Signature) -> Result<Self, Self::Error> {
        let bytes: &[u8] = source.get_data();
        Ed25519Signature::try_from(bytes).map_err(|_| ConversionError::ArrayCastError)
    }
}

/// Convert Ed25519Public --> external::Ed25519Public.
impl From<&Ed25519Public> for external::Ed25519Public {
    fn from(src: &Ed25519Public) -> Self {
        let mut dst = external::Ed25519Public::new();
        let bytes: &[u8] = src.as_ref();
        dst.set_data(bytes.to_vec());
        dst
    }
}

/// Convert external::Ed25519Public --> Ed25519Public.
impl TryFrom<&external::Ed25519Public> for Ed25519Public {
    type Error = ConversionError;

    fn try_from(source: &external::Ed25519Public) -> Result<Self, Self::Error> {
        let bytes: &[u8] = source.get_data();
        Ed25519Public::try_from(bytes).map_err(|_| ConversionError::ArrayCastError)
    }
}

/// Convert BlockSignature --> blockchain::BlockSignature.
impl From<&BlockSignature> for blockchain::BlockSignature {
    fn from(src: &BlockSignature) -> Self {
        let mut dst = blockchain::BlockSignature::new();
        dst.set_signature(external::Ed25519Signature::from(src.signature()));
        dst.set_signer(external::Ed25519Public::from(src.signer()));
        dst
    }
}

/// Convert blockchain::BlockSignature --> BlockSignature.
impl TryFrom<&blockchain::BlockSignature> for BlockSignature {
    type Error = ConversionError;

    fn try_from(source: &blockchain::BlockSignature) -> Result<Self, Self::Error> {
        let signature = Ed25519Signature::try_from(source.get_signature())?;
        let signer = Ed25519Public::try_from(source.get_signer())?;
        Ok(BlockSignature::new(signature, signer))
    }
}

/// Convert KeyImage -->  tx_grpc::KeyImage.
impl From<&KeyImage> for tx_grpc::KeyImage {
    fn from(other: &KeyImage) -> Self {
        let mut key_image = tx_grpc::KeyImage::new();
        key_image.set_value(other.to_vec());
        key_image
    }
}

/// Convert  tx_grpc::KeyImage --> KeyImage.
impl TryFrom<&tx_grpc::KeyImage> for KeyImage {
    type Error = ConversionError;

    fn try_from(source: &tx_grpc::KeyImage) -> Result<Self, Self::Error> {
        let bytes: &[u8] = source.get_value();
        Ok(KeyImage::try_from(bytes)?)
    }
}

/// Convert RedactedTx -->  tx_grpc::RedactedTx.
impl From<&RedactedTx> for tx_grpc::RedactedTx {
    fn from(redacted_tx: &RedactedTx) -> Self {
        let mut transaction = tx_grpc::RedactedTx::new();
        //transaction.set_version(tx_stored.version as u32);
        let tx_outs: Vec<tx_grpc::TxOut> = redacted_tx
            .outputs
            .iter()
            .map(tx_grpc::TxOut::from)
            .collect();
        transaction.set_outs(RepeatedField::from_vec(tx_outs));

        let key_images: Vec<tx_grpc::KeyImage> = redacted_tx
            .key_images
            .iter()
            .map(tx_grpc::KeyImage::from)
            .collect();
        transaction.set_key_images(RepeatedField::from_vec(key_images));
        transaction
    }
}

/// Convert  tx_grpc::RedactedTx --> transaction::RedactedTx
impl TryFrom<&tx_grpc::RedactedTx> for RedactedTx {
    type Error = ConversionError;

    fn try_from(source: &tx_grpc::RedactedTx) -> Result<Self, Self::Error> {
        // Convert blockchain::TxOut --> ledger_types::TxOutStored.
        let output_conversions: Result<Vec<tx::TxOut>, ConversionError> =
            source.get_outs().iter().map(tx::TxOut::try_from).collect();

        let outputs = output_conversions?;

        let mut key_images: Vec<KeyImage> = Vec::with_capacity(source.get_key_images().len());
        for source_key_image in source.get_key_images() {
            let key_image = KeyImage::try_from(source_key_image)?;
            key_images.push(key_image);
        }
        let redacted_tx = RedactedTx::new(outputs, key_images);
        Ok(redacted_tx)
    }
}

/// Convert tx::TxIn --> external::TxIn.
impl From<&tx::TxIn> for external::TxIn {
    fn from(source: &tx::TxIn) -> Self {
        let mut tx_in = external::TxIn::new();

        let ring: Vec<external::TxOut> = source.ring.iter().map(external::TxOut::from).collect();
        tx_in.set_ring(ring.into());

        let proofs: Vec<external::TxOutMembershipProof> = source
            .proofs
            .iter()
            .map(external::TxOutMembershipProof::from)
            .collect();
        tx_in.set_proofs(proofs.into());

        tx_in
    }
}

/// Convert external::TxIn --> tx::TxIn.
impl TryFrom<&external::TxIn> for tx::TxIn {
    type Error = ConversionError;

    fn try_from(source: &external::TxIn) -> Result<Self, Self::Error> {
        let mut ring: Vec<tx::TxOut> = Vec::new();
        for out in source.get_ring() {
            let tx_out = tx::TxOut::try_from(out)?;
            ring.push(tx_out);
        }

        let mut proofs: Vec<TxOutMembershipProof> = Vec::new();
        for proof in source.get_proofs() {
            let tx_proof = TxOutMembershipProof::try_from(proof)?;
            proofs.push(tx_proof);
        }

        let tx_in = tx::TxIn { ring, proofs };
        Ok(tx_in)
    }
}

/// Convert tx::TxPrefix --> external::TxPrefix.
impl From<&tx::TxPrefix> for external::TxPrefix {
    fn from(source: &tx::TxPrefix) -> Self {
        let mut tx_prefix = external::TxPrefix::new();

        let inputs: Vec<external::TxIn> = source.inputs.iter().map(external::TxIn::from).collect();
        tx_prefix.set_inputs(inputs.into());

        let outputs: Vec<external::TxOut> =
            source.outputs.iter().map(external::TxOut::from).collect();
        tx_prefix.set_outputs(outputs.into());

        tx_prefix.set_fee(source.fee);

        tx_prefix
    }
}

/// Convert external::TxPrefix --> tx::TxPrefix.
impl TryFrom<&external::TxPrefix> for tx::TxPrefix {
    type Error = ConversionError;

    fn try_from(source: &external::TxPrefix) -> Result<Self, Self::Error> {
        let mut inputs: Vec<tx::TxIn> = Vec::new();
        for out in source.get_inputs() {
            let tx_out = tx::TxIn::try_from(out)?;
            inputs.push(tx_out);
        }

        let mut outputs: Vec<tx::TxOut> = Vec::new();
        for out in source.get_outputs() {
            let tx_out = tx::TxOut::try_from(out)?;
            outputs.push(tx_out);
        }

        let tx_prefix = tx::TxPrefix {
            inputs,
            outputs,
            fee: source.get_fee(),
        };
        Ok(tx_prefix)
    }
}

/// Convert transaction::tx::Tx --> external::Tx.
impl From<&tx::Tx> for external::Tx {
    fn from(source: &tx::Tx) -> Self {
        let mut tx = external::Tx::new();

        tx.set_prefix(external::TxPrefix::from(&source.prefix));
        tx.set_signature(external::RingCtSignature::from(&source.signature));
        tx.set_range_proofs(source.range_proofs.clone());
        tx.set_tombstone_block(source.tombstone_block);

        tx
    }
}

/// Convert external::Tx --> transaction::tx::Tx.
impl TryFrom<&external::Tx> for tx::Tx {
    type Error = ConversionError;

    fn try_from(source: &external::Tx) -> Result<Self, Self::Error> {
        let prefix = tx::TxPrefix::try_from(source.get_prefix())?;
        let signature = SignatureRctFull::try_from(source.get_signature())?;
        let range_proofs = source.get_range_proofs().to_vec();
        let tombstone_block = source.get_tombstone_block();

        Ok(tx::Tx {
            prefix,
            signature,
            range_proofs,
            tombstone_block,
        })
    }
}

/// Convert Signature --> external::RingCtSignature.
impl From<&SignatureRctFull> for external::RingCtSignature {
    fn from(source: &SignatureRctFull) -> Self {
        let mut signature = external::RingCtSignature::new();

        let key_images: Vec<external::KeyImage> = source
            .key_images
            .iter()
            .map(external::KeyImage::from)
            .collect();
        signature.set_key_images(key_images.into());

        let challenge_responses: Vec<external::RingCtChallengeResponse> = source
            .challenge_responses
            .iter()
            .map(|challenge_response| {
                let mut ringct_challenge_response = external::RingCtChallengeResponse::new();

                let response: Vec<external::CurveScalar> = challenge_response
                    .response
                    .iter()
                    .map(external::CurveScalar::from)
                    .collect();
                ringct_challenge_response.set_response(response.into());

                ringct_challenge_response
            })
            .collect();
        signature.set_challenge_responses(challenge_responses.into());

        signature
            .mut_challenge()
            .set_data(source.challenge.as_bytes().to_vec());

        signature
    }
}

/// Convert external::RingCtSignature --> Signature.
impl TryFrom<&external::RingCtSignature> for SignatureRctFull {
    type Error = ConversionError;

    fn try_from(source: &external::RingCtSignature) -> Result<Self, Self::Error> {
        let mut key_images: Vec<KeyImage> = Vec::new();
        for image in source.get_key_images() {
            let key_image =
                KeyImage::try_from(image.get_data()).map_err(|_e| ConversionError::Other)?;
            key_images.push(key_image);
        }

        let mut challenge_responses: Vec<ChallengeResponse> = Vec::new();
        for response in source.get_challenge_responses() {
            let mut challenge_response: Vec<CurveScalar> = Vec::new();
            for scalar in response.get_response() {
                let curve_scalar = CurveScalar::try_from(scalar.get_data())
                    .map_err(|_e| ConversionError::Other)?;

                challenge_response.push(curve_scalar);
            }
            challenge_responses.push(ChallengeResponse {
                response: challenge_response,
            });
        }

        let challenge = CurveScalar::try_from(source.get_challenge().get_data())
            .map_err(|_e| ConversionError::Other)?;

        let tx_prefix = SignatureRctFull {
            key_images,
            challenge_responses,
            challenge,
        };
        Ok(tx_prefix)
    }
}

/// Convert tx::TxOut --> tx_grpc::TxOut.
impl From<&tx::TxOut> for tx_grpc::TxOut {
    fn from(source: &tx::TxOut) -> Self {
        let mut tx_out = tx_grpc::TxOut::new();
        let target_key_bytes: &[u8] = source.target_key.as_ref();
        tx_out.set_target_key(Vec::from(target_key_bytes));
        let public_key_bytes: &[u8] = source.public_key.as_ref();
        tx_out.set_public_key(Vec::from(public_key_bytes));
        let masked_value_bytes = source.amount.masked_value.as_bytes().to_vec();
        tx_out.set_masked_value(masked_value_bytes);
        let masked_blinding_bytes = source.amount.masked_blinding.as_bytes().to_vec();
        tx_out.set_masked_blinding(masked_blinding_bytes);
        tx_out.set_commitment(source.amount.commitment.to_bytes().to_vec());
        tx_out.set_e_account_hint(source.e_account_hint.as_ref().to_vec());
        tx_out
    }
}

/// Convert tx::TxOut --> external::TxOut.
impl From<&tx::TxOut> for external::TxOut {
    fn from(source: &tx::TxOut) -> Self {
        let mut tx_out = external::TxOut::new();

        let target_key_bytes: &[u8] = source.target_key.as_ref();
        tx_out
            .mut_target_key()
            .set_data(Vec::from(target_key_bytes));

        let public_key_bytes: &[u8] = source.public_key.as_ref();
        tx_out
            .mut_public_key()
            .set_data(Vec::from(public_key_bytes));

        let masked_value_bytes = source.amount.masked_value.as_bytes().to_vec();
        tx_out
            .mut_amount()
            .mut_masked_value()
            .set_data(masked_value_bytes);
        let masked_blinding_bytes = source.amount.masked_blinding.as_bytes().to_vec();
        tx_out
            .mut_amount()
            .mut_masked_blinding()
            .set_data(masked_blinding_bytes);
        tx_out
            .mut_amount()
            .mut_commitment()
            .set_data(source.amount.commitment.to_bytes().to_vec());
        tx_out
            .mut_e_account_hint()
            .set_data(source.e_account_hint.as_ref().to_vec());
        tx_out
    }
}

/// Convert  tx_grpc::TxOut --> tx::TxOut.
impl TryFrom<&tx_grpc::TxOut> for tx::TxOut {
    type Error = ConversionError;

    fn try_from(source: &tx_grpc::TxOut) -> Result<Self, Self::Error> {
        let commitment = Commitment::try_from(source.get_commitment())
            .map_err(|_| ConversionError::KeyCastError)?;

        fn vec_to_curve_scalar(bytes: &[u8]) -> Result<CurveScalar, ConversionError> {
            if bytes.len() != 32 {
                return Err(ConversionError::Other);
            }
            let mut curve_bytes = [0u8; 32];
            curve_bytes.copy_from_slice(&bytes);
            Ok(CurveScalar::from_bytes_mod_order(curve_bytes))
        };

        let masked_value: CurveScalar = {
            let bytes = source.get_masked_value();
            vec_to_curve_scalar(bytes)?
        };

        let masked_blinding: Blinding = {
            let bytes = source.get_masked_blinding();
            vec_to_curve_scalar(bytes)?
        };

        let amount = Amount {
            commitment,
            masked_value,
            masked_blinding,
        };

        let target_key_bytes: &[u8] = source.get_target_key();
        let target_key = RistrettoPublic::try_from(target_key_bytes)
            .map_err(|_| ConversionError::KeyCastError)?
            .into();
        let public_key_bytes: &[u8] = source.get_public_key();
        let public_key = RistrettoPublic::try_from(public_key_bytes)
            .map_err(|_| ConversionError::KeyCastError)?
            .into();
        let e_account_hint = EncryptedFogHint::try_from(source.get_e_account_hint())
            .map_err(|_| ConversionError::ArrayCastError)?;

        let tx_out_stored = tx::TxOut {
            amount,
            target_key,
            public_key,
            e_account_hint,
        };
        Ok(tx_out_stored)
    }
}

/// Convert external::TxOut --> tx::TxOut.
impl TryFrom<&external::TxOut> for tx::TxOut {
    type Error = ConversionError;

    fn try_from(source: &external::TxOut) -> Result<Self, Self::Error> {
        let commitment = Commitment::try_from(source.get_amount().get_commitment())
            .map_err(|_| ConversionError::KeyCastError)?;

        fn vec_to_curve_scalar(bytes: &[u8]) -> Result<CurveScalar, ConversionError> {
            if bytes.len() != 32 {
                return Err(ConversionError::Other);
            }
            let mut curve_bytes = [0u8; 32];
            curve_bytes.copy_from_slice(&bytes);
            Ok(CurveScalar::from_bytes_mod_order(curve_bytes))
        };

        let masked_value: CurveScalar = {
            let bytes = source.get_amount().get_masked_value().get_data();
            vec_to_curve_scalar(bytes)?
        };

        let masked_blinding: Blinding = {
            let bytes = source.get_amount().get_masked_blinding().get_data();
            vec_to_curve_scalar(bytes)?
        };

        let amount = Amount {
            commitment,
            masked_value,
            masked_blinding,
        };

        let target_key_bytes: &[u8] = source.get_target_key().get_data();
        let target_key = RistrettoPublic::try_from(target_key_bytes)
            .map_err(|_| ConversionError::KeyCastError)?
            .into();
        let public_key_bytes: &[u8] = source.get_public_key().get_data();
        let public_key = RistrettoPublic::try_from(public_key_bytes)
            .map_err(|_| ConversionError::KeyCastError)?
            .into();
        let e_account_hint = EncryptedFogHint::try_from(source.get_e_account_hint().get_data())
            .map_err(|_| ConversionError::ArrayCastError)?;

        let tx_out_stored = tx::TxOut {
            amount,
            target_key,
            public_key,
            e_account_hint,
        };
        Ok(tx_out_stored)
    }
}

/// Convert TxOutMembershipElement -> external::TxOutMembershipElement
impl From<&TxOutMembershipElement> for external::TxOutMembershipElement {
    fn from(src: &TxOutMembershipElement) -> Self {
        let mut dst = external::TxOutMembershipElement::new();
        dst.mut_range().set_from(src.range.from);
        dst.mut_range().set_to(src.range.to);
        dst.mut_hash().set_data(src.hash.to_vec());
        dst
    }
}

/// Convert external::TxOutMembershipElement -> TxOutMembershipElement
impl TryFrom<&external::TxOutMembershipElement> for TxOutMembershipElement {
    type Error = ConversionError;

    fn try_from(src: &external::TxOutMembershipElement) -> Result<Self, Self::Error> {
        let range = Range::new(src.get_range().get_from(), src.get_range().get_to())
            .map_err(|_e| ConversionError::Other)?;

        let bytes: &[u8] = src.get_hash().get_data();
        let mut hash = [0u8; 32];
        if bytes.len() != hash.len() {
            return Err(ConversionError::ArrayCastError);
        }
        hash.copy_from_slice(bytes);

        Ok(TxOutMembershipElement {
            range,
            hash: TxOutMembershipHash::from(hash),
        })
    }
}

/// Convert TxOutMembershipProof -> external::MembershipProof.
impl From<&TxOutMembershipProof> for external::TxOutMembershipProof {
    fn from(tx_out_membership_proof: &TxOutMembershipProof) -> Self {
        let mut membership_proof = external::TxOutMembershipProof::new();
        membership_proof.set_index(tx_out_membership_proof.index);
        membership_proof.set_highest_index(tx_out_membership_proof.highest_index);

        let elements: Vec<external::TxOutMembershipElement> = tx_out_membership_proof
            .elements
            .iter()
            .map(external::TxOutMembershipElement::from)
            .collect();

        membership_proof.set_elements(RepeatedField::from_vec(elements));
        membership_proof
    }
}

/// Convert external::MembershipProof --> TxOutMembershipProof.
impl TryFrom<&external::TxOutMembershipProof> for TxOutMembershipProof {
    type Error = ConversionError;

    fn try_from(membership_proof: &external::TxOutMembershipProof) -> Result<Self, Self::Error> {
        let index: u64 = membership_proof.get_index();
        let highest_index: u64 = membership_proof.get_highest_index();

        let mut elements: HashMap<Range, [u8; 32]> = HashMap::default();
        for element in membership_proof.get_elements() {
            let range: Range =
                Range::new(element.get_range().get_from(), element.get_range().get_to())
                    .map_err(|_e| ConversionError::Other)?;

            let bytes: &[u8] = element.get_hash().get_data();
            let mut hash = [0u8; 32];
            if bytes.len() != hash.len() {
                return Err(ConversionError::ArrayCastError);
            }
            hash.copy_from_slice(bytes);
            elements.insert(range, hash);
        }
        let tx_out_membership_proof = TxOutMembershipProof::new(index, highest_index, elements);
        Ok(tx_out_membership_proof)
    }
}

/// Convert TransactionValidationError --> ProposeTxResult.
impl From<TransactionValidationError> for ProposeTxResult {
    fn from(src: TransactionValidationError) -> Self {
        match src {
            TransactionValidationError::InputsProofsLengthMismatch => {
                Self::InputsProofsLengthMismatch
            }
            TransactionValidationError::NoInputs => Self::NoInputs,
            TransactionValidationError::TooManyInputs => Self::TooManyInputs,
            TransactionValidationError::InsufficientInputSignatures => {
                Self::InsufficientInputSignatures
            }
            TransactionValidationError::InvalidInputSignature => Self::InvalidInputSignature,
            TransactionValidationError::InvalidTransactionSignature => {
                Self::InvalidTransactionSignature
            }
            TransactionValidationError::InvalidRangeProof => Self::InvalidRangeProof,
            TransactionValidationError::InsufficientRingSize => Self::InsufficientRingSize,
            TransactionValidationError::TombstoneBlockExceeded => Self::TombstoneBlockExceeded,
            TransactionValidationError::TombstoneBlockTooFar => Self::TombstoneBlockTooFar,
            TransactionValidationError::NoOutputs => Self::NoOutputs,
            TransactionValidationError::TooManyOutputs => Self::TooManyOutputs,
            TransactionValidationError::ExcessiveRingSize => Self::ExcessiveRingSize,
            TransactionValidationError::DuplicateRingElements => Self::DuplicateRingElements,
            TransactionValidationError::UnsortedRingElements => Self::UnsortedRingElements,
            TransactionValidationError::UnequalRingSizes => Self::UnequalRingSizes,
            TransactionValidationError::UnsortedKeyImages => Self::UnsortedKeyImages,
            TransactionValidationError::ContainsSpentKeyImage => Self::ContainsSpentKeyImage,
            TransactionValidationError::DuplicateKeyImages => Self::DuplicateKeyImages,
            TransactionValidationError::MissingTxOutMembershipProof => {
                Self::MissingTxOutMembershipProof
            }
            TransactionValidationError::InvalidTxOutMembershipProof => {
                Self::InvalidTxOutMembershipProof
            }
            TransactionValidationError::InvalidRistrettoPublicKey => {
                Self::InvalidRistrettoPublicKey
            }
            TransactionValidationError::InvalidLedgerContext => Self::InvalidLedgerContext,
            TransactionValidationError::Ledger(_) => Self::Ledger,
            TransactionValidationError::MembershipProofValidationError => {
                Self::MembershipProofValidationError
            }
            TransactionValidationError::TxFeeError => Self::TxFeeError,
            TransactionValidationError::KeyError => Self::KeyError,
        }
    }
}

/// Convert ProposeTxResult --> TransactionValidationError.
impl TryInto<TransactionValidationError> for ProposeTxResult {
    type Error = &'static str;

    fn try_into(self) -> Result<TransactionValidationError, Self::Error> {
        match self {
            Self::Ok => Err("Ok value cannot be convererted into TransactionValidationError"),
            Self::InputsProofsLengthMismatch => {
                Ok(TransactionValidationError::InputsProofsLengthMismatch)
            }
            Self::NoInputs => Ok(TransactionValidationError::NoInputs),
            Self::TooManyInputs => Ok(TransactionValidationError::TooManyInputs),
            Self::InsufficientInputSignatures => {
                Ok(TransactionValidationError::InsufficientInputSignatures)
            }
            Self::InvalidInputSignature => Ok(TransactionValidationError::InvalidInputSignature),
            Self::InvalidTransactionSignature => {
                Ok(TransactionValidationError::InvalidTransactionSignature)
            }
            Self::InvalidRangeProof => Ok(TransactionValidationError::InvalidRangeProof),
            Self::InsufficientRingSize => Ok(TransactionValidationError::InsufficientRingSize),
            Self::TombstoneBlockExceeded => Ok(TransactionValidationError::TombstoneBlockExceeded),
            Self::TombstoneBlockTooFar => Ok(TransactionValidationError::TombstoneBlockTooFar),
            Self::NoOutputs => Ok(TransactionValidationError::NoOutputs),
            Self::TooManyOutputs => Ok(TransactionValidationError::TooManyOutputs),
            Self::ExcessiveRingSize => Ok(TransactionValidationError::ExcessiveRingSize),
            Self::DuplicateRingElements => Ok(TransactionValidationError::DuplicateRingElements),
            Self::UnsortedRingElements => Ok(TransactionValidationError::UnsortedRingElements),
            Self::UnequalRingSizes => Ok(TransactionValidationError::UnequalRingSizes),
            Self::UnsortedKeyImages => Ok(TransactionValidationError::UnsortedKeyImages),
            Self::ContainsSpentKeyImage => Ok(TransactionValidationError::ContainsSpentKeyImage),
            Self::DuplicateKeyImages => Ok(TransactionValidationError::DuplicateKeyImages),
            Self::MissingTxOutMembershipProof => {
                Ok(TransactionValidationError::MissingTxOutMembershipProof)
            }
            Self::InvalidTxOutMembershipProof => {
                Ok(TransactionValidationError::InvalidTxOutMembershipProof)
            }
            Self::InvalidRistrettoPublicKey => {
                Ok(TransactionValidationError::InvalidRistrettoPublicKey)
            }
            Self::InvalidLedgerContext => Ok(TransactionValidationError::InvalidLedgerContext),
            Self::Ledger => Ok(TransactionValidationError::Ledger(String::default())),
            Self::MembershipProofValidationError => {
                Ok(TransactionValidationError::MembershipProofValidationError)
            }
            Self::TxFeeError => Ok(TransactionValidationError::TxFeeError),
            Self::KeyError => Ok(TransactionValidationError::KeyError),
        }
    }
}

/// Helper method for getting the suggested path/filename for a given block index.
pub fn block_num_to_s3block_path(block_index: transaction::BlockIndex) -> PathBuf {
    let filename = format!("{:016x}.pb", block_index);
    let mut path = PathBuf::new();
    for i in 0..7 {
        path.push(&filename[i * 2..i * 2 + 2]);
    }
    path.push(filename);
    path
}

#[cfg(test)]
mod tests {
    extern crate rand;

    use self::rand::{rngs::StdRng, SeedableRng};
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use keys::FromRandom;
    use protobuf::Message;
    use transaction::{
        account_keys::{AccountKey, PublicAddress},
        onetime_keys::recover_onetime_private_key,
        ring_signature::Blinding,
        tx::{TxOut, TxOutMembershipProof},
    };
    use transaction_std::*;

    #[test]
    // Unmarshalling too many bytes into a BlockID should produce an error.
    fn test_from_blockchain_block_id_error() {
        let mut source = blockchain::Block::new(); // Cannot convert 37 bytes to a BlockID.
        source.set_id([1u8; 37].to_vec());
        source.set_version(1u32);
        source.set_parent_id([1u8; 32].to_vec());
        source.set_index(1);
        source.set_contents_hash([1u8; 32].to_vec());

        let converted = transaction::Block::try_from(&source);
        assert!(converted.is_err());
    }

    #[test]
    // Unmarshalling too few bytes into a BlockID should produce an error.
    fn test_from_blockchain_block_id_error_two() {
        let mut source = blockchain::Block::new();
        source.set_id([1u8; 11].to_vec()); // Cannot convert 11 bytes to a BlockID.
        source.set_version(1u32);
        source.set_parent_id([1u8; 32].to_vec());
        source.set_index(1);
        source.set_contents_hash([1u8; 32].to_vec());

        let converted = transaction::Block::try_from(&source);
        assert!(converted.is_err());
    }

    #[test]
    // Unmarshalling too many bytes into a BlockID should produce an error.
    fn test_from_blockchain_block_parent_id_error() {
        let mut source = blockchain::Block::new();
        source.set_id([1u8; 32].to_vec());
        source.set_version(1u32);
        source.set_parent_id([1u8; 37].to_vec()); // Cannot convert 37 bytes to a BlockID.
        source.set_index(1);
        source.set_contents_hash([1u8; 32].to_vec());

        let converted = transaction::Block::try_from(&source);
        assert!(converted.is_err());
    }

    #[test]
    // Unmarshalling too few bytes into a BlockID should produce an error.
    fn test_from_blockchain_block_parent_id_error_two() {
        let mut source = blockchain::Block::new();
        source.set_id([1u8; 32].to_vec());
        source.set_version(1u32);
        source.set_parent_id([1u8; 11].to_vec()); // Cannot convert 11 bytes to a BlockID.
        source.set_index(1);
        source.set_contents_hash([1u8; 32].to_vec());

        let converted = transaction::Block::try_from(&source);
        assert!(converted.is_err());
    }

    #[test]
    // Unmarshalling too many bytes into a BlockContentsHash should produce an error.
    fn test_from_blockchain_block_contents_hash_error() {
        let mut source = blockchain::Block::new();
        source.set_id([1u8; 32].to_vec());
        source.set_version(1u32);
        source.set_parent_id([1u8; 32].to_vec());
        source.set_index(1);
        source.set_contents_hash([1u8; 37].to_vec()); // Cannot convert 37 bytes to a BlockContentsHash.

        let converted = transaction::Block::try_from(&source);
        assert!(converted.is_err());
    }

    #[test]
    // Unmarshalling too few bytes into a BlockContentsHash should produce an error.
    fn test_from_blockchain_block_contents_hash_error_two() {
        let mut source = blockchain::Block::new();
        source.set_id([1u8; 32].to_vec());
        source.set_version(1u32);
        source.set_parent_id([1u8; 32].to_vec());
        source.set_index(1);
        source.set_contents_hash([1u8; 11].to_vec()); // Cannot convert 11 bytes to a BlockID.

        let converted = transaction::Block::try_from(&source);
        assert!(converted.is_err());
    }

    #[test]
    // ledger_types::TxHash --> blockchain::TxHash.
    fn test_tx_hash_from() {
        let source: tx::TxHash = tx::TxHash::from([7u8; 32]);
        let converted = tx_grpc::TxHash::from(&source);
        assert_eq!(converted.hash.as_slice(), source.as_bytes());
    }

    #[test]
    // blockchain::TxHash --> ledger_types::TxHash
    fn test_tx_hash_try_from() {
        let mut source = tx_grpc::TxHash::new();
        source.set_hash([7u8; 32].to_vec());
        let converted = tx::TxHash::try_from(&source).unwrap();
        assert_eq!(converted.0, [7u8; 32]);
    }

    #[test]
    // Unmarshalling too many bytes into a TxHash should produce an error.
    fn test_tx_hash_try_from_too_many_bytes() {
        let mut source = tx_grpc::TxHash::new();
        source.set_hash([7u8; 99].to_vec()); // Too many bytes.
        assert!(tx::TxHash::try_from(&source).is_err());
    }

    #[test]
    // Unmarshalling too few bytes into a TxHash should produce an error.
    fn test_tx_hash_try_from_too_few_bytes() {
        let mut source = tx_grpc::TxHash::new();
        source.set_hash([7u8; 3].to_vec()); // Too few bytes.
        assert!(tx::TxHash::try_from(&source).is_err());
    }

    #[test]
    // transaction::Block --> blockchain::Block
    fn test_block_from() {
        let source_block = transaction::Block {
            id: transaction::BlockID::try_from(&[2u8; 32][..]).unwrap(),
            version: 1,
            parent_id: transaction::BlockID::try_from(&[1u8; 32][..]).unwrap(),
            index: 99,
            root_element: TxOutMembershipElement {
                range: Range::new(10, 20).unwrap(),
                hash: TxOutMembershipHash::from([12u8; 32]),
            },
            contents_hash: transaction::BlockContentsHash::try_from(&[66u8; 32][..]).unwrap(),
        };

        let block = blockchain::Block::from(&source_block);
        assert_eq!(block.get_id(), [2u8; 32]);
        assert_eq!(block.get_version(), 1);
        assert_eq!(block.get_parent_id(), [1u8; 32]);
        assert_eq!(block.get_index(), 99);
        assert_eq!(block.get_root_element().get_range().get_from(), 10);
        assert_eq!(block.get_root_element().get_range().get_to(), 20);
        assert_eq!(block.get_root_element().get_hash().get_data(), &[12u8; 32]);
        assert_eq!(block.get_contents_hash(), [66u8; 32]);
    }

    #[test]
    // blockchain::Block -> transaction::Block
    fn test_block_try_from() {
        let mut root_element = external::TxOutMembershipElement::new();
        root_element.mut_range().set_from(10);
        root_element.mut_range().set_to(20);
        root_element.mut_hash().set_data([13u8; 32].to_vec());

        let mut source_block = blockchain::Block::new();
        source_block.set_id([10u8; 32].to_vec());
        source_block.set_version(1u32);
        source_block.set_parent_id([9u8; 32].to_vec());
        source_block.set_index(2);
        source_block.set_root_element(root_element);
        source_block.set_contents_hash([66u8; 32].to_vec());

        let block = transaction::Block::try_from(&source_block).unwrap();
        assert_eq!(block.id.as_ref(), [10u8; 32]);
        assert_eq!(block.version, 1);
        assert_eq!(block.parent_id.as_ref(), [9u8; 32]);
        assert_eq!(block.index, 2);
        assert_eq!(block.root_element.range.from, 10);
        assert_eq!(block.root_element.range.to, 20);
        assert_eq!(block.root_element.hash.as_ref(), &[13u8; 32]);
        assert_eq!(block.contents_hash.as_ref(), [66u8; 32]);
    }

    #[test]
    // tx::TxOutStored -> blockchain::TxOut
    fn test_tx_out_from_tx_out_stored() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let tx_out_stored = tx::TxOut {
            amount: Amount::new(
                1u64 << 13,
                Blinding::from(9u64),
                &RistrettoPublic::from_random(&mut rng),
            )
            .unwrap(),
            target_key: RistrettoPublic::from_random(&mut rng).into(),
            public_key: RistrettoPublic::from_random(&mut rng).into(),
            e_account_hint: (&[0u8; 128]).into(),
        };

        let tx_out = tx_grpc::TxOut::from(&tx_out_stored);
        let tx_out_ledger = tx::TxOut::try_from(&tx_out).unwrap();

        assert_eq!(tx_out_stored.amount, tx_out_ledger.amount);

        assert_eq!(
            tx_out.target_key,
            tx_out_stored.target_key.to_bytes().to_vec()
        );
        assert_eq!(
            tx_out.e_account_hint,
            (&tx_out_stored.e_account_hint.to_bytes()[..]).to_vec()
        );
    }

    #[test]
    // A RedactedTx that contains zero outputs or key images.
    fn test_transaction_from_tx_stored_no_outs() {
        let redacted_tx = RedactedTx::new(vec![], vec![]);
        let transaction = tx_grpc::RedactedTx::from(&redacted_tx);
        assert_eq!(transaction.outs.len(), 0);
    }

    #[test]
    // RedactedTx -> blockchain::Transaction
    fn test_transaction_from_tx_stored() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let tx_out_a = tx::TxOut {
            amount: Amount::new(
                1u64 << 17,
                Blinding::from(9u64),
                &RistrettoPublic::from_random(&mut rng),
            )
            .unwrap(),
            target_key: RistrettoPublic::from_random(&mut rng).into(),
            public_key: RistrettoPublic::from_random(&mut rng).into(),
            e_account_hint: (&[0u8; 128]).into(),
        };

        let tx_out_b = tx::TxOut {
            amount: Amount::new(
                1u64 << 18,
                Blinding::from(9u64),
                &RistrettoPublic::from_random(&mut rng),
            )
            .unwrap(),
            target_key: RistrettoPublic::from_random(&mut rng).into(),
            public_key: RistrettoPublic::from_random(&mut rng).into(),
            e_account_hint: (&[0u8; 128]).into(),
        };

        let outputs = vec![tx_out_a, tx_out_b];
        let key_images: Vec<KeyImage> = vec![KeyImage::from(RistrettoPoint::random(&mut rng))];
        let redacted_tx = RedactedTx::new(outputs, key_images);

        let transaction = tx_grpc::RedactedTx::from(&redacted_tx);
        assert_eq!(transaction.outs.len(), 2);
        assert_eq!(transaction.key_images.len(), 1);
    }

    #[test]
    fn test_key_image_from() {
        let source: KeyImage = KeyImage::from(7);
        let converted = tx_grpc::KeyImage::from(&source);
        assert_eq!(converted.value, source.to_vec());
    }

    #[test]
    fn test_key_image_try_from() {
        let key_image = KeyImage::from(11);
        let mut source = tx_grpc::KeyImage::new();
        source.set_value(key_image.to_vec());

        match KeyImage::try_from(&source) {
            Ok(image) => {
                assert_eq!(image.to_vec(), source.take_value());
            }
            Err(_e) => {
                panic!();
            }
        }
    }

    #[test]
    // `KeyImage::try_from` should return ConversionError if the source contains the
    // wrong number of bytes.
    fn test_key_image_try_from_conversion_errors() {
        // Helper function asserts that a ConversionError::ArrayCastError is produced.
        fn expects_array_cast_error(bytes: &[u8]) {
            let mut source = tx_grpc::KeyImage::new();
            source.set_value(bytes.to_vec());
            match KeyImage::try_from(&source).unwrap_err() {
                ConversionError::ArrayCastError => {} // Expected outcome.
                _ => panic!(),
            }
        }

        // Too many bytes should produce an ArrayCastError.
        expects_array_cast_error(&[11u8; 119]);

        // Too few bytes should produce an ArrayCastError.
        expects_array_cast_error(&[11u8; 3]);
    }

    #[test]
    /// Convert TxOutMembershipProof -> external::TxOutMembershipProof.
    fn test_membership_proof_from() {
        let index: u64 = 128_465;
        let highest_index: u64 = 781_384_772_994;
        let mut hashes: HashMap<Range, [u8; 32]> = HashMap::default();
        // Add some arbitrary hashes.
        hashes.insert(Range::new(0, 1).unwrap(), [2u8; 32]);
        hashes.insert(Range::new(0, 3).unwrap(), [4u8; 32]);
        hashes.insert(Range::new(0, 7).unwrap(), [8u8; 32]);
        let tx_out_membership_proof =
            TxOutMembershipProof::new(index, highest_index, hashes.clone());

        let membership_proof = external::TxOutMembershipProof::from(&tx_out_membership_proof);
        assert_eq!(membership_proof.get_index(), index);
        assert_eq!(membership_proof.get_highest_index(), highest_index);

        let elements = membership_proof.get_elements();
        assert_eq!(elements.len(), hashes.len());

        for element in elements {
            let range =
                Range::new(element.get_range().get_from(), element.get_range().get_to()).unwrap();
            let expected_hash = hashes.get(&range).unwrap();
            let bytes = element.get_hash().get_data();
            assert_eq!(bytes.len(), expected_hash.len());
            assert_eq!(bytes, expected_hash);
        }
    }

    #[test]
    /// Check that external.proto is synced with our protobufy structs
    fn test_external_proto() {
        // Generate a Tx to test with. This is copied from
        // transaction_builder.rs::test_simple_transaction
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let alice = AccountKey::random(&mut rng);
        let bob = AccountKey::random(&mut rng);
        let charlie = AccountKey::random(&mut rng);

        let minted_outputs: Vec<TxOut> = {
            // Mint an initial collection of outputs, including one belonging to `sender_account`.
            let mut recipient_and_amounts: Vec<(PublicAddress, u64)> = Vec::new();
            recipient_and_amounts.push((alice.default_subaddress(), 65536));

            // Some outputs belonging to this account will be used as mix-ins.
            recipient_and_amounts.push((charlie.default_subaddress(), 65536));
            recipient_and_amounts.push((charlie.default_subaddress(), 65536));
            transaction_test_utils::get_outputs(&recipient_and_amounts, &mut rng)
        };

        let mut transaction_builder = TransactionBuilder::new();

        let ring: Vec<TxOut> = minted_outputs.clone();
        let public_key = RistrettoPublic::try_from(&minted_outputs[0].public_key).unwrap();
        let onetime_private_key = recover_onetime_private_key(
            &public_key,
            alice.view_private_key(),
            &alice.default_subaddress_spend_key(),
        );

        let membership_proofs: Vec<TxOutMembershipProof> = ring
            .iter()
            .map(|_tx_out| {
                // TransactionBuilder does not validate membership proofs, but does require one
                // for each ring member.
                TxOutMembershipProof::new(0, 0, HashMap::default())
            })
            .collect();

        let input_credentials = InputCredentials::new(
            ring.clone(),
            membership_proofs,
            0,
            onetime_private_key,
            *alice.view_private_key(),
            &mut rng,
        )
        .unwrap();

        transaction_builder.add_input(input_credentials);
        transaction_builder.set_fee(0);
        transaction_builder
            .add_output(65536, &bob.default_subaddress(), None, &mut rng)
            .unwrap();

        let tx = transaction_builder.build(&mut rng).unwrap();

        // Serialize the tx into bytes using Prost
        let tx_prost_bytes = mcserial::encode(&tx);

        // Deserialize using rust-protobuf external.proto data type.
        let protobuf_tx =
            protobuf::parse_from_bytes::<crate::external::Tx>(&tx_prost_bytes).unwrap();

        // Serialize into bytes using protobuf
        let tx_protobuf_bytes = protobuf_tx.write_to_bytes().unwrap();

        // Make sure our bytes are not all zeros.
        assert!(!tx_prost_bytes.iter().all(|b| *b == 0));

        // Compare bytes. If this fails it means external.proto is no longer in sync with the #[prost()]
        // decorations.
        assert_eq!(tx_prost_bytes, tx_protobuf_bytes);

        // Compare some select fields.
        assert_eq!(
            tx.prefix.inputs[0].ring[0].amount.commitment.to_bytes(),
            &protobuf_tx.get_prefix().get_inputs()[0].get_ring()[0]
                .get_amount()
                .get_commitment()
                .get_data()[..]
        );

        assert_eq!(
            tx.prefix.inputs[0].ring[0].amount.masked_value.to_bytes(),
            &protobuf_tx.get_prefix().get_inputs()[0].get_ring()[0]
                .get_amount()
                .get_masked_value()
                .get_data()[..]
        );

        assert_eq!(
            tx.prefix.inputs[0].ring[0]
                .amount
                .masked_blinding
                .to_bytes(),
            &protobuf_tx.get_prefix().get_inputs()[0].get_ring()[0]
                .get_amount()
                .get_masked_blinding()
                .get_data()[..]
        );

        assert_eq!(
            tx.key_images()[0].to_bytes(),
            &protobuf_tx.signature.get_ref().key_images[0].data[..]
        );

        assert_eq!(
            tx.prefix.outputs[0].amount.commitment.to_bytes(),
            &protobuf_tx.prefix.get_ref().outputs[0]
                .amount
                .get_ref()
                .commitment
                .get_ref()
                .data[..]
        );

        assert_eq!(
            tx.prefix.outputs[0].amount.masked_value.to_bytes(),
            &protobuf_tx.prefix.get_ref().outputs[0]
                .amount
                .get_ref()
                .masked_value
                .get_ref()
                .data[..]
        );

        assert_eq!(
            tx.prefix.outputs[0].amount.masked_blinding.to_bytes(),
            &protobuf_tx.prefix.get_ref().outputs[0]
                .amount
                .get_ref()
                .masked_blinding
                .get_ref()
                .data[..]
        );

        assert_eq!(
            tx.prefix.outputs[0].target_key.to_bytes(),
            &protobuf_tx.prefix.get_ref().outputs[0]
                .target_key
                .get_ref()
                .data[..]
        );

        assert_eq!(
            tx.prefix.outputs[0].public_key.to_bytes(),
            &protobuf_tx.prefix.get_ref().outputs[0]
                .public_key
                .get_ref()
                .data[..]
        );

        assert_eq!(
            tx.prefix.outputs[0].e_account_hint.as_ref(),
            &protobuf_tx.prefix.get_ref().outputs[0]
                .e_account_hint
                .get_ref()
                .data[..]
        );

        assert_eq!(tx.prefix.fee, protobuf_tx.prefix.get_ref().fee);

        assert_eq!(tx.range_proofs, &protobuf_tx.range_proofs[..]);

        assert_eq!(tx.tombstone_block, protobuf_tx.tombstone_block);

        let external_ring: Vec<external::TxOut> = ring.iter().map(external::TxOut::from).collect();

        let ledger_ring: Vec<tx::TxOut> = external_ring
            .iter()
            .map(|tx_out| tx::TxOut::try_from(tx_out).unwrap())
            .collect();

        assert_eq!(ring, ledger_ring);

        let input = tx.prefix.inputs[0].clone();
        let external_input = external::TxIn::from(&input);
        let ledger_input = tx::TxIn::try_from(&external_input).unwrap();

        assert_eq!(input, ledger_input);

        let prefix = tx.prefix.clone();
        let external_prefix = external::TxPrefix::from(&prefix);
        let ledger_prefix = tx::TxPrefix::try_from(&external_prefix).unwrap();

        assert_eq!(prefix, ledger_prefix);

        let signature = tx.signature.clone();
        let external_signature = external::RingCtSignature::from(&signature);
        let ledger_signature = SignatureRctFull::try_from(&external_signature).unwrap();

        assert_eq!(signature, ledger_signature);

        let external_tx = external::Tx::from(&tx);
        let ledger_tx = tx::Tx::try_from(&external_tx).unwrap();

        assert_eq!(tx, ledger_tx);
    }

    #[test]
    fn test_block_num_to_s3block_path() {
        assert_eq!(
            block_num_to_s3block_path(1),
            PathBuf::from("00/00/00/00/00/00/00/0000000000000001.pb"),
        );

        assert_eq!(
            block_num_to_s3block_path(0x1a2b_3c4e_5a6b_7c8d),
            PathBuf::from("1a/2b/3c/4e/5a/6b/7c/1a2b3c4e5a6b7c8d.pb"),
        );
    }
}
