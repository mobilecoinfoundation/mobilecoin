// Copyright (c) 2018-2020 MobileCoin Inc.

//! Conversions between "API types" and "domain/persistence types".
//!
//! gRPC and Protobuf provide a reduced selection of types, and so there are some differences between
//! values stored in the ledger and values transmitted over the API. This module provides conversions
//! between "equivalent" types, such as `mc_api::blockchain::Block` and `mc_transaction_core::Block`.

use crate::{blockchain, external};
use curve25519_dalek::ristretto::CompressedRistretto;
use mc_account_keys::{AccountKey, PublicAddress};
use mc_common::HashMap;
use mc_crypto_keys::{
    CompressedRistrettoPublic, Ed25519Public, Ed25519Signature, RistrettoPrivate, RistrettoPublic,
};
use mc_transaction_core::{
    amount::Amount,
    encrypted_fog_hint::EncryptedFogHint,
    range::Range,
    ring_signature::{
        CurveScalar, Error as RingSigError, KeyImage, RingMLSAG, SignatureRctBulletproofs,
    },
    tx,
    tx::{TxOutMembershipElement, TxOutMembershipHash, TxOutMembershipProof},
    BlockContents, BlockSignature, CompressedCommitment,
};
use mc_util_repr_bytes::ReprBytes;
use protobuf::RepeatedField;
use std::{
    convert::{From, TryFrom},
    error::Error,
    fmt::{self, Formatter},
    path::PathBuf,
};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum ConversionError {
    NarrowingCastError,
    ArrayCastError,
    KeyCastError,
    Key(mc_crypto_keys::KeyError),
    FeeMismatch,
    IndexOutOfBounds,
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

impl From<mc_transaction_core::ConvertError> for ConversionError {
    fn from(_src: mc_transaction_core::ConvertError) -> Self {
        Self::ArrayCastError
    }
}

impl Error for ConversionError {}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "ConversionError")
    }
}

impl From<&CompressedCommitment> for external::CompressedRistretto {
    fn from(source: &CompressedCommitment) -> Self {
        let mut compressed_ristretto = external::CompressedRistretto::new();
        compressed_ristretto.set_data(source.point.as_bytes().to_vec());
        compressed_ristretto
    }
}

impl TryFrom<&external::CompressedRistretto> for CompressedCommitment {
    type Error = ConversionError;

    fn try_from(source: &external::CompressedRistretto) -> Result<Self, Self::Error> {
        let bytes: &[u8] = source.get_data();
        if bytes.len() != 32 {
            return Err(ConversionError::ArrayCastError);
        }
        let point = CompressedRistretto::from_slice(bytes);
        Ok(CompressedCommitment { point })
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

/// Convert external::CurveScalar --> CurveScalar.
impl TryFrom<&external::CurveScalar> for CurveScalar {
    type Error = ConversionError;

    fn try_from(source: &external::CurveScalar) -> Result<Self, Self::Error> {
        let bytes: &[u8] = source.get_data();
        CurveScalar::try_from(bytes).map_err(|_| ConversionError::ArrayCastError)
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

/// Convert external::CompressedRistretto --> RistrettoPublic.
impl TryFrom<&external::CompressedRistretto> for RistrettoPublic {
    type Error = ConversionError;

    fn try_from(source: &external::CompressedRistretto) -> Result<Self, Self::Error> {
        let bytes: &[u8] = source.get_data();
        RistrettoPublic::try_from(bytes).map_err(|_| ConversionError::ArrayCastError)
    }
}

/// Convert CompressedRistrettoPublic --> external::CompressedRistretto
impl From<&CompressedRistrettoPublic> for external::CompressedRistretto {
    fn from(other: &CompressedRistrettoPublic) -> Self {
        let mut key = external::CompressedRistretto::new();
        key.set_data(other.as_bytes().to_vec());
        key
    }
}

/// Convert &RistrettoPublic --> external::CompressedRistretto
impl From<&RistrettoPublic> for external::CompressedRistretto {
    fn from(other: &RistrettoPublic) -> Self {
        let mut key = external::CompressedRistretto::new();
        key.set_data(other.to_bytes().to_vec());
        key
    }
}

/// Convert external::CompressedRistretto --> CompressedRistrettoPublic.
impl TryFrom<&external::CompressedRistretto> for CompressedRistrettoPublic {
    type Error = ConversionError;

    fn try_from(source: &external::CompressedRistretto) -> Result<Self, Self::Error> {
        let bytes: &[u8] = source.get_data();
        CompressedRistrettoPublic::try_from(bytes).map_err(|_| ConversionError::ArrayCastError)
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

/// Convert tx::TxHash --> external::TxHash.
impl From<&tx::TxHash> for external::TxHash {
    fn from(other: &tx::TxHash) -> Self {
        let mut tx_hash = external::TxHash::new();
        tx_hash.set_hash(other.to_vec());
        tx_hash
    }
}

/// Convert  external::TxHash --> tx::TxHash.
impl TryFrom<&external::TxHash> for tx::TxHash {
    type Error = ConversionError;

    fn try_from(value: &external::TxHash) -> Result<Self, Self::Error> {
        let hash_bytes: &[u8] = value.get_hash();
        tx::TxHash::try_from(hash_bytes).or(Err(ConversionError::ArrayCastError))
    }
}

/// Convert KeyImage -->  external::KeyImage.
impl From<&KeyImage> for external::KeyImage {
    fn from(other: &KeyImage) -> Self {
        let mut key_image = external::KeyImage::new();
        key_image.set_data(other.to_vec());
        key_image
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

        tx_prefix.set_tombstone_block(source.tombstone_block);

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
            tombstone_block: source.get_tombstone_block(),
        };
        Ok(tx_prefix)
    }
}

/// Convert mc_transaction_core::tx::Tx --> external::Tx.
impl From<&tx::Tx> for external::Tx {
    fn from(source: &tx::Tx) -> Self {
        let mut tx = external::Tx::new();
        tx.set_prefix(external::TxPrefix::from(&source.prefix));
        tx.set_signature(external::SignatureRctBulletproofs::from(&source.signature));
        tx
    }
}

/// Convert external::Tx --> mc_transaction_core::tx::Tx.
impl TryFrom<&external::Tx> for tx::Tx {
    type Error = ConversionError;

    fn try_from(source: &external::Tx) -> Result<Self, Self::Error> {
        let prefix = tx::TxPrefix::try_from(source.get_prefix())?;
        let signature = SignatureRctBulletproofs::try_from(source.get_signature())?;
        Ok(tx::Tx { prefix, signature })
    }
}

impl From<&RingMLSAG> for external::RingMLSAG {
    fn from(source: &RingMLSAG) -> Self {
        let mut ring_mlsag = external::RingMLSAG::new();
        ring_mlsag.set_c_zero(external::CurveScalar::from(&source.c_zero));
        let responses: Vec<external::CurveScalar> = source
            .responses
            .iter()
            .map(external::CurveScalar::from)
            .collect();
        ring_mlsag.set_responses(responses.into());
        ring_mlsag.set_key_image(external::KeyImage::from(&source.key_image));
        ring_mlsag
    }
}

impl TryFrom<&external::RingMLSAG> for RingMLSAG {
    type Error = ConversionError;

    fn try_from(source: &external::RingMLSAG) -> Result<Self, Self::Error> {
        let c_zero = CurveScalar::try_from(source.get_c_zero())?;
        let mut responses: Vec<CurveScalar> = Vec::new();
        for response in source.get_responses() {
            responses.push(CurveScalar::try_from(response)?);
        }
        let key_image = KeyImage::try_from(source.get_key_image())?;

        Ok(RingMLSAG {
            c_zero,
            responses,
            key_image,
        })
    }
}

impl From<&SignatureRctBulletproofs> for external::SignatureRctBulletproofs {
    fn from(source: &SignatureRctBulletproofs) -> Self {
        let mut signature = external::SignatureRctBulletproofs::new();

        let ring_signatures: Vec<external::RingMLSAG> = source
            .ring_signatures
            .iter()
            .map(external::RingMLSAG::from)
            .collect();
        signature.set_ring_signatures(ring_signatures.into());

        let pseudo_output_commitments: Vec<external::CompressedRistretto> = source
            .pseudo_output_commitments
            .iter()
            .map(external::CompressedRistretto::from)
            .collect();
        signature.set_pseudo_output_commitments(pseudo_output_commitments.into());

        signature.set_range_proofs(source.range_proof_bytes.clone());

        signature
    }
}

impl TryFrom<&external::SignatureRctBulletproofs> for SignatureRctBulletproofs {
    type Error = ConversionError;

    fn try_from(source: &external::SignatureRctBulletproofs) -> Result<Self, Self::Error> {
        let mut ring_signatures: Vec<RingMLSAG> = Vec::new();
        for ring_signature in source.get_ring_signatures() {
            ring_signatures.push(RingMLSAG::try_from(ring_signature)?);
        }

        let mut pseudo_output_commitments: Vec<CompressedCommitment> = Vec::new();
        for pseudo_output_commitment in source.get_pseudo_output_commitments() {
            pseudo_output_commitments
                .push(CompressedCommitment::try_from(pseudo_output_commitment)?);
        }

        let range_proof_bytes = source.get_range_proofs().to_vec();

        Ok(SignatureRctBulletproofs {
            ring_signatures,
            pseudo_output_commitments,
            range_proof_bytes,
        })
    }
}

impl From<&Amount> for external::Amount {
    fn from(source: &Amount) -> Self {
        let commitment_bytes = source.commitment.to_bytes().to_vec();
        let mut amount = external::Amount::new();
        amount.mut_commitment().set_data(commitment_bytes);
        amount.set_masked_value(source.masked_value);
        amount
    }
}

impl TryFrom<&external::Amount> for Amount {
    type Error = ConversionError;

    fn try_from(source: &external::Amount) -> Result<Self, Self::Error> {
        let commitment = CompressedCommitment::try_from(source.get_commitment())?;
        let masked_value = source.get_masked_value();
        let amount = Amount {
            commitment,
            masked_value,
        };
        Ok(amount)
    }
}

/// Convert tx::TxOut --> external::TxOut.
impl From<&tx::TxOut> for external::TxOut {
    fn from(source: &tx::TxOut) -> Self {
        let mut tx_out = external::TxOut::new();

        let amount = external::Amount::from(&source.amount);
        tx_out.set_amount(amount);

        let target_key_bytes = source.target_key.as_bytes().to_vec();
        tx_out.mut_target_key().set_data(target_key_bytes);

        let public_key_bytes = source.public_key.as_bytes().to_vec();
        tx_out.mut_public_key().set_data(public_key_bytes);

        let hint_bytes = source.e_account_hint.as_ref().to_vec();
        tx_out.mut_e_account_hint().set_data(hint_bytes);

        tx_out
    }
}

/// Convert external::TxOut --> tx::TxOut.
impl TryFrom<&external::TxOut> for tx::TxOut {
    type Error = ConversionError;

    fn try_from(source: &external::TxOut) -> Result<Self, Self::Error> {
        let amount = Amount::try_from(source.get_amount())?;

        let target_key_bytes: &[u8] = source.get_target_key().get_data();
        let target_key: CompressedRistrettoPublic = RistrettoPublic::try_from(target_key_bytes)
            .map_err(|_| ConversionError::KeyCastError)?
            .into();

        let public_key_bytes: &[u8] = source.get_public_key().get_data();
        let public_key: CompressedRistrettoPublic = RistrettoPublic::try_from(public_key_bytes)
            .map_err(|_| ConversionError::KeyCastError)?
            .into();

        let e_account_hint = EncryptedFogHint::try_from(source.get_e_account_hint().get_data())
            .map_err(|_| ConversionError::ArrayCastError)?;

        let tx_out = tx::TxOut {
            amount,
            target_key,
            public_key,
            e_account_hint,
        };
        Ok(tx_out)
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

/// Convert tx::TxOutConfirmationNumber --> external::TxOutConfirmationNumber.
impl From<&tx::TxOutConfirmationNumber> for external::TxOutConfirmationNumber {
    fn from(src: &tx::TxOutConfirmationNumber) -> Self {
        let mut tx_confirmation = external::TxOutConfirmationNumber::new();
        tx_confirmation.set_hash(src.to_vec());
        tx_confirmation
    }
}

/// Convert  external::TxOutConfirmationNumber --> tx::TxOutConfirmationNumber.
impl TryFrom<&external::TxOutConfirmationNumber> for tx::TxOutConfirmationNumber {
    type Error = ConversionError;

    fn try_from(src: &external::TxOutConfirmationNumber) -> Result<Self, Self::Error> {
        let bytes: &[u8] = src.get_hash();
        let mut hash = [0u8; 32];
        if bytes.len() != hash.len() {
            return Err(ConversionError::ArrayCastError);
        }
        hash.copy_from_slice(bytes);
        Ok(tx::TxOutConfirmationNumber::from(hash))
    }
}

/// Convert mc_transaction_core::BlockID --> blockchain::BlockID.
impl From<&mc_transaction_core::BlockID> for blockchain::BlockID {
    fn from(src: &mc_transaction_core::BlockID) -> Self {
        let mut dst = blockchain::BlockID::new();
        dst.set_data(src.as_ref().to_vec());
        dst
    }
}

/// Convert blockchain::BlockContentsHash --> mc_transaction_core::BlockID.
impl TryFrom<&blockchain::BlockID> for mc_transaction_core::BlockID {
    type Error = ConversionError;

    fn try_from(src: &blockchain::BlockID) -> Result<Self, Self::Error> {
        mc_transaction_core::BlockID::try_from(src.get_data())
            .map_err(|_| ConversionError::ArrayCastError)
    }
}

/// Convert mc_transaction_core::BlockContentsHash --> blockchain::BlockContentsHash.
impl From<&mc_transaction_core::BlockContentsHash> for blockchain::BlockContentsHash {
    fn from(src: &mc_transaction_core::BlockContentsHash) -> Self {
        let mut dst = blockchain::BlockContentsHash::new();
        dst.set_data(src.as_ref().to_vec());
        dst
    }
}

/// Convert blockchain::BlockContentsHash --> mc_transaction_core::BlockContentsHash.
impl TryFrom<&blockchain::BlockContentsHash> for mc_transaction_core::BlockContentsHash {
    type Error = ConversionError;

    fn try_from(src: &blockchain::BlockContentsHash) -> Result<Self, Self::Error> {
        mc_transaction_core::BlockContentsHash::try_from(src.get_data())
            .map_err(|_| ConversionError::ArrayCastError)
    }
}

/// Convert mc_transaction_core::Block --> blockchain::Block.
impl From<&mc_transaction_core::Block> for blockchain::Block {
    fn from(other: &mc_transaction_core::Block) -> Self {
        let mut block = blockchain::Block::new();
        block.set_id(blockchain::BlockID::from(&other.id));
        block.set_version(other.version);
        block.set_parent_id(blockchain::BlockID::from(&other.parent_id));
        block.set_index(other.index);
        block.set_cumulative_txo_count(other.cumulative_txo_count);
        block.set_root_element((&other.root_element).into());
        block.set_contents_hash(blockchain::BlockContentsHash::from(&other.contents_hash));
        block
    }
}

/// Convert blockchain::Block --> mc_transaction_core::Block.
impl TryFrom<&blockchain::Block> for mc_transaction_core::Block {
    type Error = ConversionError;

    fn try_from(value: &blockchain::Block) -> Result<Self, Self::Error> {
        let block_id = mc_transaction_core::BlockID::try_from(value.get_id())?;
        let parent_id = mc_transaction_core::BlockID::try_from(value.get_parent_id())?;
        let root_element = TxOutMembershipElement::try_from(value.get_root_element())?;
        let contents_hash =
            mc_transaction_core::BlockContentsHash::try_from(value.get_contents_hash())?;

        let block = mc_transaction_core::Block {
            id: block_id,
            version: value.version,
            parent_id,
            index: value.index,
            cumulative_txo_count: value.cumulative_txo_count,
            root_element,
            contents_hash,
        };
        Ok(block)
    }
}

impl From<&mc_transaction_core::BlockContents> for blockchain::BlockContents {
    fn from(source: &mc_transaction_core::BlockContents) -> Self {
        let mut block_contents = blockchain::BlockContents::new();

        let key_images: Vec<external::KeyImage> = source
            .key_images
            .iter()
            .map(external::KeyImage::from)
            .collect();

        let outputs: Vec<external::TxOut> =
            source.outputs.iter().map(external::TxOut::from).collect();

        block_contents.set_key_images(RepeatedField::from_vec(key_images));
        block_contents.set_outputs(RepeatedField::from_vec(outputs));
        block_contents
    }
}

impl TryFrom<&blockchain::BlockContents> for mc_transaction_core::BlockContents {
    type Error = ConversionError;

    fn try_from(source: &blockchain::BlockContents) -> Result<Self, Self::Error> {
        let mut key_images: Vec<KeyImage> = Vec::new();
        for key_image in source.get_key_images() {
            key_images.push(KeyImage::try_from(key_image)?);
        }

        let mut outputs: Vec<tx::TxOut> = Vec::new();
        for output in source.get_outputs() {
            outputs.push(tx::TxOut::try_from(output)?);
        }
        Ok(BlockContents::new(key_images, outputs))
    }
}

/// Convert BlockSignature --> blockchain::BlockSignature.
impl From<&BlockSignature> for blockchain::BlockSignature {
    fn from(src: &BlockSignature) -> Self {
        let mut dst = blockchain::BlockSignature::new();
        dst.set_signature(external::Ed25519Signature::from(src.signature()));
        dst.set_signer(external::Ed25519Public::from(src.signer()));
        dst.set_signed_at(src.signed_at());
        dst
    }
}

/// Convert blockchain::BlockSignature --> BlockSignature.
impl TryFrom<&blockchain::BlockSignature> for BlockSignature {
    type Error = ConversionError;

    fn try_from(source: &blockchain::BlockSignature) -> Result<Self, Self::Error> {
        let signature = Ed25519Signature::try_from(source.get_signature())?;
        let signer = Ed25519Public::try_from(source.get_signer())?;
        let signed_at = source.get_signed_at();
        Ok(BlockSignature::new(signature, signer, signed_at))
    }
}

/// Helper method for getting the suggested path/filename for a given block index.
pub fn block_num_to_s3block_path(block_index: mc_transaction_core::BlockIndex) -> PathBuf {
    let filename = format!("{:016x}.pb", block_index);
    let mut path = PathBuf::new();
    for i in 0..7 {
        path.push(&filename[i * 2..i * 2 + 2]);
    }
    path.push(filename);
    path
}

impl From<Vec<u8>> for external::KeyImage {
    fn from(src: Vec<u8>) -> Self {
        let mut key_image = external::KeyImage::new();
        key_image.set_data(src);
        key_image
    }
}

impl From<mc_crypto_keys::KeyError> for ConversionError {
    fn from(src: mc_crypto_keys::KeyError) -> Self {
        Self::Key(src)
    }
}

impl From<&AccountKey> for external::AccountKey {
    fn from(src: &AccountKey) -> Self {
        let mut dst = external::AccountKey::new();

        dst.set_view_private_key(external::RistrettoPrivate::from(src.view_private_key()));
        dst.set_spend_private_key(external::RistrettoPrivate::from(src.spend_private_key()));

        if let Some(url) = src.fog_report_url() {
            dst.set_fog_report_url(url.to_string());
        }

        if let Some(fingerprint) = src.fog_authority_fingerprint() {
            dst.set_fog_authority_fingerprint(fingerprint.to_vec());
        }

        if let Some(key) = src.fog_report_id() {
            dst.set_fog_report_id(key.to_string());
        }

        dst
    }
}

impl TryFrom<&external::AccountKey> for AccountKey {
    type Error = ConversionError;

    fn try_from(src: &external::AccountKey) -> Result<Self, Self::Error> {
        let spend_private_key = src
            .spend_private_key
            .as_ref()
            .ok_or(mc_crypto_keys::KeyError::LengthMismatch(0, 32))
            .and_then(|key| mc_crypto_keys::RistrettoPrivate::try_from(&key.data[..]))?;

        let view_private_key = src
            .view_private_key
            .as_ref()
            .ok_or(mc_crypto_keys::KeyError::LengthMismatch(0, 32))
            .and_then(|key| mc_crypto_keys::RistrettoPrivate::try_from(&key.data[..]))?;

        if src.fog_report_url.is_empty() {
            Ok(AccountKey::new(&spend_private_key, &view_private_key))
        } else {
            Ok(AccountKey::new_with_fog(
                &spend_private_key,
                &view_private_key,
                &src.fog_report_url,
                src.fog_report_id.clone(),
                &src.fog_authority_fingerprint[..],
            ))
        }
    }
}

impl From<&PublicAddress> for external::PublicAddress {
    fn from(src: &PublicAddress) -> Self {
        let mut dst = external::PublicAddress::new();

        dst.set_view_public_key(external::CompressedRistretto::from(src.view_public_key()));
        dst.set_spend_public_key(external::CompressedRistretto::from(src.spend_public_key()));

        if let Some(url) = src.fog_report_url() {
            dst.set_fog_report_url(url.to_string());
        }

        if let Some(sig) = src.fog_authority_fingerprint_sig() {
            dst.set_fog_authority_fingerprint_sig(sig.to_vec());
        }

        if let Some(key) = src.fog_report_id() {
            dst.set_fog_report_id(key.to_string());
        }

        dst
    }
}

impl TryFrom<&external::PublicAddress> for PublicAddress {
    type Error = ConversionError;

    fn try_from(src: &external::PublicAddress) -> Result<Self, Self::Error> {
        let spend_public_key = src
            .spend_public_key
            .as_ref()
            .ok_or(mc_crypto_keys::KeyError::LengthMismatch(0, 32))
            .and_then(|key| mc_crypto_keys::RistrettoPublic::try_from(&key.data[..]))?;

        let view_public_key = src
            .view_public_key
            .as_ref()
            .ok_or(mc_crypto_keys::KeyError::LengthMismatch(0, 32))
            .and_then(|key| mc_crypto_keys::RistrettoPublic::try_from(&key.data[..]))?;

        if src.fog_report_url.is_empty() {
            Ok(PublicAddress::new(&spend_public_key, &view_public_key))
        } else {
            Ok(PublicAddress::new_with_fog(
                &spend_public_key,
                &view_public_key,
                &src.fog_report_url,
                src.fog_report_id.clone(),
                src.fog_authority_fingerprint_sig.clone(),
            ))
        }
    }
}

#[cfg(test)]
mod conversion_tests {
    use super::*;
    use mc_crypto_keys::Ed25519Private;
    use mc_transaction_core::{
        onetime_keys::recover_onetime_private_key,
        tx::{Tx, TxOut, TxOutMembershipProof},
    };
    use mc_transaction_std::*;
    use mc_util_from_random::FromRandom;
    use mc_util_repr_bytes::ReprBytes;
    use protobuf::Message;
    use rand::{rngs::StdRng, SeedableRng};
    use std::convert::{From, TryFrom};

    #[test]
    // Unmarshalling too many bytes into a BlockID should produce an error.
    fn test_from_blockchain_block_id_error() {
        // Cannot convert 37 bytes to a BlockID.
        let mut bad_block_id = blockchain::BlockID::new();
        bad_block_id.set_data(vec![1u8; 37]);

        let converted = mc_transaction_core::BlockID::try_from(&bad_block_id);
        assert!(converted.is_err());
    }

    #[test]
    // Unmarshalling too few bytes into a BlockID should produce an error.
    fn test_from_blockchain_block_id_error_two() {
        // Cannot convert 11 bytes to a BlockID.
        let mut bad_block_id = blockchain::BlockID::new();
        bad_block_id.set_data(vec![1u8; 11]);

        let converted = mc_transaction_core::BlockID::try_from(&bad_block_id);
        assert!(converted.is_err());
    }

    #[test]
    // Unmarshalling too many bytes into a BlockContentsHash should produce an error.
    fn test_from_blockchain_block_contents_hash_error() {
        // Cannot convert 37 bytes to a BlockContentsHash.
        let mut bad_block_contents_hash = blockchain::BlockContentsHash::new();
        bad_block_contents_hash.set_data(vec![1u8; 37]);

        let converted = mc_transaction_core::BlockContentsHash::try_from(&bad_block_contents_hash);
        assert!(converted.is_err());
    }

    #[test]
    // Unmarshalling too few bytes into a BlockContentsHash should produce an error.
    fn test_from_blockchain_block_contents_hash_error_two() {
        // Cannot convert 11 bytes to a BlockContentsHash.
        let mut bad_block_contents_hash = blockchain::BlockContentsHash::new();
        bad_block_contents_hash.set_data(vec![1u8; 11]);

        let converted = mc_transaction_core::BlockContentsHash::try_from(&bad_block_contents_hash);
        assert!(converted.is_err());
    }

    #[test]
    // tx::TxHash --> external::TxHash.
    fn test_tx_hash_from() {
        let source: tx::TxHash = tx::TxHash::from([7u8; 32]);
        let converted = external::TxHash::from(&source);
        assert_eq!(converted.hash.as_slice(), source.as_bytes());
    }

    #[test]
    // external::TxHash --> tx::TxHash
    fn test_tx_hash_try_from() {
        let mut source = external::TxHash::new();
        source.set_hash(vec![7u8; 32]);
        let converted = tx::TxHash::try_from(&source).unwrap();
        assert_eq!(converted.0, [7u8; 32]);
    }

    #[test]
    // Unmarshalling too many bytes into a TxHash should produce an error.
    fn test_tx_hash_try_from_too_many_bytes() {
        let mut source = external::TxHash::new();
        source.set_hash(vec![7u8; 99]); // Too many bytes.
        assert!(tx::TxHash::try_from(&source).is_err());
    }

    #[test]
    // Unmarshalling too few bytes into a TxHash should produce an error.
    fn test_tx_hash_try_from_too_few_bytes() {
        let mut source = external::TxHash::new();
        source.set_hash(vec![7u8; 3]); // Too few bytes.
        assert!(tx::TxHash::try_from(&source).is_err());
    }

    #[test]
    // mc_transaction_core::Block --> blockchain::Block
    fn test_block_from() {
        let source_block = mc_transaction_core::Block {
            id: mc_transaction_core::BlockID::try_from(&[2u8; 32][..]).unwrap(),
            version: 1,
            parent_id: mc_transaction_core::BlockID::try_from(&[1u8; 32][..]).unwrap(),
            index: 99,
            cumulative_txo_count: 400,
            root_element: TxOutMembershipElement {
                range: Range::new(10, 20).unwrap(),
                hash: TxOutMembershipHash::from([12u8; 32]),
            },
            contents_hash: mc_transaction_core::BlockContentsHash::try_from(&[66u8; 32][..])
                .unwrap(),
        };

        let block = blockchain::Block::from(&source_block);
        assert_eq!(block.get_id().get_data(), [2u8; 32]);
        assert_eq!(block.get_version(), 1);
        assert_eq!(block.get_parent_id().get_data(), [1u8; 32]);
        assert_eq!(block.get_index(), 99);
        assert_eq!(block.get_cumulative_txo_count(), 400);
        assert_eq!(block.get_root_element().get_range().get_from(), 10);
        assert_eq!(block.get_root_element().get_range().get_to(), 20);
        assert_eq!(block.get_root_element().get_hash().get_data(), &[12u8; 32]);
        assert_eq!(block.get_contents_hash().get_data(), [66u8; 32]);
    }

    #[test]
    // blockchain::Block -> mc_transaction_core::Block
    fn test_block_try_from() {
        let mut root_element = external::TxOutMembershipElement::new();
        root_element.mut_range().set_from(10);
        root_element.mut_range().set_to(20);
        root_element.mut_hash().set_data(vec![13u8; 32]);

        let mut block_id = blockchain::BlockID::new();
        block_id.set_data(vec![10u8; 32]);

        let mut parent_block_id = blockchain::BlockID::new();
        parent_block_id.set_data(vec![9u8; 32]);

        let mut contents_hash = blockchain::BlockContentsHash::new();
        contents_hash.set_data(vec![66u8; 32]);

        let mut source_block = blockchain::Block::new();
        source_block.set_id(block_id);
        source_block.set_version(1u32);
        source_block.set_parent_id(parent_block_id);
        source_block.set_index(2);
        source_block.set_root_element(root_element);
        source_block.set_contents_hash(contents_hash);

        let block = mc_transaction_core::Block::try_from(&source_block).unwrap();
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
    // the blockchain::Block definition matches the Block prost attributes.
    // This ensures the definition in the .proto files matches the prost attributes inside the
    // Block struct.
    fn test_blockchain_block_matches_prost() {
        let source_block = mc_transaction_core::Block {
            id: mc_transaction_core::BlockID::try_from(&[2u8; 32][..]).unwrap(),
            version: 1,
            parent_id: mc_transaction_core::BlockID::try_from(&[1u8; 32][..]).unwrap(),
            index: 99,
            cumulative_txo_count: 400,
            root_element: TxOutMembershipElement {
                range: Range::new(10, 20).unwrap(),
                hash: TxOutMembershipHash::from([12u8; 32]),
            },
            contents_hash: mc_transaction_core::BlockContentsHash::try_from(&[66u8; 32][..])
                .unwrap(),
        };

        // Encode using `protobuf`, decode using `prost`.
        {
            let blockchain_block = blockchain::Block::from(&source_block);
            let blockchain_block_bytes = blockchain_block.write_to_bytes().unwrap();

            let block_from_prost: mc_transaction_core::Block =
                mc_util_serial::decode(&blockchain_block_bytes).expect("failed decoding");
            assert_eq!(source_block, block_from_prost);
        }

        // Encode using `prost`, decode using `protobuf`.
        {
            let prost_block_bytes = mc_util_serial::encode(&source_block);
            let blockchain_block: blockchain::Block =
                protobuf::parse_from_bytes(&prost_block_bytes).expect("failed decoding");

            assert_eq!(blockchain_block, blockchain::Block::from(&source_block));
        }
    }

    #[test]
    // tx::TxOut -> blockchain::TxOut --> tx::TxOut
    fn test_tx_out_from_tx_out_stored() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let source = tx::TxOut {
            amount: Amount::new(1u64 << 13, &RistrettoPublic::from_random(&mut rng)).unwrap(),
            target_key: RistrettoPublic::from_random(&mut rng).into(),
            public_key: RistrettoPublic::from_random(&mut rng).into(),
            e_account_hint: (&[0u8; 128]).into(),
        };

        let converted = external::TxOut::from(&source);

        let recovered_tx_out = tx::TxOut::try_from(&converted).unwrap();
        assert_eq!(source.amount, recovered_tx_out.amount);
    }

    #[test]
    // mc_transaction_core::BlockSignature --> blockchain::BlockSignature
    fn test_block_signature_from() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let source_block_signature = mc_transaction_core::BlockSignature::new(
            Ed25519Signature::new([1; 64]),
            (&Ed25519Private::from_random(&mut rng)).into(),
            31337,
        );

        let block_signature = blockchain::BlockSignature::from(&source_block_signature);
        assert_eq!(
            block_signature.get_signature().get_data(),
            source_block_signature.signature().as_ref()
        );
        assert_eq!(
            block_signature.get_signer().get_data(),
            source_block_signature.signer().to_bytes().as_ref(),
        );
        assert_eq!(
            block_signature.get_signed_at(),
            source_block_signature.signed_at(),
        );
    }

    #[test]
    // blockchain::BlockSignature -> mc_transaction_core::BlockSignature
    fn test_block_signature_try_from() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let expected_block_signature = mc_transaction_core::BlockSignature::new(
            Ed25519Signature::new([1; 64]),
            (&Ed25519Private::from_random(&mut rng)).into(),
            31337,
        );

        let mut source_block_signature = blockchain::BlockSignature::new();

        let mut signature = external::Ed25519Signature::new();
        signature.set_data(expected_block_signature.signature().to_bytes().to_vec());
        source_block_signature.set_signature(signature);

        let mut signer = external::Ed25519Public::new();
        signer.set_data(expected_block_signature.signer().to_bytes().to_vec());
        source_block_signature.set_signer(signer);

        source_block_signature.set_signed_at(31337);

        let block_signature =
            mc_transaction_core::BlockSignature::try_from(&source_block_signature).unwrap();
        assert_eq!(block_signature, expected_block_signature);
    }

    #[test]
    // the blockchain::BlockSignature definition matches the BlockSignature prost attributes.
    // This ensures the definition in the .proto files matches the prost attributes inside the
    // BlockSignature struct.
    fn test_blockchain_block_signature_matches_prost() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let source_block_signature = mc_transaction_core::BlockSignature::new(
            Ed25519Signature::new([1; 64]),
            (&Ed25519Private::from_random(&mut rng)).into(),
            31337,
        );

        // Encode using `protobuf`, decode using `prost`.
        {
            let blockchain_block_signature =
                blockchain::BlockSignature::from(&source_block_signature);
            let blockchain_block_signature_bytes =
                blockchain_block_signature.write_to_bytes().unwrap();

            let block_signature_from_prost: mc_transaction_core::BlockSignature =
                mc_util_serial::decode(&blockchain_block_signature_bytes).expect("failed decoding");
            assert_eq!(source_block_signature, block_signature_from_prost);
        }

        // Encode using `prost`, decode using `protobuf`.
        {
            let prost_block_signature_bytes = mc_util_serial::encode(&source_block_signature);
            let blockchain_block_signature: blockchain::BlockSignature =
                protobuf::parse_from_bytes(&prost_block_signature_bytes).expect("failed decoding");

            assert_eq!(
                blockchain_block_signature,
                blockchain::BlockSignature::from(&source_block_signature)
            );
        }
    }

    #[test]
    // KeyImage --> external::KeyImage
    fn test_key_image_from() {
        let source: KeyImage = KeyImage::from(7);
        let converted = external::KeyImage::from(&source);
        assert_eq!(converted.data, source.to_vec());
    }

    #[test]
    // external::keyImage --> KeyImage
    fn test_key_image_try_from() {
        let mut source = external::KeyImage::new();
        source.set_data(KeyImage::from(11).to_vec());

        // try_from should succeed.
        let key_image = KeyImage::try_from(&source).unwrap();

        // key_image should have the correct value.
        assert_eq!(key_image, KeyImage::from(11));
    }

    #[test]
    // `KeyImage::try_from` should return ConversionError if the source contains the
    // wrong number of bytes.
    fn test_key_image_try_from_conversion_errors() {
        // Helper function asserts that a ConversionError::ArrayCastError is produced.
        fn expects_array_cast_error(bytes: &[u8]) {
            let mut source = external::KeyImage::new();
            source.set_data(bytes.to_vec());
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
    // tx::TxOutConfirmationNumber --> external::TxOutConfirmationNumber.
    fn test_confirmation_number_from() {
        let source: tx::TxOutConfirmationNumber = tx::TxOutConfirmationNumber::from([7u8; 32]);
        let converted = external::TxOutConfirmationNumber::from(&source);
        assert_eq!(converted.hash.as_slice(), source.as_ref());
    }

    #[test]
    // external::TxOutConfirmationNumber --> tx::TxOutConfirmationNumber
    fn test_confirmation_number_try_from() {
        let mut source = external::TxOutConfirmationNumber::new();
        source.set_hash(vec![7u8; 32]);
        let converted = tx::TxOutConfirmationNumber::try_from(&source).unwrap();
        assert_eq!(*converted.as_ref(), [7u8; 32]);
    }

    #[test]
    // Unmarshalling too many bytes into a TxOutConfirmationNumber should produce an error.
    fn test_confirmation_number_try_from_too_many_bytes() {
        let mut source = external::TxOutConfirmationNumber::new();
        source.set_hash(vec![7u8; 99]); // Too many bytes.
        assert!(tx::TxOutConfirmationNumber::try_from(&source).is_err());
    }

    #[test]
    // Unmarshalling too few bytes into a TxOutConfirmationNumber should produce an error.
    fn test_confirmation_number_try_from_too_few_bytes() {
        let mut source = external::TxOutConfirmationNumber::new();
        source.set_hash(vec![7u8; 3]); // Too few bytes.
        assert!(tx::TxOutConfirmationNumber::try_from(&source).is_err());
    }

    #[test]
    /// Tx --> externalTx --> Tx should be the identity function.
    fn test_convert_tx() {
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
            mc_transaction_core_test_utils::get_outputs(&recipient_and_amounts, &mut rng)
        };

        let mut transaction_builder = TransactionBuilder::new();

        let ring: Vec<TxOut> = minted_outputs.clone();
        let public_key = RistrettoPublic::try_from(&minted_outputs[0].public_key).unwrap();
        let onetime_private_key = recover_onetime_private_key(
            &public_key,
            alice.view_private_key(),
            &alice.default_subaddress_spend_private(),
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
        )
        .unwrap();

        transaction_builder.add_input(input_credentials);
        transaction_builder.set_fee(0);
        transaction_builder
            .add_output(65536, &bob.default_subaddress(), None, &mut rng)
            .unwrap();

        let tx = transaction_builder.build(&mut rng).unwrap();

        // decode(encode(tx)) should be the identity function.
        {
            let bytes = mc_util_serial::encode(&tx);
            let recovered_tx = mc_util_serial::decode(&bytes).unwrap();
            assert_eq!(tx, recovered_tx);
        }

        // Converting mc_transaction_core::Tx -> external::Tx -> mc_transaction_core::Tx should be the identity function.
        {
            let external_tx: external::Tx = external::Tx::from(&tx);
            let recovered_tx: Tx = Tx::try_from(&external_tx).unwrap();
            assert_eq!(tx, recovered_tx);
        }

        // Encoding with prost, decoding with protobuf should be the identity function.
        {
            let bytes = mc_util_serial::encode(&tx);
            let recovered_tx: external::Tx = protobuf::parse_from_bytes(&bytes).unwrap();
            assert_eq!(recovered_tx, external::Tx::from(&tx));
        }

        // Encoding with protobuf, decoding with prost should be the identity function.
        {
            let external_tx: external::Tx = external::Tx::from(&tx);
            let bytes = external_tx.write_to_bytes().unwrap();
            let recovered_tx: Tx = mc_util_serial::decode(&bytes).unwrap();
            assert_eq!(tx, recovered_tx);
        }
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

    // Test converting between external::AccountKey and account_keys::AccountKey
    #[test]
    fn test_account_key_conversion() {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);

        // without fog_report_url
        {
            // account_keys -> external
            let account_key = AccountKey::random(&mut rng);
            let proto_credentials = external::AccountKey::from(&account_key);
            assert_eq!(
                *proto_credentials.get_view_private_key(),
                external::RistrettoPrivate::from(account_key.view_private_key())
            );
            assert_eq!(
                *proto_credentials.get_spend_private_key(),
                external::RistrettoPrivate::from(account_key.spend_private_key())
            );
            assert_eq!(proto_credentials.fog_report_url, String::from(""));

            assert_eq!(proto_credentials.fog_authority_fingerprint.len(), 0);

            assert_eq!(proto_credentials.fog_report_id, String::from(""));

            // external -> account_keys
            let account_key2 = AccountKey::try_from(&proto_credentials).unwrap();
            assert_eq!(account_key, account_key2);
        }

        // with valid fog_report_url
        {
            // account_keys -> external
            let tmp_account_key = AccountKey::random(&mut rng);
            let account_key = AccountKey::new_with_fog(
                tmp_account_key.spend_private_key(),
                tmp_account_key.view_private_key(),
                "fog://test.mobilecoin.com".to_string(),
                "99".to_string(),
                vec![9, 9, 9, 9],
            );

            let proto_credentials = external::AccountKey::from(&account_key);
            assert_eq!(
                *proto_credentials.get_view_private_key(),
                external::RistrettoPrivate::from(account_key.view_private_key())
            );
            assert_eq!(
                *proto_credentials.get_spend_private_key(),
                external::RistrettoPrivate::from(account_key.spend_private_key())
            );
            assert_eq!(
                proto_credentials.fog_report_url,
                String::from("fog://test.mobilecoin.com")
            );

            assert_eq!(
                proto_credentials.fog_authority_fingerprint,
                vec![9, 9, 9, 9],
            );

            assert_eq!(proto_credentials.fog_report_id, String::from("99"));

            // external -> account_keys
            let account_key2 = AccountKey::try_from(&proto_credentials).unwrap();
            assert_eq!(account_key, account_key2);
        }
    }

    // Test converting between external::PublicAddress and account_keys::PublicAddress
    #[test]
    fn test_public_address_conversion() {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);

        // without fog_url
        {
            // public_addresss -> external
            let public_address = AccountKey::random(&mut rng).default_subaddress();
            let proto_credentials = external::PublicAddress::from(&public_address);
            assert_eq!(
                *proto_credentials.get_view_public_key(),
                external::CompressedRistretto::from(public_address.view_public_key())
            );
            assert_eq!(
                *proto_credentials.get_spend_public_key(),
                external::CompressedRistretto::from(public_address.spend_public_key())
            );
            assert_eq!(proto_credentials.fog_report_url, String::from(""));

            assert_eq!(proto_credentials.fog_authority_fingerprint_sig.len(), 0);

            assert_eq!(proto_credentials.fog_report_id, String::from(""));

            // external -> public_addresss
            let public_address2 = PublicAddress::try_from(&proto_credentials).unwrap();
            assert_eq!(public_address, public_address2);
        }

        // with valid fog_url
        {
            // public_addresss -> external
            let tmp_public_address = AccountKey::random(&mut rng).default_subaddress();
            let public_address = PublicAddress::new_with_fog(
                tmp_public_address.spend_public_key(),
                tmp_public_address.view_public_key(),
                "fog://test.mobilecoin.com".to_string(),
                "99".to_string(),
                vec![9, 9, 9, 9],
            );

            let proto_credentials = external::PublicAddress::from(&public_address);
            assert_eq!(
                *proto_credentials.get_view_public_key(),
                external::CompressedRistretto::from(public_address.view_public_key())
            );
            assert_eq!(
                *proto_credentials.get_spend_public_key(),
                external::CompressedRistretto::from(public_address.spend_public_key())
            );
            assert_eq!(
                proto_credentials.fog_report_url,
                String::from("fog://test.mobilecoin.com")
            );

            assert_eq!(
                proto_credentials.fog_authority_fingerprint_sig,
                vec![9, 9, 9, 9],
            );

            assert_eq!(proto_credentials.fog_report_id, "99");

            // external -> public_addresss
            let public_address2 = PublicAddress::try_from(&proto_credentials).unwrap();
            assert_eq!(public_address, public_address2);
        }
    }
}
