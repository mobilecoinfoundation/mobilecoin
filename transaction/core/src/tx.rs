// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Definition of a MobileCoin transaction and a MobileCoin TxOut

use alloc::vec::Vec;
use core::{convert::TryFrom, fmt};
use mc_account_keys::PublicAddress;
use mc_common::Hash;
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_crypto_hashes::{Blake2b256, Digest};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic};
use mc_util_repr_bytes::{
    derive_prost_message_from_repr_bytes, typenum::U32, GenericArray, ReprBytes,
};
use prost::Message;
use serde::{Deserialize, Serialize};

use crate::{
    amount::{Amount, AmountError, MaskedAmount},
    domain_separators::TXOUT_CONFIRMATION_NUMBER_DOMAIN_TAG,
    encrypted_fog_hint::EncryptedFogHint,
    get_tx_out_shared_secret,
    input_rules::InputRules,
    membership_proofs::Range,
    memo::{EncryptedMemo, MemoPayload},
    onetime_keys::{create_shared_secret, create_tx_out_public_key, create_tx_out_target_key},
    ring_signature::{KeyImage, SignatureRctBulletproofs, SignedInputRing},
    CompressedCommitment, NewMemoError, NewTxError, ViewKeyMatchError,
};

/// Transaction hash length, in bytes.
pub const TX_HASH_LEN: usize = 32;

#[derive(
    Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Digestible,
)]
/// Hash of a Tx.
pub struct TxHash(pub [u8; TX_HASH_LEN]);

impl TxHash {
    #[inline]
    /// Copies `self` to a new Vec.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    #[inline]
    /// A reference to the underlying byte array.
    pub fn as_bytes(&self) -> &[u8; TX_HASH_LEN] {
        &self.0
    }
}

impl core::ops::Deref for TxHash {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8; TX_HASH_LEN]> for TxHash {
    #[inline]
    fn from(a: &[u8; TX_HASH_LEN]) -> Self {
        Self(*a)
    }
}

impl From<[u8; TX_HASH_LEN]> for TxHash {
    #[inline]
    fn from(a: [u8; TX_HASH_LEN]) -> Self {
        Self(a)
    }
}

impl<'bytes> TryFrom<&'bytes [u8]> for TxHash {
    type Error = ();

    #[inline]
    fn try_from(src: &[u8]) -> Result<Self, <Self as TryFrom<&'bytes [u8]>>::Error> {
        if src.len() != TX_HASH_LEN {
            return Err(());
        }
        let mut bytes = [0u8; TX_HASH_LEN];
        bytes.copy_from_slice(src);
        Ok(Self::from(bytes))
    }
}

impl fmt::Display for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex_fmt::HexFmt(&self.0[0..6]))
    }
}

impl fmt::Debug for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Tx#{}", self)
    }
}

/// A CryptoNote-style transaction.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Message, Digestible)]
pub struct Tx {
    /// The transaction contents.
    #[prost(message, required, tag = "1")]
    pub prefix: TxPrefix,

    /// The transaction signature.
    #[prost(message, required, tag = "2")]
    pub signature: SignatureRctBulletproofs,
}

impl fmt::Display for Tx {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.tx_hash())
    }
}

impl Tx {
    /// Compute a 32-byte hash from all of the contents of a Tx
    pub fn tx_hash(&self) -> TxHash {
        TxHash::from(self.digest32::<MerlinTranscript>(b"mobilecoin-tx"))
    }

    /// Key images "spent" by this transaction.
    pub fn key_images(&self) -> Vec<KeyImage> {
        self.signature.key_images()
    }

    /// Get the highest index of each membership proof referenced by the
    /// transaction.
    pub fn get_membership_proof_highest_indices(&self) -> Vec<u64> {
        self.prefix.get_membership_proof_highest_indices()
    }

    /// Output public keys contained in this transaction.
    pub fn output_public_keys(&self) -> Vec<CompressedRistrettoPublic> {
        self.prefix
            .outputs
            .iter()
            .map(|tx_out| tx_out.public_key)
            .collect()
    }
}

/// TxPrefix is the Tx struct without the signature.  It is used to
/// calculate the prefix hash for signing and verifying.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize, Message, Digestible)]
pub struct TxPrefix {
    /// List of inputs to the transaction.
    #[prost(message, repeated, tag = "1")]
    pub inputs: Vec<TxIn>,

    /// List of outputs from the transaction.
    #[prost(message, repeated, tag = "2")]
    pub outputs: Vec<TxOut>,

    /// Fee paid to the foundation for this transaction
    #[prost(uint64, tag = "3")]
    pub fee: u64,

    /// The block index at which this transaction is no longer valid.
    #[prost(uint64, tag = "4")]
    pub tombstone_block: u64,

    /// Token id for the fee output of this transaction
    #[prost(fixed64, tag = "5")]
    pub fee_token_id: u64,
}

impl TxPrefix {
    /// Create a new TxPrefix.
    ///
    /// # Arguments:
    /// * `inputs` - Inputs spent by the transaction.
    /// * `outputs` - Outputs created by the transaction.
    /// * `fee` - Transaction fee.
    /// * `tombstone_block` - The block index at which this transaction is no
    ///   longer valid.
    pub fn new(
        inputs: Vec<TxIn>,
        outputs: Vec<TxOut>,
        fee: Amount,
        tombstone_block: u64,
    ) -> TxPrefix {
        TxPrefix {
            inputs,
            outputs,
            fee: fee.value,
            fee_token_id: *fee.token_id,
            tombstone_block,
        }
    }

    /// Digestible-crate hash of `self` using Merlin
    pub fn hash(&self) -> TxHash {
        TxHash::from(self.digest32::<MerlinTranscript>(b"mobilecoin-tx-prefix"))
    }

    /// Return the `highest_index` for each tx_out membership proof in this
    /// transaction.
    pub fn get_membership_proof_highest_indices(&self) -> Vec<u64> {
        self.inputs
            .iter()
            .flat_map(|tx_in| {
                let indices: Vec<u64> = tx_in
                    .proofs
                    .iter()
                    .map(|tx_out_membership_proof| tx_out_membership_proof.highest_index)
                    .collect();
                indices
            })
            .collect()
    }

    /// Get all output commitments.
    pub fn output_commitments(&self) -> Vec<CompressedCommitment> {
        self.outputs
            .iter()
            .map(|output| output.masked_amount.commitment)
            .collect()
    }

    /// Get all input rings.
    pub fn get_input_rings(&self) -> Vec<SignedInputRing> {
        self.inputs.iter().map(SignedInputRing::from).collect()
    }
}

/// An "input" to a transaction.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize, Message, Digestible)]
pub struct TxIn {
    /// A "ring" of outputs containing the single output that is being spent.
    /// It would be nice to use [TxOut; RING_SIZE] here, but Prost only works
    /// with Vec.
    #[prost(message, repeated, tag = "1")]
    pub ring: Vec<TxOut>,

    /// Proof that each TxOut in `ring` is in the ledger.
    /// It would be nice to use [TxOutMembershipProof; RING_SIZE] here, but
    /// Prost only works with Vec.
    #[prost(message, repeated, tag = "2")]
    pub proofs: Vec<TxOutMembershipProof>,

    /// Any rules associated to this input, per MCIP #31
    #[prost(message, tag = "3")]
    pub input_rules: Option<InputRules>,
}

impl From<&TxIn> for SignedInputRing {
    fn from(src: &TxIn) -> SignedInputRing {
        SignedInputRing {
            members: src
                .ring
                .iter()
                .map(|tx_out| {
                    (
                        tx_out.target_key.clone(),
                        tx_out.masked_amount.commitment.clone(),
                    )
                })
                .collect(),
            input_rules: src.input_rules.clone(),
        }
    }
}

/// An output created by a transaction.
#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize, Message, Digestible)]
pub struct TxOut {
    /// The amount being sent.
    #[prost(message, required, tag = "1")]
    #[digestible(name = "amount")]
    pub masked_amount: MaskedAmount,

    /// The one-time public address of this output.
    #[prost(message, required, tag = "2")]
    pub target_key: CompressedRistrettoPublic,

    /// The per output tx public key
    #[prost(message, required, tag = "3")]
    pub public_key: CompressedRistrettoPublic,

    /// The encrypted fog hint for the fog ingest server.
    #[prost(message, required, tag = "4")]
    pub e_fog_hint: EncryptedFogHint,

    /// The encrypted memo (except for old TxOut's, which don't have this.)
    #[prost(message, tag = "5")]
    pub e_memo: Option<EncryptedMemo>,
}

/// When creating a MemoPayload for a TxOut, sometimes it is important to be
/// able to have access to the fields of this TxOut. For example, in some of
/// the authenticated memos, the memo contains an HMAC, which includes the
/// tx_out_public_key, in order to bind the memo to the TxOut.
///
/// However, the TxOut public key is not created until `TxOut::new` is already
/// being called. We also want for `TxOut::new` to be responsible to encrypt
/// the memo using the shared secret. So this means that `TxOut::new_with_memo`
/// needs to take a callback which produces the memo and has access to these
/// intermediate variables.
///
/// The intermediate variables that we provide to the memo callback are gathered
/// up into a MemoContext object, and this is passed to the callback. This makes
/// the callbacks more readable and it makes it easy to pass new variables into
/// the callbacks in the future if needed without disrupting existing working
/// code.
pub struct MemoContext<'a> {
    /// The tx_public_key of the TxOut we are creating that we need a memo for
    pub tx_public_key: &'a RistrettoPublic,
}

impl TxOut {
    /// Creates a TxOut that sends `value` to `recipient`.
    /// This uses a defaulted (all zeroes) MemoPayload.
    ///
    /// # Arguments
    /// * `amount` - Amount contained within the TxOut
    /// * `recipient` - Recipient's address.
    /// * `tx_private_key` - The transaction's private key
    /// * `hint` - Encrypted Fog hint for this output.
    pub fn new(
        amount: Amount,
        recipient: &PublicAddress,
        tx_private_key: &RistrettoPrivate,
        hint: EncryptedFogHint,
    ) -> Result<Self, AmountError> {
        TxOut::new_with_memo(amount, recipient, tx_private_key, hint, |_| {
            Ok(Some(MemoPayload::default()))
        })
        .map_err(|err| match err {
            NewTxError::Amount(err) => err,
            // Memo error is unreachable because the memo_fn we passed is infallible
            NewTxError::Memo(_) => unreachable!(),
        })
    }

    /// Creates a TxOut that sends `value` to `recipient`, with a custom memo
    /// attached. The memo is produced by a callback function which is
    /// passed the value and tx_public_key.
    ///
    /// # Arguments
    /// * `amount` - Amount contained within the TxOut
    /// * `recipient` - Recipient's address.
    /// * `tx_private_key` - The transaction's private key
    /// * `hint` - Encrypted Fog hint.
    /// * `memo_fn` - A callback taking MemoContext, which produces a
    ///   MemoPayload, or a NewMemo error
    pub fn new_with_memo(
        amount: Amount,
        recipient: &PublicAddress,
        tx_private_key: &RistrettoPrivate,
        hint: EncryptedFogHint,
        memo_fn: impl FnOnce(MemoContext) -> Result<Option<MemoPayload>, NewMemoError>,
    ) -> Result<Self, NewTxError> {
        let target_key = create_tx_out_target_key(tx_private_key, recipient).into();
        let public_key = create_tx_out_public_key(tx_private_key, recipient.spend_public_key());

        let shared_secret = create_shared_secret(recipient.view_public_key(), tx_private_key);

        let masked_amount = MaskedAmount::new(amount, &shared_secret)?;

        let memo_ctxt = MemoContext {
            tx_public_key: &public_key,
        };
        let memo = memo_fn(memo_ctxt).map_err(NewTxError::Memo)?;
        let e_memo = memo.map(|memo| memo.encrypt(&shared_secret));

        Ok(TxOut {
            masked_amount,
            target_key,
            public_key: public_key.into(),
            e_fog_hint: hint,
            e_memo,
        })
    }

    /// A merlin-based hash of this TxOut.
    pub fn hash(&self) -> Hash {
        self.digest32::<MerlinTranscript>(b"mobilecoin-txout")
    }

    /// Try to establish ownership of this TxOut, using the view private key.
    ///
    /// Arguments:
    /// * view_private_key: The account view private key for the (possible)
    ///   owner
    ///
    /// Returns:
    /// * An (unmasked) Amount
    /// * The shared secret
    /// Or, an error if recovery failed.
    pub fn view_key_match(
        &self,
        view_private_key: &RistrettoPrivate,
    ) -> Result<(Amount, RistrettoPublic), ViewKeyMatchError> {
        // Reconstruct compressed commitment based on our view key.
        // The first step is reconstructing the TxOut shared secret
        let public_key = RistrettoPublic::try_from(&self.public_key)?;

        let tx_out_shared_secret = get_tx_out_shared_secret(view_private_key, &public_key);

        let (amount, _scalar) = self.masked_amount.get_value(&tx_out_shared_secret)?;

        Ok((amount, tx_out_shared_secret))
    }

    /// Try to decrypt the e_memo field, using the TxOut shared secret.
    ///
    /// This function is backwards-compatible in the following sense:
    /// - If self.e_memo is empty (a TxOut from before this field was added), we
    ///   return MemoPayload corresponding to "unused memo".
    /// - If self.e_memo is present, we use MemoPayload::try_decrypt. This
    ///   succeeds unless the e_memo has an invalid length.
    ///
    /// Note that the results of this function call are unauthenticated.
    ///
    /// The next step is usually to call MemoType::try_from to determine what
    /// memo type this is, see transaction_std::memo module. Then, if it has
    /// authentication, such as an hmac, check the hmac.
    pub fn decrypt_memo(&self, tx_out_shared_secret: &RistrettoPublic) -> MemoPayload {
        if let Some(e_memo) = self.e_memo {
            e_memo.decrypt(tx_out_shared_secret)
        } else {
            MemoPayload::default()
        }
    }
}

/// A Merkle proof-of-membership for the TxOut at the given index contains a set
/// of hashes: it includes each hash between the leaf and the root, as well as
/// each "other" child hash. It is assumed that the proof accompanies the leaf
/// TxOut, so its leaf hash may be computed as part of checking the proof.
///
/// In total, the TxOut, its index, and the set of non-leaf hashes are
/// sufficient to re-compute the root hash, which completes the
/// proof-of-membership verification.
///
/// # References
/// * [How Log Proofs Work](http://www.certificate-transparency.org/log-proofs-work)
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize, Message, Digestible)]
pub struct TxOutMembershipProof {
    /// Index of the TxOut that this proof refers to.
    #[prost(uint64, tag = "1")]
    pub index: u64,

    /// Index of the last TxOut at the time the proof was created.
    #[prost(uint64, tag = "2")]
    pub highest_index: u64,

    /// All hashes needed to recompute the root hash.
    /// These elements must be listed in the order in which they should be
    /// combined for the proof to be valid.
    #[prost(message, repeated, tag = "3")]
    pub elements: Vec<TxOutMembershipElement>,
}

impl TxOutMembershipProof {
    /// Create a Merkle proof-of-membership for a given TxOut.
    ///
    /// # Arguments
    /// * `index` - The index of the TxOut.
    /// * `highest_index` - The index of the last TxOut in the ledger,
    ///   indicating the size of the tree that the proof refers to.
    /// * `elements` - The tx out membership elements, containing ranges
    ///   referring to subtrees in the tree, and hashes. These must be provided
    ///   in the order in which they should be combined to validate the proof.
    pub fn new(index: u64, highest_index: u64, elements: Vec<TxOutMembershipElement>) -> Self {
        Self {
            index,
            highest_index,
            elements,
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialOrd, Ord, PartialEq, Serialize, Message, Digestible)]
/// An element of a TxOut membership proof, denoting an internal hash node in a
/// Merkle tree.
pub struct TxOutMembershipElement {
    /// The range of leaf nodes "under" this internal hash.
    #[prost(message, required, tag = "1")]
    pub range: Range,

    #[prost(message, required, tag = "2")]
    /// The internal hash value.
    pub hash: TxOutMembershipHash,
}

impl TxOutMembershipElement {
    /// Create a new membership element
    pub fn new(range: Range, hash: [u8; 32]) -> Self {
        Self {
            range,
            hash: hash.into(),
        }
    }
}

#[derive(
    Clone, Deserialize, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Debug, Digestible,
)]
#[digestible(transparent)]
/// A hash in a TxOut membership proof.
pub struct TxOutMembershipHash(pub [u8; 32]);

impl TxOutMembershipHash {
    /// Copies self into a new Vec.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl core::convert::AsRef<[u8; 32]> for TxOutMembershipHash {
    #[inline]
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::convert::From<&[u8; 32]> for TxOutMembershipHash {
    #[inline]
    fn from(src: &[u8; 32]) -> Self {
        Self(*src)
    }
}

impl core::convert::From<[u8; 32]> for TxOutMembershipHash {
    #[inline]
    fn from(src: [u8; 32]) -> Self {
        Self(src)
    }
}

impl ReprBytes for TxOutMembershipHash {
    type Size = U32;
    type Error = &'static str;
    fn from_bytes(src: &GenericArray<u8, U32>) -> Result<Self, &'static str> {
        Ok(Self((*src).into()))
    }
    fn to_bytes(&self) -> GenericArray<u8, U32> {
        self.0.into()
    }
}

derive_prost_message_from_repr_bytes!(TxOutMembershipHash);

/// A hash of the shared secret used to confirm tx was sent
#[derive(
    Clone, Deserialize, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Debug, Digestible,
)]
pub struct TxOutConfirmationNumber([u8; 32]);

impl TxOutConfirmationNumber {
    /// Copies self into a new Vec.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Validate a confirmation number against tx pubkey and view private key
    pub fn validate(
        &self,
        tx_pubkey: &RistrettoPublic,
        view_private_key: &RistrettoPrivate,
    ) -> bool {
        let shared_secret = get_tx_out_shared_secret(view_private_key, tx_pubkey);
        let calculated_confirmation = TxOutConfirmationNumber::from(&shared_secret);
        calculated_confirmation == *self
    }
}

impl core::convert::AsRef<[u8; 32]> for TxOutConfirmationNumber {
    #[inline]
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::convert::From<&[u8; 32]> for TxOutConfirmationNumber {
    #[inline]
    fn from(src: &[u8; 32]) -> Self {
        Self(*src)
    }
}

impl core::convert::From<[u8; 32]> for TxOutConfirmationNumber {
    #[inline]
    fn from(src: [u8; 32]) -> Self {
        Self(src)
    }
}

impl core::convert::From<&RistrettoPublic> for TxOutConfirmationNumber {
    fn from(shared_secret: &RistrettoPublic) -> Self {
        let mut hasher = Blake2b256::new();
        hasher.update(&TXOUT_CONFIRMATION_NUMBER_DOMAIN_TAG);
        hasher.update(shared_secret.to_bytes());
        Self(hasher.finalize().into())
    }
}

impl ReprBytes for TxOutConfirmationNumber {
    type Size = U32;
    type Error = &'static str;
    fn from_bytes(src: &GenericArray<u8, U32>) -> Result<Self, &'static str> {
        Ok(Self((*src).into()))
    }
    fn to_bytes(&self) -> GenericArray<u8, U32> {
        self.0.into()
    }
}

derive_prost_message_from_repr_bytes!(TxOutConfirmationNumber);

#[cfg(test)]
mod tests {
    use crate::{
        encrypted_fog_hint::{EncryptedFogHint, ENCRYPTED_FOG_HINT_LEN},
        get_tx_out_shared_secret,
        memo::MemoPayload,
        ring_signature::SignatureRctBulletproofs,
        subaddress_matches_tx_out,
        tokens::Mob,
        tx::{Tx, TxIn, TxOut, TxPrefix},
        Amount, MaskedAmount, Token,
    };
    use alloc::vec::Vec;
    use core::convert::TryFrom;
    use mc_account_keys::{AccountKey, CHANGE_SUBADDRESS_INDEX, DEFAULT_SUBADDRESS_INDEX};
    use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
    use mc_util_from_random::FromRandom;
    use prost::Message;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    // `serialize_tx` should create a Tx, encode/decode it, and compare
    fn test_serialize_tx_no_memo() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let tx_out = {
            let shared_secret = RistrettoPublic::from_random(&mut rng);
            let target_key = RistrettoPublic::from_random(&mut rng).into();
            let public_key = RistrettoPublic::from_random(&mut rng).into();
            let amount = Amount {
                value: 23u64,
                token_id: Mob::ID,
            };
            let masked_amount = MaskedAmount::new(amount, &shared_secret).unwrap();
            TxOut {
                masked_amount,
                target_key,
                public_key,
                e_fog_hint: EncryptedFogHint::from(&[1u8; ENCRYPTED_FOG_HINT_LEN]),
                e_memo: Default::default(),
            }
        };

        // TxOut = decode(encode(TxOut))
        let mut buf = Vec::new();
        tx_out.encode(&mut buf).expect("failed to serialize TxOut");
        assert_eq!(tx_out, TxOut::decode(&buf[..]).unwrap());

        let tx_in = TxIn {
            ring: vec![tx_out.clone()],
            proofs: vec![],
            input_rules: None,
        };

        // TxIn = decode(encode(TxIn))
        let mut buf = Vec::new();
        tx_in.encode(&mut buf).expect("failed to serialize TxIn");
        assert_eq!(tx_in, TxIn::decode(&buf[..]).unwrap());

        let prefix = TxPrefix {
            inputs: vec![tx_in],
            outputs: vec![tx_out],
            fee: Mob::MINIMUM_FEE,
            fee_token_id: *Mob::ID,
            tombstone_block: 23,
        };

        let mut buf = Vec::new();
        prefix
            .encode(&mut buf)
            .expect("failed to serialize into slice");

        assert_eq!(prefix, TxPrefix::decode(&buf[..]).unwrap());

        // TODO: use a meaningful signature.
        let signature = SignatureRctBulletproofs::default();

        let tx = Tx { prefix, signature };

        let mut buf = Vec::new();
        tx.encode(&mut buf).expect("failed to serialize into slice");
        let recovered_tx: Tx = Tx::decode(&buf[..]).unwrap();
        assert_eq!(tx, recovered_tx);
    }

    #[test]
    // `serialize_tx` should create a Tx, encode/decode it, and compare
    fn test_serialize_tx_with_memo() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let tx_out = {
            let shared_secret = RistrettoPublic::from_random(&mut rng);
            let target_key = RistrettoPublic::from_random(&mut rng).into();
            let public_key = RistrettoPublic::from_random(&mut rng).into();
            let amount = Amount {
                value: 23,
                token_id: Mob::ID,
            };
            let masked_amount = MaskedAmount::new(amount, &shared_secret).unwrap();
            TxOut {
                masked_amount,
                target_key,
                public_key,
                e_fog_hint: EncryptedFogHint::from(&[1u8; ENCRYPTED_FOG_HINT_LEN]),
                e_memo: Some(MemoPayload::default().encrypt(&shared_secret)),
            }
        };

        // TxOut = decode(encode(TxOut))
        let mut buf = Vec::new();
        tx_out.encode(&mut buf).expect("failed to serialize TxOut");
        assert_eq!(tx_out, TxOut::decode(&buf[..]).unwrap());

        let tx_in = TxIn {
            ring: vec![tx_out.clone()],
            proofs: vec![],
            input_rules: None,
        };

        // TxIn = decode(encode(TxIn))
        let mut buf = Vec::new();
        tx_in.encode(&mut buf).expect("failed to serialize TxIn");
        assert_eq!(tx_in, TxIn::decode(&buf[..]).unwrap());

        let prefix = TxPrefix {
            inputs: vec![tx_in],
            outputs: vec![tx_out],
            fee: Mob::MINIMUM_FEE,
            fee_token_id: *Mob::ID,
            tombstone_block: 23,
        };

        let mut buf = Vec::new();
        prefix
            .encode(&mut buf)
            .expect("failed to serialize into slice");

        assert_eq!(prefix, TxPrefix::decode(&buf[..]).unwrap());

        // TODO: use a meaningful signature.
        let signature = SignatureRctBulletproofs::default();

        let tx = Tx { prefix, signature };

        let mut buf = Vec::new();
        tx.encode(&mut buf).expect("failed to serialize into slice");
        let recovered_tx: Tx = Tx::decode(&buf[..]).unwrap();
        assert_eq!(tx, recovered_tx);
    }

    // round trip memos from `TxOut` constructors through `decrypt_memo()`
    #[test]
    fn test_decrypt_memo() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let bob = AccountKey::new(
            &RistrettoPrivate::from_random(&mut rng),
            &RistrettoPrivate::from_random(&mut rng),
        );
        let bob_addr = bob.default_subaddress();

        {
            let tx_private_key = RistrettoPrivate::from_random(&mut rng);

            // A tx out with an empty memo
            let mut tx_out = TxOut::new(
                Amount {
                    value: 13,
                    token_id: Mob::ID,
                },
                &bob_addr,
                &tx_private_key,
                Default::default(),
            )
            .unwrap();
            assert!(
                tx_out.e_memo.is_some(),
                "All TxOut (except preexisting) should have a memo"
            );
            let ss = get_tx_out_shared_secret(
                bob.view_private_key(),
                &RistrettoPublic::try_from(&tx_out.public_key).unwrap(),
            );
            assert_eq!(
                tx_out.decrypt_memo(&ss),
                MemoPayload::default(),
                "TxOut::new should produce an empty memo"
            );

            // Now, modify TxOut to make it like old TxOut's with no memo
            tx_out.e_memo = None;
            assert_eq!(
                tx_out.decrypt_memo(&ss),
                MemoPayload::default(),
                "decrypt_memo should produce an empty memo on old TxOut's"
            );
            assert!(
                subaddress_matches_tx_out(&bob, DEFAULT_SUBADDRESS_INDEX, &tx_out).unwrap(),
                "TxOut didn't belong to default subaddress"
            );
        }

        {
            let tx_private_key = RistrettoPrivate::from_random(&mut rng);

            let memo_val = MemoPayload::new([2u8; 2], [4u8; 64]);
            // A tx out with a memo
            let tx_out = TxOut::new_with_memo(
                Amount {
                    value: 13,
                    token_id: Mob::ID,
                },
                &bob_addr,
                &tx_private_key,
                Default::default(),
                |_| Ok(Some(memo_val)),
            )
            .unwrap();

            assert!(
                tx_out.e_memo.is_some(),
                "All TxOut (except preexisting) should have a memo"
            );
            let ss = get_tx_out_shared_secret(
                bob.view_private_key(),
                &RistrettoPublic::try_from(&tx_out.public_key).unwrap(),
            );
            assert_eq!(
                tx_out.decrypt_memo(&ss),
                memo_val,
                "memo did not round trip"
            );
            assert!(
                subaddress_matches_tx_out(&bob, DEFAULT_SUBADDRESS_INDEX, &tx_out).unwrap(),
                "TxOut didn't belong to default subaddress"
            );
        }

        {
            let tx_private_key = RistrettoPrivate::from_random(&mut rng);

            let memo_val = MemoPayload::new([4u8; 2], [9u8; 64]);
            // A tx out with a memo
            let tx_out = TxOut::new_with_memo(
                Amount {
                    value: 13,
                    token_id: Mob::ID,
                },
                &bob.change_subaddress(),
                &tx_private_key,
                Default::default(),
                |_| Ok(Some(memo_val)),
            )
            .unwrap();

            assert!(
                tx_out.e_memo.is_some(),
                "All TxOut (except preexisting) should have a memo"
            );
            let ss = get_tx_out_shared_secret(
                bob.view_private_key(),
                &RistrettoPublic::try_from(&tx_out.public_key).unwrap(),
            );
            assert_eq!(
                tx_out.decrypt_memo(&ss),
                memo_val,
                "memo did not round trip"
            );
            assert!(
                subaddress_matches_tx_out(&bob, CHANGE_SUBADDRESS_INDEX, &tx_out).unwrap(),
                "TxOut didn't belong to change subaddress"
            );
        }
    }
}
