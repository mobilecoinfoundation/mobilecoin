// Copyright (c) 2018-2022 The MobileCoin Foundation
//

use crate::{
    common::*,
    fog::McFogResolver,
    keys::{McAccountKey, McPublicAddress},
    LibMcError,
};
use core::convert::TryFrom;
use crc::Crc;
use generic_array::{typenum::U66, GenericArray};
use mc_account_keys::{AccountKey, PublicAddress, ShortAddressHash};
use mc_crypto_keys::{CompressedRistrettoPublic, ReprBytes, RistrettoPrivate, RistrettoPublic};
use mc_fog_report_validation::FogResolver;
use mc_transaction_core::{
    get_tx_out_shared_secret,
    onetime_keys::{recover_onetime_private_key, recover_public_subaddress_spend_key},
    ring_signature::KeyImage,
    tokens::Mob,
    tx::{TxOut, TxOutConfirmationNumber, TxOutMembershipProof},
    Amount, BlockVersion, CompressedCommitment, EncryptedMemo, MaskedAmount, Token,
};

use mc_transaction_std::{
    AuthenticatedSenderMemo, AuthenticatedSenderWithPaymentRequestIdMemo, ChangeDestination,
    DestinationMemo, InputCredentials, MemoBuilder, MemoPayload, RTHMemoBuilder,
    SenderMemoCredential, TransactionBuilder,
};

use mc_util_ffi::*;

/* ==== TxOut ==== */

#[repr(C)]
pub struct McTxOutAmount {
    /// 32-byte `CompressedCommitment`
    masked_value: u64,
}

pub type McTxOutMemoBuilder = Option<Box<dyn MemoBuilder + Sync + Send>>;
impl_into_ffi!(Option<Box<dyn MemoBuilder + Sync + Send>>);

/// # Preconditions
///
/// * `view_private_key` - must be a valid 32-byte Ristretto-format scalar.
#[no_mangle]
pub extern "C" fn mc_tx_out_reconstruct_commitment(
    tx_out_amount: FfiRefPtr<McTxOutAmount>,
    tx_out_public_key: FfiRefPtr<McBuffer>,
    view_private_key: FfiRefPtr<McBuffer>,
    out_tx_out_commitment: FfiMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let view_private_key = RistrettoPrivate::try_from_ffi(&view_private_key)?;

        let tx_out_public_key = RistrettoPublic::try_from_ffi(&tx_out_public_key)?;

        let shared_secret = get_tx_out_shared_secret(&view_private_key, &tx_out_public_key);

        // FIXME #1596: McTxOutAmount should include the masked_token_id bytes, which
        // are 0 or 4 bytes For now zero to avoid breaking changes to FFI
        let (masked_amount, _) =
            MaskedAmount::reconstruct(tx_out_amount.masked_value, &[], &shared_secret)?;

        let out_tx_out_commitment = out_tx_out_commitment
            .into_mut()
            .as_slice_mut_of_len(RistrettoPublic::size())
            .expect("out_tx_out_commitment length is insufficient");

        out_tx_out_commitment.copy_from_slice(&masked_amount.commitment.to_bytes());
        Ok(())
    })
}

/// # Preconditions
///
/// * `tx_out_commitment` - must be a valid CompressedCommitment
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_tx_out_commitment_crc32(
    tx_out_commitment: FfiRefPtr<McBuffer>,
    out_crc32: FfiMutPtr<u32>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let commitment = CompressedCommitment::try_from_ffi(&tx_out_commitment)?;
        *out_crc32.into_mut() =
            Crc::<u32>::new(&crc::CRC_32_ISO_HDLC).checksum(&commitment.to_bytes());
        Ok(())
    })
}

/// # Preconditions
///
/// * `view_private_key` - must be a valid 32-byte Ristretto-format scalar.
#[no_mangle]
pub extern "C" fn mc_tx_out_matches_any_subaddress(
    _tx_out_amount: FfiRefPtr<McTxOutAmount>,
    tx_out_public_key: FfiRefPtr<McBuffer>,
    view_private_key: FfiRefPtr<McBuffer>,
    out_matches: FfiMutPtr<bool>,
) -> bool {
    ffi_boundary(|| {
        let _view_private_key = RistrettoPrivate::try_from_ffi(&view_private_key)
            .expect("view_private_key is not a valid RistrettoPrivate");

        let mut matches = false;
        if let Ok(_public_key) = RistrettoPublic::try_from_ffi(&tx_out_public_key) {
            // FIXME #1596: This function doesn't make sense unless we have access to the
            // amount.commitment from the TxOut, or the commitment_crc32 from the fog tx
            // out, so that we have some way to check if we recovered the
            // correct commitment.
            matches = true;
        }
        *out_matches.into_mut() = matches;
    })
}

/// # Preconditions
///
/// * `view_private_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `subaddress_spend_private_key` - must be a valid 32-byte Ristretto-format
///   scalar.
#[no_mangle]
pub extern "C" fn mc_tx_out_matches_subaddress(
    tx_out_target_key: FfiRefPtr<McBuffer>,
    tx_out_public_key: FfiRefPtr<McBuffer>,
    view_private_key: FfiRefPtr<McBuffer>,
    subaddress_spend_private_key: FfiRefPtr<McBuffer>,
    out_matches: FfiMutPtr<bool>,
) -> bool {
    ffi_boundary(|| {
        let view_private_key = RistrettoPrivate::try_from_ffi(&view_private_key)
            .expect("view_private_key is not a valid RistrettoPrivate");
        let subaddress_spend_private_key =
            RistrettoPrivate::try_from_ffi(&subaddress_spend_private_key)
                .expect("subaddress_spend_private_key is not a valid RistrettoPrivate");

        let mut matches = false;
        if let Ok(target_key) = RistrettoPublic::try_from_ffi(&tx_out_target_key) {
            if let Ok(tx_out_public_key) = RistrettoPublic::try_from_ffi(&tx_out_public_key) {
                let onetime_private_key = recover_onetime_private_key(
                    &tx_out_public_key,
                    &view_private_key,
                    &subaddress_spend_private_key,
                );
                matches = RistrettoPublic::from(&onetime_private_key) == target_key;
            }
        }
        *out_matches.into_mut() = matches;
    })
}

/// # Preconditions
///
/// * `view_private_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `out_subaddress_spend_public_key` - length must be >= 32.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_tx_out_get_subaddress_spend_public_key(
    tx_out_target_key: FfiRefPtr<McBuffer>,
    tx_out_public_key: FfiRefPtr<McBuffer>,
    view_private_key: FfiRefPtr<McBuffer>,
    out_subaddress_spend_public_key: FfiMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let target_key = RistrettoPublic::try_from_ffi(&tx_out_target_key)?;
        let tx_out_public_key = RistrettoPublic::try_from_ffi(&tx_out_public_key)?;
        let view_private_key = RistrettoPrivate::try_from_ffi(&view_private_key)
            .expect("view_private_key is not a valid RistrettoPrivate");
        let out_subaddress_spend_public_key = out_subaddress_spend_public_key
            .into_mut()
            .as_slice_mut_of_len(RistrettoPublic::size())
            .expect("out_subaddress_spend_public_key length is insufficient");

        let subaddress_spend_public_key =
            recover_public_subaddress_spend_key(&view_private_key, &target_key, &tx_out_public_key);

        out_subaddress_spend_public_key.copy_from_slice(&subaddress_spend_public_key.to_bytes());
        Ok(())
    })
}

/// # Preconditions
///
/// * `view_private_key` - must be a valid 32-byte Ristretto-format scalar.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
/// * `LibMcError::TransactionCrypto`
#[no_mangle]
pub extern "C" fn mc_tx_out_get_value(
    tx_out_amount: FfiRefPtr<McTxOutAmount>,
    tx_out_public_key: FfiRefPtr<McBuffer>,
    view_private_key: FfiRefPtr<McBuffer>,
    out_value: FfiMutPtr<u64>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let tx_out_public_key = RistrettoPublic::try_from_ffi(&tx_out_public_key)?;
        let view_private_key = RistrettoPrivate::try_from_ffi(&view_private_key)?;

        let shared_secret = get_tx_out_shared_secret(&view_private_key, &tx_out_public_key);
        let (_masked_amount, amount) =
            MaskedAmount::reconstruct(tx_out_amount.masked_value, &[], &shared_secret)?;

        // FIXME #1596: This should also return the amount.token_id
        *out_value.into_mut() = amount.value;
        Ok(())
    })
}

/// # Preconditions
///
/// * `view_private_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `subaddress_spend_private_key` - must be a valid 32-byte Ristretto-format
///   scalar.
/// * `out_key_image` - length must be >= 32.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
/// * `LibMcError::TransactionCrypto`
#[no_mangle]
pub extern "C" fn mc_tx_out_get_key_image(
    tx_out_target_key: FfiRefPtr<McBuffer>,
    tx_out_public_key: FfiRefPtr<McBuffer>,
    view_private_key: FfiRefPtr<McBuffer>,
    subaddress_spend_private_key: FfiRefPtr<McBuffer>,
    out_key_image: FfiMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let target_key = RistrettoPublic::try_from_ffi(&tx_out_target_key)?;
        let tx_out_public_key = RistrettoPublic::try_from_ffi(&tx_out_public_key)?;
        let view_private_key = RistrettoPrivate::try_from_ffi(&view_private_key)
            .expect("view_private_key is not a valid RistrettoPrivate");
        let subaddress_spend_private_key =
            RistrettoPrivate::try_from_ffi(&subaddress_spend_private_key)
                .expect("subaddress_spend_private_key is not a valid RistrettoPrivate");
        let out_key_image = out_key_image
            .into_mut()
            .as_slice_mut_of_len(KeyImage::size())
            .expect("out_key_image length is insufficient");

        let onetime_private_key = recover_onetime_private_key(
            &tx_out_public_key,
            &view_private_key,
            &subaddress_spend_private_key,
        );
        if RistrettoPublic::from(&onetime_private_key) != target_key {
            return Err(LibMcError::TransactionCrypto(
                "TxOut is not owned by private keys".to_owned(),
            ));
        }
        let key_image = KeyImage::from(&onetime_private_key);

        out_key_image.copy_from_slice(key_image.as_ref());
        Ok(())
    })
}

/// # Preconditions
///
/// * `view_private_key` - must be a valid 32-byte Ristretto-format scalar.
#[no_mangle]
pub extern "C" fn mc_tx_out_validate_confirmation_number(
    tx_out_public_key: FfiRefPtr<McBuffer>,
    tx_out_confirmation_number: FfiRefPtr<McBuffer>,
    view_private_key: FfiRefPtr<McBuffer>,
    out_valid: FfiMutPtr<bool>,
) -> bool {
    ffi_boundary(|| {
        let view_private_key = RistrettoPrivate::try_from_ffi(&view_private_key)
            .expect("view_private_key is not a valid RistrettoPrivate");

        let mut valid = false;
        if let Ok(tx_out_public_key) = RistrettoPublic::try_from_ffi(&tx_out_public_key) {
            if let Ok(confirmation_number) =
                TxOutConfirmationNumber::try_from_ffi(&tx_out_confirmation_number)
            {
                valid = confirmation_number.validate(&tx_out_public_key, &view_private_key);
            }
        }
        *out_valid.into_mut() = valid;
    })
}

/* ==== McTransactionBuilderRing ==== */

pub type McTransactionBuilderRing = Vec<(TxOut, TxOutMembershipProof)>;
impl_into_ffi!(Vec<(TxOut, TxOutMembershipProof)>);

#[no_mangle]
pub extern "C" fn mc_transaction_builder_ring_create() -> FfiOptOwnedPtr<McTransactionBuilderRing> {
    ffi_boundary(Vec::new)
}

#[no_mangle]
pub extern "C" fn mc_transaction_builder_ring_free(
    transaction_builder_ring: FfiOptOwnedPtr<McTransactionBuilderRing>,
) {
    ffi_boundary(|| {
        let _ = transaction_builder_ring;
    })
}

/// # Preconditions
///
/// * `tx_out_proto_bytes` - must be a valid binary-serialized `external.TxOut`
///   Protobuf.
/// * `membership_proof_proto_bytes` - must be a valid binary-serialized
///   `external.TxOutMembershipProof` Protobuf.
#[no_mangle]
pub extern "C" fn mc_transaction_builder_ring_add_element(
    ring: FfiMutPtr<McTransactionBuilderRing>,
    tx_out_proto_bytes: FfiRefPtr<McBuffer>,
    membership_proof_proto_bytes: FfiRefPtr<McBuffer>,
) -> bool {
    ffi_boundary(|| {
        let tx_out: TxOut = mc_util_serial::decode(tx_out_proto_bytes.as_slice())
            .expect("tx_out_proto_bytes could not be converted to TxOut");
        let membership_proof: TxOutMembershipProof = mc_util_serial::decode(
            membership_proof_proto_bytes.as_slice(),
        )
        .expect("membership_proof_proto_bytes could not be converted to TxOutMembershipProof");

        ring.into_mut().push((tx_out, membership_proof));
    })
}

/* ==== McTransactionBuilder ==== */

pub type McTransactionBuilder = Option<TransactionBuilder<FogResolver>>;
impl_into_ffi!(Option<TransactionBuilder<FogResolver>>);

#[no_mangle]
pub extern "C" fn mc_transaction_builder_create(
    fee: u64,
    tombstone_block: u64,
    fog_resolver: FfiOptRefPtr<McFogResolver>,
    memo_builder: FfiMutPtr<McTxOutMemoBuilder>,
    block_version: u32,
) -> FfiOptOwnedPtr<McTransactionBuilder> {
    ffi_boundary(|| {
        let fog_resolver =
            fog_resolver
                .as_ref()
                .map_or_else(FogResolver::default, |fog_resolver| {
                    // It is safe to add an expect here (which should never occur) because
                    // fogReportUrl is already checked in mc_fog_resolver_add_report_response
                    // to be convertible to FogUri
                    FogResolver::new(fog_resolver.0.clone(), &fog_resolver.1)
                        .expect("FogResolver could not be constructed from the provided materials")
                });
        let block_version = BlockVersion::try_from(block_version).unwrap();

        let memo_builder_box = memo_builder
            .into_mut()
            .take()
            .expect("McTxOutMemoBuilder has already been used to build a Tx");
        // FIXME: block version should be a parameter, it should be the latest
        // version that fog ledger told us about, or that we got from ledger-db
        //let block_version = BlockVersion::ZERO;

        // TODO #1596: Support token id other than Mob
        let token_id = Mob::ID;

        let mut transaction_builder = TransactionBuilder::new_with_box(
            block_version,
            token_id,
            fog_resolver,
            memo_builder_box,
        );

        transaction_builder
            .set_fee(fee)
            .expect("failure not expected");
        transaction_builder.set_tombstone_block(tombstone_block);
        Some(transaction_builder)
    })
}

#[no_mangle]
pub extern "C" fn mc_transaction_builder_free(
    transaction_builder: FfiOptOwnedPtr<McTransactionBuilder>,
) {
    ffi_boundary(|| {
        let _ = transaction_builder;
    })
}

/// # Preconditions
///
/// * `transaction_builder` - must not have been previously consumed by a call
///   to `build`.
/// * `view_private_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `subaddress_spend_private_key` - must be a valid 32-byte Ristretto-format
///   scalar.
/// * `real_index` - must be within bounds of `ring`.
/// * `ring` - `TxOut` at `real_index` must be owned by account keys.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_transaction_builder_add_input(
    transaction_builder: FfiMutPtr<McTransactionBuilder>,
    view_private_key: FfiRefPtr<McBuffer>,
    subaddress_spend_private_key: FfiRefPtr<McBuffer>,
    real_index: usize,
    ring: FfiRefPtr<McTransactionBuilderRing>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let transaction_builder = transaction_builder
            .into_mut()
            .as_mut()
            .expect("McTransactionBuilder instance has already been used to build a Tx");
        let view_private_key = RistrettoPrivate::try_from_ffi(&view_private_key)
            .expect("view_private_key is not a valid RistrettoPrivate");
        let subaddress_spend_private_key =
            RistrettoPrivate::try_from_ffi(&subaddress_spend_private_key)
                .expect("subaddress_spend_private_key is not a valid RistrettoPrivate");
        let membership_proofs = ring.iter().map(|element| element.1.clone()).collect();
        let ring: Vec<TxOut> = ring.iter().map(|element| element.0.clone()).collect();
        let input_tx_out = ring
            .get(real_index)
            .expect("real_index not in bounds of ring")
            .clone();
        let target_key = RistrettoPublic::try_from(&input_tx_out.target_key)
            .expect("input_tx_out.target_key is not a valid RistrettoPublic");
        let public_key = RistrettoPublic::try_from(&input_tx_out.public_key)
            .expect("input_tx_out.public_key is not a valid RistrettoPublic");

        let onetime_private_key = recover_onetime_private_key(
            &public_key,
            &view_private_key,
            &subaddress_spend_private_key,
        );
        if RistrettoPublic::from(&onetime_private_key) != target_key {
            panic!("TxOut at real_index isn't owned by account key");
        }
        let input_credential = InputCredentials::new(
            ring,
            membership_proofs,
            real_index,
            onetime_private_key,
            view_private_key, // `a`
        )
        .map_err(|err| LibMcError::InvalidInput(format!("{:?}", err)))?;
        transaction_builder.add_input(input_credential);

        Ok(())
    })
}

/// # Preconditions
///
/// * `transaction_builder` - must not have been previously consumed by a call
///   to `build`.
/// * `recipient_address` - must be a valid `PublicAddress`.
/// * `out_subaddress_spend_public_key` - length must be >= 32.
///
/// # Errors
///
/// * `LibMcError::AttestationVerification`
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_transaction_builder_add_output(
    transaction_builder: FfiMutPtr<McTransactionBuilder>,
    amount: u64,
    recipient_address: FfiRefPtr<McPublicAddress>,
    rng_callback: FfiOptMutPtr<McRngCallback>,
    out_tx_out_confirmation_number: FfiMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> FfiOptOwnedPtr<McData> {
    ffi_boundary_with_error(out_error, || {
        let transaction_builder = transaction_builder
            .into_mut()
            .as_mut()
            .expect("McTransactionBuilder instance has already been used to build a Tx");
        let recipient_address =
            PublicAddress::try_from_ffi(&recipient_address).expect("recipient_address is invalid");
        let mut rng = SdkRng::from_ffi(rng_callback);
        let out_tx_out_confirmation_number = out_tx_out_confirmation_number
            .into_mut()
            .as_slice_mut_of_len(TxOutConfirmationNumber::size())
            .expect("out_tx_out_confirmation_number length is insufficient");

        // TODO: If you want to support mixed transactions, use something other
        // than fee_token_id here.
        let amount = Amount {
            value: amount,
            token_id: transaction_builder.get_fee_token_id(),
        };

        let (tx_out, confirmation) =
            transaction_builder.add_output(amount, &recipient_address, &mut rng)?;

        out_tx_out_confirmation_number.copy_from_slice(confirmation.as_ref());
        Ok(mc_util_serial::encode(&tx_out))
    })
}

/// # Preconditions
///
/// * `account_key` - must be a valid account key, default change address
///   computed from account key
/// * `transaction_builder` - must not have been previously consumed by a call
///   to `build`.
/// * `out_tx_out_confirmation_number` - length must be >= 32.
///
/// # Errors
///
/// * `LibMcError::AttestationVerification`
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_transaction_builder_add_change_output(
    account_key: FfiRefPtr<McAccountKey>,
    transaction_builder: FfiMutPtr<McTransactionBuilder>,
    amount: u64,
    rng_callback: FfiOptMutPtr<McRngCallback>,
    out_tx_out_confirmation_number: FfiMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> FfiOptOwnedPtr<McData> {
    ffi_boundary_with_error(out_error, || {
        let account_key_obj =
            AccountKey::try_from_ffi(&account_key).expect("account_key is invalid");
        let transaction_builder = transaction_builder
            .into_mut()
            .as_mut()
            .expect("McTransactionBuilder instance has already been used to build a Tx");
        let change_destination = ChangeDestination::from(&account_key_obj);
        let mut rng = SdkRng::from_ffi(rng_callback);
        let out_tx_out_confirmation_number = out_tx_out_confirmation_number
            .into_mut()
            .as_slice_mut_of_len(TxOutConfirmationNumber::size())
            .expect("out_tx_out_confirmation_number length is insufficient");

        // TODO: If you want to support mixed transactions, use something other
        // than fee_token_id here.
        let amount = Amount {
            value: amount,
            token_id: transaction_builder.get_fee_token_id(),
        };

        let (tx_out, confirmation) =
            transaction_builder.add_change_output(amount, &change_destination, &mut rng)?;

        out_tx_out_confirmation_number.copy_from_slice(confirmation.as_ref());
        Ok(mc_util_serial::encode(&tx_out))
    })
}

/// # Preconditions
///
/// * `transaction_builder` - must not have been previously consumed by a call
///   to `build`.
/// * `recipient_address` - must be a valid `PublicAddress`.
/// * `fog_hint_address` - must be a valid `PublicAddress` with `fog_info`.
/// * `out_tx_out_confirmation_number` - length must be >= 32.
///
/// # Errors
///
/// * `LibMcError::AttestationVerification`
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_transaction_builder_add_output_with_fog_hint_address(
    _transaction_builder: FfiMutPtr<McTransactionBuilder>,
    _amount: u64,
    _recipient_address: FfiRefPtr<McPublicAddress>,
    _fog_hint_address: FfiRefPtr<McPublicAddress>,
    _rng_callback: FfiOptMutPtr<McRngCallback>,
    _out_tx_out_confirmation_number: FfiMutPtr<McMutableBuffer>,
    _out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> FfiOptOwnedPtr<McData> {
    // FIXME(chris): The SDK should probably stop binding to this function, I don't
    // believe that there is legitimate use for this.
    // It should bind "add_change_output" instead.
    // Please speak to me if you disagree.
    unimplemented!("TransactionBuilder::add_output_with_fog_hint_address was removed, please use add_change_output");
}

/// # Preconditions
///
/// * `transaction_builder` - must not have been previously consumed by a call
///   to `build`.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_transaction_builder_build(
    transaction_builder: FfiMutPtr<McTransactionBuilder>,
    rng_callback: FfiOptMutPtr<McRngCallback>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> FfiOptOwnedPtr<McData> {
    ffi_boundary_with_error(out_error, || {
        let transaction_builder = transaction_builder
            .into_mut()
            .take()
            .expect("McTransactionBuilder instance has already been used to build a Tx");
        let mut rng = SdkRng::from_ffi(rng_callback);

        let tx = transaction_builder
            .build(&mut rng)
            .map_err(|err| LibMcError::InvalidInput(format!("{:?}", err)))?;
        Ok(mc_util_serial::encode(&tx))
    })
}

/* ==== TxOutMemoBuilder ==== */

/// # Preconditions
///
/// * `account_key` - must be a valid `AccountKey` with `fog_info`.
#[no_mangle]
pub extern "C" fn mc_memo_builder_sender_and_destination_create(
    account_key: FfiRefPtr<McAccountKey>,
) -> FfiOptOwnedPtr<McTxOutMemoBuilder> {
    ffi_boundary(|| {
        let account_key = AccountKey::try_from_ffi(&account_key).expect("account_key is invalid");
        let mut rth_memo_builder: RTHMemoBuilder = RTHMemoBuilder::default();
        rth_memo_builder.set_sender_credential(SenderMemoCredential::from(&account_key));
        rth_memo_builder.enable_destination_memo();

        let memo_builder_box: Box<dyn MemoBuilder + Sync + Send> = Box::new(rth_memo_builder);

        Some(memo_builder_box)
    })
}

/// # Preconditions
///
/// * `account_key` - must be a valid `AccountKey` with `fog_info`.
#[no_mangle]
pub extern "C" fn mc_memo_builder_sender_payment_request_and_destination_create(
    payment_request_id: u64,
    account_key: FfiRefPtr<McAccountKey>,
) -> FfiOptOwnedPtr<McTxOutMemoBuilder> {
    ffi_boundary(|| {
        let account_key = AccountKey::try_from_ffi(&account_key).expect("account_key is invalid");
        let mut rth_memo_builder: RTHMemoBuilder = RTHMemoBuilder::default();
        rth_memo_builder.set_sender_credential(SenderMemoCredential::from(&account_key));
        rth_memo_builder.set_payment_request_id(payment_request_id);
        rth_memo_builder.enable_destination_memo();

        let memo_builder_box: Box<dyn MemoBuilder + Sync + Send> = Box::new(rth_memo_builder);

        Some(memo_builder_box)
    })
}

#[no_mangle]
pub extern "C" fn mc_memo_builder_default_create() -> FfiOptOwnedPtr<McTxOutMemoBuilder> {
    ffi_boundary(|| {
        let memo_builder_box: Box<dyn MemoBuilder + Sync + Send> =
            Box::new(RTHMemoBuilder::default());
        Some(memo_builder_box)
    })
}

#[no_mangle]
pub extern "C" fn mc_memo_builder_free(memo_builder: FfiOptOwnedPtr<McTxOutMemoBuilder>) {
    ffi_boundary(|| {
        let _ = memo_builder;
    })
}

/* ==== SenderMemo ==== */

/// # Preconditions
///
/// * `sender_memo_data` - must be 64 bytes
/// * `sender_public_address` - must be a valid `PublicAddress`.
/// * `receiving_subaddress_view_private_key` - must be a valid 32-byte
///   Ristretto-format scalar.
/// * `tx_out_public_key` - must be a valid 32-byte Ristretto-format scalar.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_memo_sender_memo_is_valid(
    sender_memo_data: FfiRefPtr<McBuffer>,
    sender_public_address: FfiRefPtr<McPublicAddress>,
    receiving_subaddress_view_private_key: FfiRefPtr<McBuffer>,
    tx_out_public_key: FfiRefPtr<McBuffer>,
    out_valid: FfiMutPtr<bool>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let sender_public_address = PublicAddress::try_from_ffi(&sender_public_address)
            .expect("sender_public_address is invalid");

        let receiving_subaddress_view_private_key =
            RistrettoPrivate::try_from_ffi(&receiving_subaddress_view_private_key)
                .expect("receiving_subaddress_view_private_key is not a valid RistrettoPrivate");

        let tx_out_public_key_compressed =
            CompressedRistrettoPublic::try_from_ffi(&tx_out_public_key)
                .expect("tx_out_public_key is not a valid RistrettoPublic");

        let memo_data =
            <[u8; 64]>::try_from_ffi(&sender_memo_data).expect("sender_memo_data invalid length");

        let authenticated_sender_memo: AuthenticatedSenderMemo =
            AuthenticatedSenderMemo::from(&memo_data);

        let is_memo_valid = authenticated_sender_memo.validate(
            &sender_public_address,
            &receiving_subaddress_view_private_key,
            &tx_out_public_key_compressed,
        );

        *out_valid.into_mut() = bool::from(is_memo_valid);

        Ok(())
    })
}

/// # Preconditions
///
/// * `sender_account_key` - must be a valid account key
/// * `recipient_subaddress_view_public_key` - must be a valid 32-byte
///   Ristretto-format scalar.
/// * `tx_out_public_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `out_memo_data` - length must be >= 64.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_memo_sender_memo_create(
    sender_account_key: FfiRefPtr<McAccountKey>,
    recipient_subaddress_view_public_key: FfiRefPtr<McBuffer>,
    tx_out_public_key: FfiRefPtr<McBuffer>,
    out_memo_data: FfiMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let sender_account_key =
            AccountKey::try_from_ffi(&sender_account_key).expect("account_key is invalid");
        let recipient_subaddress_view_public_key =
            RistrettoPublic::try_from_ffi(&recipient_subaddress_view_public_key)?;
        let tx_out_public_key = CompressedRistrettoPublic::try_from_ffi(&tx_out_public_key)?;

        let sender_cred = SenderMemoCredential::from(&sender_account_key);
        let memo = AuthenticatedSenderMemo::new(
            &sender_cred,
            &recipient_subaddress_view_public_key,
            &tx_out_public_key,
        );

        let memo_bytes: [u8; 64] = memo.into();

        let out_memo_data = out_memo_data
            .into_mut()
            .as_slice_mut_of_len(core::mem::size_of_val(&memo_bytes))
            .expect("out_memo_data length is insufficient");

        out_memo_data.copy_from_slice(&memo_bytes);
        Ok(())
    })
}

/// # Preconditions
///
/// * `sender_memo_data` - must be 64 bytes
/// * `out_short_address_hash` - length must be >= 16 bytes
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_memo_sender_memo_get_address_hash(
    sender_memo_data: FfiRefPtr<McBuffer>,
    out_short_address_hash: FfiMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let memo_data =
            <[u8; 64]>::try_from_ffi(&sender_memo_data).expect("sender_memo_data invalid length");

        let authenticated_sender_memo: AuthenticatedSenderMemo =
            AuthenticatedSenderMemo::from(&memo_data);

        let short_address_hash: ShortAddressHash = authenticated_sender_memo.sender_address_hash();

        let hash_data: [u8; 16] = short_address_hash.into();

        let out_short_address_hash = out_short_address_hash
            .into_mut()
            .as_slice_mut_of_len(core::mem::size_of_val(&hash_data))
            .expect("ShortAddressHash length is insufficient");

        out_short_address_hash.copy_from_slice(&hash_data);
        Ok(())
    })
}

/********************************************************************
 * DestinationMemo
 */

/// # Preconditions
///
/// * `destination_public_address` - must be a valid 32-byte Ristretto-format
///   scalar.
/// * `number_of_recipients` - must be > 0
/// * `out_memo_data` - length must be >= 64.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_memo_destination_memo_create(
    destination_public_address: FfiRefPtr<McPublicAddress>,
    number_of_recipients: u8,
    fee: u64,
    total_outlay: u64,
    out_memo_data: FfiMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let destination_public_address = PublicAddress::try_from_ffi(&destination_public_address)
            .expect("destination_public_address is invalid");

        let mut memo = DestinationMemo::new(
            ShortAddressHash::from(&destination_public_address),
            total_outlay,
            fee,
        )
        .unwrap();

        memo.set_num_recipients(number_of_recipients);

        let memo_bytes: [u8; 64] = memo.clone().into();

        let out_memo_data = out_memo_data
            .into_mut()
            .as_slice_mut_of_len(core::mem::size_of_val(&memo_bytes))
            .expect("out_memo_data length is insufficient");

        out_memo_data.copy_from_slice(&memo_bytes);
        Ok(())
    })
}

/// # Preconditions
///
/// * `destination_memo_data` - must be 64 bytes
/// * `out_short_address_hash` - length must be >= 16 bytes
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_memo_destination_memo_get_address_hash(
    destination_memo_data: FfiRefPtr<McBuffer>,
    out_short_address_hash: FfiMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let memo_data = <[u8; 64]>::try_from_ffi(&destination_memo_data)
            .expect("destination_memo_data invalid length");

        let destination_memo: DestinationMemo = DestinationMemo::from(&memo_data);

        let short_address_hash: &ShortAddressHash = destination_memo.get_address_hash();

        let hash_data: [u8; 16] = <[u8; 16]>::from(short_address_hash.clone());

        let out_short_address_hash = out_short_address_hash
            .into_mut()
            .as_slice_mut_of_len(core::mem::size_of_val(&hash_data))
            .expect("ShortAddressHash length is insufficient");

        out_short_address_hash.copy_from_slice(&hash_data);

        Ok(())
    })
}

/// # Preconditions
///
/// * `destination_memo_data` - must be 64 bytes
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_memo_destination_memo_get_number_of_recipients(
    destination_memo_data: FfiRefPtr<McBuffer>,
    out_number_of_recipients: FfiMutPtr<u8>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let memo_data = <[u8; 64]>::try_from_ffi(&destination_memo_data)
            .expect("destination_memo_data invalid length");

        let destination_memo: DestinationMemo = DestinationMemo::from(&memo_data);

        let number_of_recipients: u8 = destination_memo.get_num_recipients();

        *out_number_of_recipients.into_mut() = number_of_recipients;

        Ok(())
    })
}

/// # Preconditions
///
/// * `destination_memo_data` - must be 64 bytes
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_memo_destination_memo_get_fee(
    destination_memo_data: FfiRefPtr<McBuffer>,
    out_fee: FfiMutPtr<u64>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let memo_data = <[u8; 64]>::try_from_ffi(&destination_memo_data)
            .expect("destination_memo_data invalid length");

        let destination_memo: DestinationMemo = DestinationMemo::from(&memo_data);

        let fee: u64 = destination_memo.get_fee();

        *out_fee.into_mut() = fee;

        Ok(())
    })
}

/// # Preconditions
///
/// * `destination_memo_data` - must be 64 bytes
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_memo_destination_memo_get_total_outlay(
    destination_memo_data: FfiRefPtr<McBuffer>,
    out_total_outlay: FfiMutPtr<u64>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let memo_data = <[u8; 64]>::try_from_ffi(&destination_memo_data)
            .expect("destination_memo_data invalid length");

        let destination_memo: DestinationMemo = DestinationMemo::from(&memo_data);

        let total_outlay: u64 = destination_memo.get_total_outlay();

        *out_total_outlay.into_mut() = total_outlay;

        Ok(())
    })
}

/********************************************************************
 * SenderWithPaymentRequestMemo
 */

/// # Preconditions
///
/// * `sender_with_payment_request_memo_data` - must be 64 bytes
/// * `sender_public_address` - must be a valid `PublicAddress`.
/// * `receiving_subaddress_view_private_key` - must be a valid 32-byte
///   Ristretto-format scalar.
/// * `tx_out_public_key` - must be a valid 32-byte Ristretto-format scalar.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_memo_sender_with_payment_request_memo_is_valid(
    sender_with_payment_request_memo_data: FfiRefPtr<McBuffer>,
    sender_public_address: FfiRefPtr<McPublicAddress>,
    receiving_subaddress_view_private_key: FfiRefPtr<McBuffer>,
    tx_out_public_key: FfiRefPtr<McBuffer>,
    out_valid: FfiMutPtr<bool>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let sender_public_address = PublicAddress::try_from_ffi(&sender_public_address)
            .expect("sender_public_address is invalid");

        let receiving_subaddress_view_private_key =
            RistrettoPrivate::try_from_ffi(&receiving_subaddress_view_private_key)
                .expect("receiving_subaddress_view_private_key is not a valid RistrettoPrivate");

        let tx_out_public_key_compressed =
            CompressedRistrettoPublic::try_from_ffi(&tx_out_public_key)
                .expect("tx_out_public_key is not a valid RistrettoPublic");

        let memo_data = <[u8; 64]>::try_from_ffi(&sender_with_payment_request_memo_data)
            .expect("sender_with_payment_request_memo_data invalid length");

        let authenticated_sender_with_payment_request_memo: AuthenticatedSenderWithPaymentRequestIdMemo =
            AuthenticatedSenderWithPaymentRequestIdMemo::from(&memo_data);

        let is_memo_valid = authenticated_sender_with_payment_request_memo.validate(
            &sender_public_address,
            &receiving_subaddress_view_private_key,
            &tx_out_public_key_compressed,
        );

        *out_valid.into_mut() = bool::from(is_memo_valid);

        Ok(())
    })
}

/// # Preconditions
///
/// * `sender_account_key` - must be a valid account key
/// * `recipient_subaddress_view_public_key` - must be a valid 32-byte
///   Ristretto-format scalar.
/// * `tx_out_public_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `out_memo_data` - length must be >= 64.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_memo_sender_with_payment_request_memo_create(
    sender_account_key: FfiRefPtr<McAccountKey>,
    recipient_subaddress_view_public_key: FfiRefPtr<McBuffer>,
    tx_out_public_key: FfiRefPtr<McBuffer>,
    payment_request_id: u64,
    out_memo_data: FfiMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let sender_account_key =
            AccountKey::try_from_ffi(&sender_account_key).expect("account_key is invalid");
        let recipient_subaddress_view_public_key =
            RistrettoPublic::try_from_ffi(&recipient_subaddress_view_public_key)?;
        let tx_out_public_key = CompressedRistrettoPublic::try_from_ffi(&tx_out_public_key)?;

        let sender_cred = SenderMemoCredential::from(&sender_account_key);
        let memo = AuthenticatedSenderWithPaymentRequestIdMemo::new(
            &sender_cred,
            &recipient_subaddress_view_public_key,
            &tx_out_public_key,
            payment_request_id,
        );

        let memo_bytes: [u8; 64] = memo.into();

        let out_memo_data = out_memo_data
            .into_mut()
            .as_slice_mut_of_len(core::mem::size_of_val(&memo_bytes))
            .expect("out_memo_data length is insufficient");

        out_memo_data.copy_from_slice(&memo_bytes);

        Ok(())
    })
}

/// # Preconditions
///
/// * `sender_with_payment_request_memo_data` - must be 64 bytes
/// * `out_short_address_hash` - length must be >= 16 bytes
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_memo_sender_with_payment_request_memo_get_address_hash(
    sender_with_payment_request_memo_data: FfiRefPtr<McBuffer>,
    out_short_address_hash: FfiMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let memo_data = <[u8; 64]>::try_from_ffi(&sender_with_payment_request_memo_data)
            .expect("sender_with_payment_request_memo_data invalid length");

        let authenticated_sender_with_payment_request_memo: AuthenticatedSenderWithPaymentRequestIdMemo =
            AuthenticatedSenderWithPaymentRequestIdMemo::from(&memo_data);

        let short_address_hash: ShortAddressHash =
            authenticated_sender_with_payment_request_memo.sender_address_hash();

        let hash_data: [u8; 16] = short_address_hash.into();

        let out_short_address_hash = out_short_address_hash
            .into_mut()
            .as_slice_mut_of_len(core::mem::size_of_val(&hash_data))
            .expect("ShortAddressHash length is insufficient");

        out_short_address_hash.copy_from_slice(&hash_data);

        Ok(())
    })
}

/// # Preconditions
///
/// * `sender_with_payment_request_memo_data` - must be 64 bytes
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_memo_sender_with_payment_request_memo_get_payment_request_id(
    sender_with_payment_request_memo_data: FfiRefPtr<McBuffer>,
    out_payment_request_id: FfiMutPtr<u64>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let memo_data = <[u8; 64]>::try_from_ffi(&sender_with_payment_request_memo_data)
            .expect("sender_with_payment_request_memo_data invalid length");

        let sender_with_payment_request_memo: AuthenticatedSenderWithPaymentRequestIdMemo =
            AuthenticatedSenderWithPaymentRequestIdMemo::from(&memo_data);

        let payment_request_id: u64 = sender_with_payment_request_memo.payment_request_id();

        *out_payment_request_id.into_mut() = payment_request_id;

        Ok(())
    })
}

/********************************************************************
 * Decrypt Memo Payload
 */

/// # Preconditions
///
/// * `encrypted_memo` - must be 66 bytes
/// * `tx_out_public_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `account_key` - must be a valid account key
/// * `out_memo_payload` - length must be >= 16 bytes
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_memo_decrypt_e_memo_payload(
    encrypted_memo: FfiRefPtr<McBuffer>,
    tx_out_public_key: FfiRefPtr<McBuffer>,
    account_key: FfiRefPtr<McAccountKey>,
    out_memo_payload: FfiMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let tx_out_public_key = RistrettoPublic::try_from_ffi(&tx_out_public_key)?;
        let account_key_obj =
            AccountKey::try_from_ffi(&account_key).expect("account_key is invalid");
        let e_memo = EncryptedMemo::try_from_ffi(&encrypted_memo)?;
        let shared_secret =
            get_tx_out_shared_secret(&*account_key_obj.view_private_key(), &tx_out_public_key);

        let memo_payload: MemoPayload = e_memo.decrypt(&shared_secret);
        let memo_payload_generic_array: GenericArray<u8, U66> = memo_payload.into();

        let out_memo_payload = out_memo_payload
            .into_mut()
            .as_slice_mut_of_len(core::mem::size_of_val(&memo_payload_generic_array))
            .expect("Memo payload length is insufficient");

        out_memo_payload.copy_from_slice(&memo_payload_generic_array);
        Ok(())
    })
}

/********************************************************************
 * Trait Implementations
 */

impl<'a> TryFromFfi<&McBuffer<'a>> for CompressedCommitment {
    type Error = LibMcError;

    fn try_from_ffi(src: &McBuffer<'a>) -> Result<Self, LibMcError> {
        let src = <&[u8; 32]>::try_from_ffi(src)?;
        Ok(CompressedCommitment::from(src))
    }
}

impl<'a> TryFromFfi<&McBuffer<'a>> for TxOutConfirmationNumber {
    type Error = LibMcError;

    fn try_from_ffi(src: &McBuffer<'a>) -> Result<Self, LibMcError> {
        let confirmation_number = <&[u8; 32]>::try_from_ffi(src)?;
        Ok(TxOutConfirmationNumber::from(confirmation_number))
    }
}

/* ==== Ristretto ==== */

impl<'a> TryFromFfi<&McBuffer<'a>> for CompressedRistrettoPublic {
    type Error = LibMcError;

    fn try_from_ffi(src: &McBuffer<'a>) -> Result<Self, LibMcError> {
        let src = <&[u8; 32]>::try_from_ffi(src)?;
        CompressedRistrettoPublic::try_from(src)
            .map_err(|err| LibMcError::InvalidInput(format!("{:?}", err)))
    }
}

/* ==== EncryptedMemo ==== */

impl<'a> TryFromFfi<&McBuffer<'a>> for EncryptedMemo {
    type Error = LibMcError;

    fn try_from_ffi(src: &McBuffer<'a>) -> Result<Self, LibMcError> {
        let src = <&[u8; 66]>::try_from_ffi(src)?;
        let memo_payload_generic_array: GenericArray<u8, U66> = GenericArray::clone_from_slice(src);
        EncryptedMemo::try_from(memo_payload_generic_array)
            .map_err(|err| LibMcError::InvalidInput(format!("{:?}", err)))
    }
}
