// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::{
    common::*,
    fog::McFogResolver,
    keys::{McPublicAddress, McAccountKey},
    LibMcError, 
};
use hex;
use core::convert::TryFrom;
use crc::Crc;
use mc_account_keys::{PublicAddress, AccountKey, ShortAddressHash};
use mc_crypto_keys::{ReprBytes, RistrettoPrivate, RistrettoPublic, CompressedRistrettoPublic};
use mc_fog_report_validation::FogResolver;
use mc_transaction_core::{
    get_tx_out_shared_secret, get_value_mask,
    onetime_keys::{recover_onetime_private_key, recover_public_subaddress_spend_key},
    ring_signature::KeyImage,
    tx::{TxOut, TxOutConfirmationNumber, TxOutMembershipProof},
    Amount, BlockVersion, CompressedCommitment,
};
use std::convert::TryInto;

//use mc_transaction_std::{
    //AuthenticatedSenderMemo, AuthenticatedSenderWithPaymentRequestIdMemo, ChangeDestination,
    //DestinationMemo, InputCredentials, MemoBuilder, MemoPayload, RTHMemoBuilder,
    //SenderMemoCredential, TransactionBuilder,
//};

use mc_transaction_std::{
    InputCredentials,
    RTHMemoBuilder,
    TransactionBuilder,
    MemoBuilder,
    SenderMemoCredential,
    AuthenticatedSenderMemo,
    DestinationMemo,
    ChangeDestination
};
//use mc_transaction_std::{InputCredentials, NoMemoBuilder, TransactionBuilder, ChangeDestination};
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
        let value = (tx_out_amount.masked_value as u64) ^ get_value_mask(&shared_secret);

        let amount: Amount = Amount::new(value, &shared_secret)?;

        let out_tx_out_commitment = out_tx_out_commitment
            .into_mut()
            .as_slice_mut_of_len(RistrettoPublic::size())
            .expect("out_tx_out_commitment length is insufficient");

        out_tx_out_commitment.copy_from_slice(&amount.commitment.to_bytes());
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
    tx_out_amount: FfiRefPtr<McTxOutAmount>,
    tx_out_public_key: FfiRefPtr<McBuffer>,
    view_private_key: FfiRefPtr<McBuffer>,
    out_matches: FfiMutPtr<bool>,
) -> bool {
    ffi_boundary(|| {
        let view_private_key = RistrettoPrivate::try_from_ffi(&view_private_key)
            .expect("view_private_key is not a valid RistrettoPrivate");

        let mut matches = false;
        if let Ok(public_key) = RistrettoPublic::try_from_ffi(&tx_out_public_key) {
            let shared_secret = get_tx_out_shared_secret(&view_private_key, &public_key);
            let value = (tx_out_amount.masked_value as u64) ^ get_value_mask(&shared_secret);
            let amount: Amount =
                Amount::new(value, &shared_secret).expect("could not create amount object");
            matches = amount.get_value(&shared_secret).is_ok()
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
        let value = (tx_out_amount.masked_value as u64) ^ get_value_mask(&shared_secret);
        let amount: Amount = Amount::new(value, &shared_secret)?;
        let (val, _blinding) = amount.get_value(&shared_secret)?;

        *out_value.into_mut() = val;
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

        let mut transaction_builder =
            TransactionBuilder::new_with_box(block_version, fog_resolver, memo_builder_box);

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

        let (tx_out, confirmation) =
            transaction_builder.add_output(amount, &recipient_address, &mut rng)?;

        out_tx_out_confirmation_number.copy_from_slice(confirmation.as_ref());
        Ok(mc_util_serial::encode(&tx_out))
    })
}

/// # Preconditions
///
/// * `account_kay` - must be a valid account key, default change address computed from account key
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
        let account_key_obj = AccountKey::try_from_ffi(&account_key).expect("account_key is invalid");
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
pub extern "C" fn mc_memo_builder_default_create(
    ) -> FfiOptOwnedPtr<McTxOutMemoBuilder> {
    ffi_boundary(|| {
        let memo_builder_box: Box<dyn MemoBuilder + Sync + Send> =
            Box::new(RTHMemoBuilder::default());
        Some(memo_builder_box)
    })
}

#[no_mangle]
pub extern "C" fn mc_memo_builder_free(
    memo_builder: FfiOptOwnedPtr<McTxOutMemoBuilder>,
) {
    ffi_boundary(|| {
        let _ = memo_builder;
    })
}

/* ==== SenderMemo ==== */

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
        let alice_bytes : [u8; 657]= hex::decode(&"0a220a20ec8cb9814ac5c1a4aacbc613e756744679050927cc9e5f8772c6d649d4a5ac0612220a20e7ef0b2772663314ecd7ee92008613764ab5669666d95bd2621d99d60506cb0d1a1e666f673a2f2f666f672e616c7068612e6d6f62696c65636f696e2e636f6d2aa60430820222300d06092a864886f70d01010105000382020f003082020a0282020100c853a8724bc211cf5370ed4dbec8947c5573bed0ec47ae14211454977b41336061f0a040f77dbf529f3a46d8095676ec971b940ab4c9642578760779840a3f9b3b893b2f65006c544e9c16586d33649769b7c1c94552d7efa081a56ad612dec932812676ebec091f2aed69123604f4888a125e04ff85f5a727c286664378581cf34c7ee13eb01cc4faf3308ed3c07a9415f98e5fbfe073e6c357967244e46ba6ebbe391d8154e6e4a1c80524b1a6733eca46e37bfdd62d75816988a79aac6bdb62a06b1237a8ff5e5c848d01bbff684248cf06d92f301623c893eb0fba0f3faee2d197ea57ac428f89d6c000f76d58d5aacc3d70204781aca45bc02b1456b454231d2f2ed4ca6614e5242c7d7af0fe61e9af6ecfa76674ffbc29b858091cbfb4011538f0e894ce45d21d7fac04ba2ff57e9ff6db21e2afd9468ad785c262ec59d4a1a801c5ec2f95fc107dc9cb5f7869d70aa84450b8c350c2fa48bddef20752a1e43676b246c7f59f8f1f4aee43c1a15f36f7a36a9ec708320ea42089991551f2656ec62ea38233946b85616ff182cf17cd227e596329b546ea04d13b053be4cf3338de777b50bc6eca7a6185cf7a5022bc9be3749b1bb43e10ecc88a0c580f2b7373138ee49c7bafd8be6a64048887230480b0c85a045255494e04a9a81646369ce7a10e08da6fae27333ec0c16c8a74d93779a9e055395078d0b07286f9930203010001").unwrap().try_into().unwrap();
        let alice: AccountKey = mc_util_serial::decode(&alice_bytes).unwrap();

        let bob_bytes : [u8; 657]= hex::decode(&"0a220a20553a1c51c1e91d3105b17c909c163f8bc6faf93718deb06e5b9fdb9a24c2560912220a20db8b25545216d606fc3ff6da43d3281e862ba254193aff8c408f3564aefca5061a1e666f673a2f2f666f672e616c7068612e6d6f62696c65636f696e2e636f6d2aa60430820222300d06092a864886f70d01010105000382020f003082020a0282020100c853a8724bc211cf5370ed4dbec8947c5573bed0ec47ae14211454977b41336061f0a040f77dbf529f3a46d8095676ec971b940ab4c9642578760779840a3f9b3b893b2f65006c544e9c16586d33649769b7c1c94552d7efa081a56ad612dec932812676ebec091f2aed69123604f4888a125e04ff85f5a727c286664378581cf34c7ee13eb01cc4faf3308ed3c07a9415f98e5fbfe073e6c357967244e46ba6ebbe391d8154e6e4a1c80524b1a6733eca46e37bfdd62d75816988a79aac6bdb62a06b1237a8ff5e5c848d01bbff684248cf06d92f301623c893eb0fba0f3faee2d197ea57ac428f89d6c000f76d58d5aacc3d70204781aca45bc02b1456b454231d2f2ed4ca6614e5242c7d7af0fe61e9af6ecfa76674ffbc29b858091cbfb4011538f0e894ce45d21d7fac04ba2ff57e9ff6db21e2afd9468ad785c262ec59d4a1a801c5ec2f95fc107dc9cb5f7869d70aa84450b8c350c2fa48bddef20752a1e43676b246c7f59f8f1f4aee43c1a15f36f7a36a9ec708320ea42089991551f2656ec62ea38233946b85616ff182cf17cd227e596329b546ea04d13b053be4cf3338de777b50bc6eca7a6185cf7a5022bc9be3749b1bb43e10ecc88a0c580f2b7373138ee49c7bafd8be6a64048887230480b0c85a045255494e04a9a81646369ce7a10e08da6fae27333ec0c16c8a74d93779a9e055395078d0b07286f9930203010001").unwrap().try_into().unwrap();
        let bob: AccountKey = mc_util_serial::decode(&bob_bytes).unwrap();

        let tx_public_key_bytes: [u8; 32] =
            hex::decode(&"c235c13c4dedd808e95f428036716d52561fad7f51ce675f4d4c9c1fa1ea2165")
                .unwrap()
                .try_into()
                .unwrap();
        let tx_public_key = CompressedRistrettoPublic::from(&tx_public_key_bytes);

        let alice_cred = SenderMemoCredential::from(&alice);
        let memo = AuthenticatedSenderMemo::new(
            &alice_cred,
            bob.default_subaddress().view_public_key(),
            &tx_public_key,
        );
        let _memo_bytes: [u8; 64] = memo.clone().into();

        let _result = memo.validate(
            &alice.default_subaddress(),
            &bob.default_subaddress_view_private(),
            &tx_public_key,
        );




        let sender_public_address =
            PublicAddress::try_from_ffi(&sender_public_address)
                .expect("sender_public_address is invalid");

        let receiving_subaddress_view_private_key = 
            RistrettoPrivate::try_from_ffi(&receiving_subaddress_view_private_key)
                .expect("receiving_subaddress_view_private_key is not a valid RistrettoPrivate");

        let tx_out_public_key_compressed =
            CompressedRistrettoPublic::try_from_ffi(&tx_out_public_key)
                .expect("tx_out_public_key is not a valid RistrettoPublic");

        let memo_data = <[u8; 64]>::try_from_ffi(&sender_memo_data)
                .expect("sender_memo_data invalid length");

        let authenticated_sender_memo: AuthenticatedSenderMemo =
            AuthenticatedSenderMemo::from(&memo_data);

        let _authenticated_sender_memo_bytes: [u8; 64] = authenticated_sender_memo.clone().into();

        let is_memo_valid = authenticated_sender_memo
            .validate(
                &sender_public_address,
                &receiving_subaddress_view_private_key,
                &tx_out_public_key_compressed,
            );

        *out_valid.into_mut() = bool::from(is_memo_valid);

        //let _memo_bytes: [u8; 64] = authenticated_sender_memo.clone().into();
        //let a = format!("Memo payload:  is: {}", hex::encode(memo_bytes));
        //let b = format!("Result is {}", is_memo_valid.unwrap_u8());
        let c = format!("Result is {}", hex::encode(mc_util_serial::encode(&receiving_subaddress_view_private_key)));
        let d = format!("Result is {}", hex::encode(mc_util_serial::encode(&bob.default_subaddress_view_private())));
        let message = format!("message {} {}", c, d);

        if bool::from(is_memo_valid) {
            Ok(())
        } else {
            return Err(LibMcError::TransactionCrypto(
                message.to_owned(),
            ));
            //return Err(LibMcError::TransactionCrypto(
                //"derp".to_owned(),
            //));
        }
    })
}

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

        let memo_bytes: [u8; 64] = memo.clone().into();

        let out_memo_data = out_memo_data
            .into_mut()
            .as_slice_mut_of_len(core::mem::size_of_val(&memo_bytes))
            .expect("out_memo_data length is insufficient");

        out_memo_data.copy_from_slice(&memo_bytes);
        Ok(())
    })
}


#[no_mangle]
pub extern "C" fn mc_memo_sender_memo_get_address_hash(
    sender_memo_data: FfiRefPtr<McBuffer>,
    out_short_address_hash: FfiMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let memo_data = <[u8; 64]>::try_from_ffi(&sender_memo_data)
                .expect("sender_memo_data invalid length");

        let authenticated_sender_memo: AuthenticatedSenderMemo =
            AuthenticatedSenderMemo::from(&memo_data);

        let short_address_hash: ShortAddressHash =
            authenticated_sender_memo.sender_address_hash();

        let hash_data: [u8; 16] = short_address_hash.into();

        let out_short_address_hash = out_short_address_hash
            .into_mut()
            .as_slice_mut_of_len(core::mem::size_of_val(&hash_data))
            .expect("ShortAddressHash length is insufficient");

        out_short_address_hash.copy_from_slice(&hash_data);

        //let _memo_bytes: [u8; 64] = authenticated_sender_memo.clone().into();
        //let a = format!("Memo payload:  is: {}", hex::encode(memo_bytes));
        //let b = format!("Result is {}", is_memo_valid.unwrap_u8());
        //let c = format!("Result is {}", hex::encode(mc_util_serial::encode(&receiving_subaddress_view_private_key)));
        //let d = format!("Result is {}", hex::encode(mc_util_serial::encode(&bob.default_subaddress_view_private())));
        //let message = format!("message {} {}", c, d);

        //if bool::from(is_memo_valid) {
            //Ok(())
        //} else {
            //return Err(LibMcError::TransactionCrypto(
                //message.to_owned(),
            //));
            ////return Err(LibMcError::TransactionCrypto(
                ////"derp".to_owned(),
            ////));
        //}

        Ok(())
    })
}

/* ==== DestinationMemo ==== */

//#[no_mangle]
//pub extern "C" fn mc_memo_sender_memo_is_valid(
    //sender_memo_data: FfiRefPtr<McBuffer>,
    //sender_public_address: FfiRefPtr<McPublicAddress>,
    //receiving_subaddress_view_private_key: FfiRefPtr<McBuffer>,
    //tx_out_public_key: FfiRefPtr<McBuffer>,
    //out_valid: FfiMutPtr<bool>,
    //out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
//) -> bool {
    //ffi_boundary_with_error(out_error, || {
        //let alice_bytes : [u8; 657]= hex::decode(&"0a220a20ec8cb9814ac5c1a4aacbc613e756744679050927cc9e5f8772c6d649d4a5ac0612220a20e7ef0b2772663314ecd7ee92008613764ab5669666d95bd2621d99d60506cb0d1a1e666f673a2f2f666f672e616c7068612e6d6f62696c65636f696e2e636f6d2aa60430820222300d06092a864886f70d01010105000382020f003082020a0282020100c853a8724bc211cf5370ed4dbec8947c5573bed0ec47ae14211454977b41336061f0a040f77dbf529f3a46d8095676ec971b940ab4c9642578760779840a3f9b3b893b2f65006c544e9c16586d33649769b7c1c94552d7efa081a56ad612dec932812676ebec091f2aed69123604f4888a125e04ff85f5a727c286664378581cf34c7ee13eb01cc4faf3308ed3c07a9415f98e5fbfe073e6c357967244e46ba6ebbe391d8154e6e4a1c80524b1a6733eca46e37bfdd62d75816988a79aac6bdb62a06b1237a8ff5e5c848d01bbff684248cf06d92f301623c893eb0fba0f3faee2d197ea57ac428f89d6c000f76d58d5aacc3d70204781aca45bc02b1456b454231d2f2ed4ca6614e5242c7d7af0fe61e9af6ecfa76674ffbc29b858091cbfb4011538f0e894ce45d21d7fac04ba2ff57e9ff6db21e2afd9468ad785c262ec59d4a1a801c5ec2f95fc107dc9cb5f7869d70aa84450b8c350c2fa48bddef20752a1e43676b246c7f59f8f1f4aee43c1a15f36f7a36a9ec708320ea42089991551f2656ec62ea38233946b85616ff182cf17cd227e596329b546ea04d13b053be4cf3338de777b50bc6eca7a6185cf7a5022bc9be3749b1bb43e10ecc88a0c580f2b7373138ee49c7bafd8be6a64048887230480b0c85a045255494e04a9a81646369ce7a10e08da6fae27333ec0c16c8a74d93779a9e055395078d0b07286f9930203010001").unwrap().try_into().unwrap();
        //let alice: AccountKey = mc_util_serial::decode(&alice_bytes).unwrap();

        //let bob_bytes : [u8; 657]= hex::decode(&"0a220a20553a1c51c1e91d3105b17c909c163f8bc6faf93718deb06e5b9fdb9a24c2560912220a20db8b25545216d606fc3ff6da43d3281e862ba254193aff8c408f3564aefca5061a1e666f673a2f2f666f672e616c7068612e6d6f62696c65636f696e2e636f6d2aa60430820222300d06092a864886f70d01010105000382020f003082020a0282020100c853a8724bc211cf5370ed4dbec8947c5573bed0ec47ae14211454977b41336061f0a040f77dbf529f3a46d8095676ec971b940ab4c9642578760779840a3f9b3b893b2f65006c544e9c16586d33649769b7c1c94552d7efa081a56ad612dec932812676ebec091f2aed69123604f4888a125e04ff85f5a727c286664378581cf34c7ee13eb01cc4faf3308ed3c07a9415f98e5fbfe073e6c357967244e46ba6ebbe391d8154e6e4a1c80524b1a6733eca46e37bfdd62d75816988a79aac6bdb62a06b1237a8ff5e5c848d01bbff684248cf06d92f301623c893eb0fba0f3faee2d197ea57ac428f89d6c000f76d58d5aacc3d70204781aca45bc02b1456b454231d2f2ed4ca6614e5242c7d7af0fe61e9af6ecfa76674ffbc29b858091cbfb4011538f0e894ce45d21d7fac04ba2ff57e9ff6db21e2afd9468ad785c262ec59d4a1a801c5ec2f95fc107dc9cb5f7869d70aa84450b8c350c2fa48bddef20752a1e43676b246c7f59f8f1f4aee43c1a15f36f7a36a9ec708320ea42089991551f2656ec62ea38233946b85616ff182cf17cd227e596329b546ea04d13b053be4cf3338de777b50bc6eca7a6185cf7a5022bc9be3749b1bb43e10ecc88a0c580f2b7373138ee49c7bafd8be6a64048887230480b0c85a045255494e04a9a81646369ce7a10e08da6fae27333ec0c16c8a74d93779a9e055395078d0b07286f9930203010001").unwrap().try_into().unwrap();
        //let bob: AccountKey = mc_util_serial::decode(&bob_bytes).unwrap();

        //let tx_public_key_bytes: [u8; 32] =
            //hex::decode(&"c235c13c4dedd808e95f428036716d52561fad7f51ce675f4d4c9c1fa1ea2165")
                //.unwrap()
                //.try_into()
                //.unwrap();
        //let tx_public_key = CompressedRistrettoPublic::from(&tx_public_key_bytes);

        //let alice_cred = SenderMemoCredential::from(&alice);
        //let memo = AuthenticatedSenderMemo::new(
            //&alice_cred,
            //bob.default_subaddress().view_public_key(),
            //&tx_public_key,
        //);
        //let _memo_bytes: [u8; 64] = memo.clone().into();

        //let _result = memo.validate(
            //&alice.default_subaddress(),
            //&bob.default_subaddress_view_private(),
            //&tx_public_key,
        //);




        //let sender_public_address =
            //PublicAddress::try_from_ffi(&sender_public_address)
                //.expect("sender_public_address is invalid");

        //let receiving_subaddress_view_private_key = 
            //RistrettoPrivate::try_from_ffi(&receiving_subaddress_view_private_key)
                //.expect("receiving_subaddress_view_private_key is not a valid RistrettoPrivate");

        //let tx_out_public_key_compressed =
            //CompressedRistrettoPublic::try_from_ffi(&tx_out_public_key)
                //.expect("tx_out_public_key is not a valid RistrettoPublic");

        //let memo_data = <[u8; 64]>::try_from_ffi(&sender_memo_data)
                //.expect("sender_memo_data invalid length");

        //let authenticated_sender_memo: AuthenticatedSenderMemo =
            //AuthenticatedSenderMemo::from(&memo_data);

        //let _authenticated_sender_memo_bytes: [u8; 64] = authenticated_sender_memo.clone().into();

        //let is_memo_valid = authenticated_sender_memo
            //.validate(
                //&sender_public_address,
                //&receiving_subaddress_view_private_key,
                //&tx_out_public_key_compressed,
            //);

        //*out_valid.into_mut() = bool::from(is_memo_valid);

        ////let _memo_bytes: [u8; 64] = authenticated_sender_memo.clone().into();
        ////let a = format!("Memo payload:  is: {}", hex::encode(memo_bytes));
        ////let b = format!("Result is {}", is_memo_valid.unwrap_u8());
        //let c = format!("Result is {}", hex::encode(mc_util_serial::encode(&receiving_subaddress_view_private_key)));
        //let d = format!("Result is {}", hex::encode(mc_util_serial::encode(&bob.default_subaddress_view_private())));
        //let message = format!("message {} {}", c, d);

        //if bool::from(is_memo_valid) {
            //Ok(())
        //} else {
            //return Err(LibMcError::TransactionCrypto(
                //message.to_owned(),
            //));
            ////return Err(LibMcError::TransactionCrypto(
                ////"derp".to_owned(),
            ////));
        //}
    //})
//}

//#[no_mangle]
//pub extern "C" fn mc_memo_sender_memo_create(
  //sender_account_key: FfiRefPtr<McAccountKey>,
  //recipient_subaddress_view_public_key: FfiRefPtr<McBuffer>,
  //tx_out_public_key: FfiRefPtr<McBuffer>,
  //out_memo_data: FfiMutPtr<McMutableBuffer>,
  //out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
//) -> bool {
    //ffi_boundary_with_error(out_error, || {
        //let sender_account_key = 
            //AccountKey::try_from_ffi(&sender_account_key).expect("account_key is invalid");
        //let recipient_subaddress_view_public_key = 
            //RistrettoPublic::try_from_ffi(&recipient_subaddress_view_public_key)?;
        //let tx_out_public_key = CompressedRistrettoPublic::try_from_ffi(&tx_out_public_key)?;

        //let sender_cred = SenderMemoCredential::from(&sender_account_key);
        //let memo = AuthenticatedSenderMemo::new(
            //&sender_cred,
            //&recipient_subaddress_view_public_key,
            //&tx_out_public_key,
        //);

        //let memo_bytes: [u8; 64] = memo.clone().into();

        //let out_memo_data = out_memo_data
            //.into_mut()
            //.as_slice_mut_of_len(core::mem::size_of_val(&memo_bytes))
            //.expect("out_memo_data length is insufficient");

        //out_memo_data.copy_from_slice(&memo_bytes);
        //Ok(())
    //})
//}


//#[no_mangle]
//pub extern "C" fn mc_memo_sender_memo_get_address_hash(
    //sender_memo_data: FfiRefPtr<McBuffer>,
    //out_short_address_hash: FfiMutPtr<McMutableBuffer>,
    //out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
//) -> bool {
    //ffi_boundary_with_error(out_error, || {
        //let memo_data = <[u8; 64]>::try_from_ffi(&sender_memo_data)
                //.expect("sender_memo_data invalid length");

        //let authenticated_sender_memo: AuthenticatedSenderMemo =
            //AuthenticatedSenderMemo::from(&memo_data);

        //let short_address_hash: ShortAddressHash =
            //authenticated_sender_memo.sender_address_hash();

        //let hash_data: [u8; 16] = short_address_hash.into();

        //let out_short_address_hash = out_short_address_hash
            //.into_mut()
            //.as_slice_mut_of_len(core::mem::size_of_val(&hash_data))
            //.expect("ShortAddressHash length is insufficient");

        //out_short_address_hash.copy_from_slice(&hash_data);

        ////let _memo_bytes: [u8; 64] = authenticated_sender_memo.clone().into();
        ////let a = format!("Memo payload:  is: {}", hex::encode(memo_bytes));
        ////let b = format!("Result is {}", is_memo_valid.unwrap_u8());
        ////let c = format!("Result is {}", hex::encode(mc_util_serial::encode(&receiving_subaddress_view_private_key)));
        ////let d = format!("Result is {}", hex::encode(mc_util_serial::encode(&bob.default_subaddress_view_private())));
        ////let message = format!("message {} {}", c, d);

        ////if bool::from(is_memo_valid) {
            ////Ok(())
        ////} else {
            ////return Err(LibMcError::TransactionCrypto(
                ////message.to_owned(),
            ////));
            //////return Err(LibMcError::TransactionCrypto(
                //////"derp".to_owned(),
            //////));
        ////}

        //Ok(())
    //})
//}




















/********************************************************************
 * DestinationMemo
 */

#[no_mangle]
pub extern "C" fn mc_memo_destination_memo_create(
  destination_public_address: FfiRefPtr<McPublicAddress>,
  _number_of_recipients: FfiRefPtr<u8>,
  _fee: FfiRefPtr<u64>,
  _total_outlay: FfiRefPtr<u64>,
  out_memo_data: FfiMutPtr<McMutableBuffer>,
  out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let destination_public_address =
            PublicAddress::try_from_ffi(&destination_public_address).expect("destination_public_address is invalid");

        let memo =
            DestinationMemo::new(ShortAddressHash::from(&destination_public_address), total_outlay, fee).unwrap();

        let memo_bytes: [u8; 64] = memo.clone().into();

        let out_memo_data = out_memo_data
            .into_mut()
            .as_slice_mut_of_len(core::mem::size_of_val(&memo_bytes))
            .expect("out_memo_data length is insufficient");

        out_memo_data.copy_from_slice(&memo_bytes);
        Ok(())
    })
}


#[no_mangle]
pub extern "C" fn mc_memo_destination_memo_get_address_hash(
    destination_memo_data: FfiRefPtr<McBuffer>,
    out_short_address_hash: FfiMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let memo_data = <[u8; 64]>::try_from_ffi(&destination_memo_data)
                .expect("destination_memo_data invalid length");

        let destination_memo: DestinationMemo =
            DestinationMemo::from(&memo_data);

        let short_address_hash: &ShortAddressHash =
            destination_memo.get_address_hash();

        let hash_data: [u8; 16] = <[u8; 16]>::from(short_address_hash.clone());

        let out_short_address_hash = out_short_address_hash
            .into_mut()
            .as_slice_mut_of_len(core::mem::size_of_val(&hash_data))
            .expect("ShortAddressHash length is insufficient");

        out_short_address_hash.copy_from_slice(&hash_data);

        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn mc_memo_destination_memo_get_number_of_recipients(
    destination_memo_data: FfiRefPtr<McBuffer>,
    out_number_of_recipients: FfiMutPtr<u8>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let memo_data = <[u8; 64]>::try_from_ffi(&destination_memo_data)
                .expect("destination_memo_data invalid length");

        let destination_memo: DestinationMemo =
            DestinationMemo::from(&memo_data);

        let number_of_recipients: u8 =
            destination_memo.get_num_recipients().clone();

        *out_number_of_recipients.into_mut() = number_of_recipients;

        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn mc_memo_destination_memo_get_fee(
    destination_memo_data: FfiRefPtr<McBuffer>,
    out_fee: FfiMutPtr<u64>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let memo_data = <[u8; 64]>::try_from_ffi(&destination_memo_data)
                .expect("destination_memo_data invalid length");

        let destination_memo: DestinationMemo =
            DestinationMemo::from(&memo_data);

        let fee: u64 =
            destination_memo.get_fee().clone();

        *out_fee.into_mut() = fee;

        Ok(())
    })
}

//#[no_mangle]
//pub unsafe extern "C" fn Java_com_mobilecoin_lib_DestinationMemo_get_1fee(
    //env: JNIEnv,
    //obj: JObject,
//) -> jlong {
    //jni_ffi_call_or(
        //|| Ok(0),
        //&env,
        //|env| {
            //let destination_memo: MutexGuard<DestinationMemo> =
                //env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            //Ok(destination_memo.get_fee() as jlong)
        //},
    //)
//}

#[no_mangle]
pub extern "C" fn mc_memo_destination_memo_get_total_outlay(
    destination_memo_data: FfiRefPtr<McBuffer>,
    out_total_outlay: FfiMutPtr<u64>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let memo_data = <[u8; 64]>::try_from_ffi(&destination_memo_data)
                .expect("destination_memo_data invalid length");

        let destination_memo: DestinationMemo =
            DestinationMemo::from(&memo_data);

        let total_outlay: u64 =
            destination_memo.get_total_outlay();

        *out_total_outlay.into_mut() = total_outlay;

        Ok(())
    })
}

//#[no_mangle]
//pub unsafe extern "C" fn Java_com_mobilecoin_lib_DestinationMemo_get_1total_1outlay(
    //env: JNIEnv,
    //obj: JObject,
//) -> jlong {
    //jni_ffi_call_or(
        //|| Ok(0),
        //&env,
        //|env| {
            //let destination_memo: MutexGuard<DestinationMemo> =
                //env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            //Ok(destination_memo.get_total_outlay() as jlong)
        //},
    //)
//}


//#[no_mangle]
//pub unsafe extern "C" fn Java_com_mobilecoin_lib_DestinationMemo_get_1number_1of_1recipients(
    //env: JNIEnv,
    //obj: JObject,
//) -> jshort {
    //jni_ffi_call_or(
        //|| Ok(0),
        //&env,
        //|env| {
            //let destination_memo: MutexGuard<DestinationMemo> =
                //env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            //// number_of_recipients is a u8 and jshort is an i16. This is fine
            //// because number_of_recipients will never be negative.
            //Ok(destination_memo.get_num_recipients() as jshort)
        //},
    //)
//}

// use mc_tx_out_matches_any_subaddress(...) to test validity of a destination_memo
// if the TxOut is owned by a subaddress of the user's account key, it is valid.
//
//
//#[no_mangle]
//pub extern "C" fn mc_memo_destination_memo_is_valid(
    //sender_memo_data: FfiRefPtr<McBuffer>,
    //sender_public_address: FfiRefPtr<McPublicAddress>,
    //receiving_subaddress_view_private_key: FfiRefPtr<McBuffer>,
    //tx_out_public_key: FfiRefPtr<McBuffer>,
    //out_valid: FfiMutPtr<bool>,
    //out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
//) -> bool {
    //ffi_boundary_with_error(out_error, || {
        //let alice_bytes : [u8; 657]= hex::decode(&"0a220a20ec8cb9814ac5c1a4aacbc613e756744679050927cc9e5f8772c6d649d4a5ac0612220a20e7ef0b2772663314ecd7ee92008613764ab5669666d95bd2621d99d60506cb0d1a1e666f673a2f2f666f672e616c7068612e6d6f62696c65636f696e2e636f6d2aa60430820222300d06092a864886f70d01010105000382020f003082020a0282020100c853a8724bc211cf5370ed4dbec8947c5573bed0ec47ae14211454977b41336061f0a040f77dbf529f3a46d8095676ec971b940ab4c9642578760779840a3f9b3b893b2f65006c544e9c16586d33649769b7c1c94552d7efa081a56ad612dec932812676ebec091f2aed69123604f4888a125e04ff85f5a727c286664378581cf34c7ee13eb01cc4faf3308ed3c07a9415f98e5fbfe073e6c357967244e46ba6ebbe391d8154e6e4a1c80524b1a6733eca46e37bfdd62d75816988a79aac6bdb62a06b1237a8ff5e5c848d01bbff684248cf06d92f301623c893eb0fba0f3faee2d197ea57ac428f89d6c000f76d58d5aacc3d70204781aca45bc02b1456b454231d2f2ed4ca6614e5242c7d7af0fe61e9af6ecfa76674ffbc29b858091cbfb4011538f0e894ce45d21d7fac04ba2ff57e9ff6db21e2afd9468ad785c262ec59d4a1a801c5ec2f95fc107dc9cb5f7869d70aa84450b8c350c2fa48bddef20752a1e43676b246c7f59f8f1f4aee43c1a15f36f7a36a9ec708320ea42089991551f2656ec62ea38233946b85616ff182cf17cd227e596329b546ea04d13b053be4cf3338de777b50bc6eca7a6185cf7a5022bc9be3749b1bb43e10ecc88a0c580f2b7373138ee49c7bafd8be6a64048887230480b0c85a045255494e04a9a81646369ce7a10e08da6fae27333ec0c16c8a74d93779a9e055395078d0b07286f9930203010001").unwrap().try_into().unwrap();
        //let alice: AccountKey = mc_util_serial::decode(&alice_bytes).unwrap();

        //let alice_addr = alice.default_subaddress();

        //let mut memo =
            //DestinationMemo::new(ShortAddressHash::from(&alice_addr), 100, 4).unwrap();

        ////assert_eq!(
            ////memo.get_address_hash(),
            ////&ShortAddressHash::from(&alice_addr)
        ////);
        ////assert_eq!(memo.get_total_outlay(), 100);
        ////assert_eq!(memo.get_fee(), 4);
        ////assert_eq!(memo.get_num_recipients(), 1);

        //let _memo_bytes: [u8; 64] = memo.clone().into();

        //let _result = memo.validate(
            //&alice.default_subaddress(),
            //&bob.default_subaddress_view_private(),
            //&tx_public_key,
        //);



        //let sender_public_address =
            //PublicAddress::try_from_ffi(&sender_public_address)
                //.expect("sender_public_address is invalid");

        //let receiving_subaddress_view_private_key = 
            //RistrettoPrivate::try_from_ffi(&receiving_subaddress_view_private_key)
                //.expect("receiving_subaddress_view_private_key is not a valid RistrettoPrivate");

        //let tx_out_public_key_compressed =
            //CompressedRistrettoPublic::try_from_ffi(&tx_out_public_key)
                //.expect("tx_out_public_key is not a valid RistrettoPublic");

        //let memo_data = <[u8; 64]>::try_from_ffi(&sender_memo_data)
                //.expect("sender_memo_data invalid length");

        //let authenticated_sender_memo: AuthenticatedSenderMemo =
            //AuthenticatedSenderMemo::from(&memo_data);

        //let _authenticated_sender_memo_bytes: [u8; 64] = authenticated_sender_memo.clone().into();

        //let is_memo_valid = authenticated_sender_memo
            //.validate(
                //&sender_public_address,
                //&receiving_subaddress_view_private_key,
                //&tx_out_public_key_compressed,
            //);

        //*out_valid.into_mut() = bool::from(is_memo_valid);

        ////let _memo_bytes: [u8; 64] = authenticated_sender_memo.clone().into();
        ////let a = format!("Memo payload:  is: {}", hex::encode(memo_bytes));
        ////let b = format!("Result is {}", is_memo_valid.unwrap_u8());
        //let c = format!("Result is {}", hex::encode(mc_util_serial::encode(&receiving_subaddress_view_private_key)));
        //let d = format!("Result is {}", hex::encode(mc_util_serial::encode(&bob.default_subaddress_view_private())));
        //let message = format!("message {} {}", c, d);

        //if bool::from(is_memo_valid) {
            //Ok(())
        //} else {
            //return Err(LibMcError::TransactionCrypto(
                //message.to_owned(),
            //));
            ////return Err(LibMcError::TransactionCrypto(
                ////"derp".to_owned(),
            ////));
        //}
    //})
//}

//#[no_mangle]
//pub unsafe extern "C" fn Java_com_mobilecoin_lib_DestinationMemo_is_1valid(
    //env: JNIEnv,
    //_obj: JObject,
    //account_key: JObject,
    //tx_out: JObject,
//) -> jboolean {
    //jni_ffi_call_or(
        //|| Ok(JNI_FALSE),
        //&env,
        //|env| {
            //let account_key: MutexGuard<AccountKey> =
                //env.get_rust_field(account_key, RUST_OBJ_FIELD)?;
            //let tx_out: MutexGuard<TxOut> = env.get_rust_field(tx_out, RUST_OBJ_FIELD)?;

            //Ok(mc_transaction_core::subaddress_matches_tx_out(
                //&*account_key,
                //CHANGE_SUBADDRESS_INDEX,
                //&*tx_out,
            //)? as u8)
        //},
    //)
//}


//#[no_mangle]
//pub unsafe extern "C" fn Java_com_mobilecoin_lib_DestinationMemo_get_1address_1hash_1data(
    //env: JNIEnv,
    //obj: JObject,
//) -> jbyteArray {
    //jni_ffi_call_or(
        //|| Ok(JObject::null().into_inner()),
        //&env,
        //|env| {
            //let destination_memo: MutexGuard<DestinationMemo> =
                //env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            //let short_address_hash: &ShortAddressHash = destination_memo.get_address_hash();
            //let hash_data: [u8; 16] = <[u8; 16]>::from(short_address_hash.clone());
            //Ok(env.byte_array_from_slice(&hash_data)?)
        //},
    //)
//}


//#[no_mangle]
//pub unsafe extern "C" fn Java_com_mobilecoin_lib_DestinationMemo_init_1jni_1from_1memo_1data(
    //env: JNIEnv,
    //obj: JObject,
    //memo_data: jbyteArray,
//) {
    //jni_ffi_call(&env, |env| {
        //let memo_data = <[u8; 64]>::try_from(&env.convert_byte_array(memo_data)?[..])?;
        //let destination_memo: DestinationMemo = DestinationMemo::from(&memo_data);

        //Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, destination_memo)?)
    //})
//}

























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

