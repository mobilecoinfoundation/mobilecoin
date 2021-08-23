// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::{common::*, fog::McFogResolver, keys::McPublicAddress, LibMcError};
use core::convert::TryFrom;
use mc_account_keys::PublicAddress;
use mc_crypto_keys::{ReprBytes, RistrettoPrivate, RistrettoPublic};
use mc_fog_report_validation::FogResolver;
use mc_transaction_core::{
    get_tx_out_shared_secret,
    onetime_keys::{recover_onetime_private_key, recover_public_subaddress_spend_key},
    ring_signature::KeyImage,
    tx::{TxOut, TxOutConfirmationNumber, TxOutMembershipProof},
    Amount, CompressedCommitment, MemoPayload,
};
use mc_transaction_std::{InputCredentials, RTHMemoBuilder, TransactionBuilder};
use mc_util_ffi::*;

/* ==== TxOut ==== */

#[repr(C)]
pub struct McTxOutAmount<'a> {
    /// 32-byte `CompressedCommitment`
    commitment: FfiRefPtr<'a, McBuffer<'a>>,
    masked_value: u64,
}

impl<'a> TryFromFfi<&McTxOutAmount<'a>> for Amount {
    type Error = LibMcError;

    fn try_from_ffi(src: &McTxOutAmount<'a>) -> Result<Self, Self::Error> {
        let commitment = CompressedCommitment::try_from_ffi(&src.commitment)?;
        Ok(Amount {
            commitment,
            masked_value: src.masked_value,
        })
    }
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
        if let Ok(amount) = Amount::try_from_ffi(&tx_out_amount) {
            if let Ok(public_key) = RistrettoPublic::try_from_ffi(&tx_out_public_key) {
                let shared_secret = get_tx_out_shared_secret(&view_private_key, &public_key);
                matches = amount.get_value(&shared_secret).is_ok()
            }
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
        let amount = Amount::try_from_ffi(&tx_out_amount)?;
        let tx_out_public_key = RistrettoPublic::try_from_ffi(&tx_out_public_key)?;
        let view_private_key = RistrettoPrivate::try_from_ffi(&view_private_key)
            .expect("view_private_key is not a valid RistrettoPrivate");

        let shared_secret = get_tx_out_shared_secret(&view_private_key, &tx_out_public_key);
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
        let memo_builder = RTHMemoBuilder::default();
        // FIXME: Enable recoverable transaction history by configuring memo_builder
        let mut transaction_builder = TransactionBuilder::new(fog_resolver, memo_builder);
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
    transaction_builder: FfiMutPtr<McTransactionBuilder>,
    amount: u64,
    recipient_address: FfiRefPtr<McPublicAddress>,
    fog_hint_address: FfiRefPtr<McPublicAddress>,
    rng_callback: FfiOptMutPtr<McRngCallback>,
    out_tx_out_confirmation_number: FfiMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> FfiOptOwnedPtr<McData> {
    // FIXME(chris): The SDK should probably stop binding to this function, I don't
    // believe that there is legitimate use for this.
    // It should bind "add_change_output" instead.
    // Please speak to me if you disagree.
    ffi_boundary_with_error(out_error, || {
        let transaction_builder = transaction_builder
            .into_mut()
            .as_mut()
            .expect("McTransactionBuilder instance has already been used to build a Tx");
        let recipient_address =
            PublicAddress::try_from_ffi(&recipient_address).expect("recipient_address is invalid");
        let fog_hint_address =
            PublicAddress::try_from_ffi(&fog_hint_address).expect("fog_hint_address is invalid");
        let mut rng = SdkRng::from_ffi(rng_callback);
        let out_tx_out_confirmation_number = out_tx_out_confirmation_number
            .into_mut()
            .as_slice_mut_of_len(TxOutConfirmationNumber::size())
            .expect("out_tx_out_confirmation_number length is insufficient");

        let (tx_out, confirmation) = transaction_builder.add_output_with_fog_hint_address(
            amount,
            &recipient_address,
            &fog_hint_address,
            |_| Ok(MemoPayload::default()),
            &mut rng,
        )?;

        out_tx_out_confirmation_number.copy_from_slice(confirmation.as_ref());
        Ok(mc_util_serial::encode(&tx_out))
    })
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
