// Copyright 2018-2021 The MobileCoin Foundation

use crate::{common::*, LibMcError};
use mc_account_keys::{AccountKey, PublicAddress};
use mc_crypto_keys::{ReprBytes, RistrettoPrivate, RistrettoPublic};
use mc_util_ffi::*;

/* ==== Account Key ==== */

#[repr(C)]
pub struct McAccountKey<'a> {
    /// 32-byte `RistrettoPrivate`
    pub view_private_key: FfiRefPtr<'a, McBuffer<'a>>,
    /// 32-byte `RistrettoPrivate`
    pub spend_private_key: FfiRefPtr<'a, McBuffer<'a>>,
    pub fog_info: FfiOptRefPtr<'a, McAccountKeyFogInfo<'a>>,
}

#[repr(C)]
pub struct McAccountKeyFogInfo<'a> {
    pub report_url: FfiStr<'a>,
    pub report_id: FfiStr<'a>,
    pub authority_spki: FfiRefPtr<'a, McBuffer<'a>>,
}

impl<'a> TryFromFfi<&McAccountKey<'a>> for AccountKey {
    type Error = LibMcError;

    fn try_from_ffi(src: &McAccountKey<'a>) -> Result<Self, Self::Error> {
        let view_private_key = RistrettoPrivate::try_from_ffi(&src.view_private_key)?;
        let spend_private_key = RistrettoPrivate::try_from_ffi(&src.spend_private_key)?;

        if let Some(fog_info) = src.fog_info.as_option() {
            Ok(AccountKey::new_with_fog(
                &spend_private_key,
                &view_private_key,
                <&str>::try_from_ffi(fog_info.report_url)?,
                fog_info.report_id.ffi_try_into()?,
                fog_info.authority_spki.as_slice(),
            ))
        } else {
            Ok(AccountKey::new(&spend_private_key, &view_private_key))
        }
    }
}

/// # Preconditions
///
/// * `view_private_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `spend_private_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `out_subaddress_view_private_key` - length must be >= 32.
/// * `out_subaddress_spend_private_key` - length must be >= 32.
#[no_mangle]
pub extern "C" fn mc_account_key_get_subaddress_private_keys(
    view_private_key: FfiRefPtr<McBuffer>,
    spend_private_key: FfiRefPtr<McBuffer>,
    subaddress_index: u64,
    out_subaddress_view_private_key: FfiMutPtr<McMutableBuffer>,
    out_subaddress_spend_private_key: FfiMutPtr<McMutableBuffer>,
) -> bool {
    ffi_boundary(|| {
        let view_private_key = RistrettoPrivate::try_from_ffi(&view_private_key)
            .expect("view_private_key is not a valid RistrettoPrivate");
        let spend_private_key = RistrettoPrivate::try_from_ffi(&spend_private_key)
            .expect("spend_private_key is not a valid RistrettoPrivate");
        let account_key = AccountKey::new(&spend_private_key, &view_private_key);
        let out_subaddress_view_private_key = out_subaddress_view_private_key
            .into_mut()
            .as_slice_mut_of_len(RistrettoPrivate::size())
            .expect("out_subaddress_view_private_key length is insufficient");
        let out_subaddress_spend_private_key = out_subaddress_spend_private_key
            .into_mut()
            .as_slice_mut_of_len(RistrettoPrivate::size())
            .expect("out_subaddress_spend_private_key length is insufficient");

        out_subaddress_view_private_key.copy_from_slice(
            account_key
                .subaddress_view_private(subaddress_index)
                .as_ref(),
        );
        out_subaddress_spend_private_key.copy_from_slice(
            account_key
                .subaddress_spend_private(subaddress_index)
                .as_ref(),
        );
    })
}

/// # Preconditions
///
/// * `view_private_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `spend_private_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `out_subaddress_view_public_key` - length must be >= 32.
/// * `out_subaddress_spend_public_key` - length must be >= 32.
#[no_mangle]
pub extern "C" fn mc_account_key_get_public_address_public_keys(
    view_private_key: FfiRefPtr<McBuffer>,
    spend_private_key: FfiRefPtr<McBuffer>,
    subaddress_index: u64,
    out_subaddress_view_public_key: FfiMutPtr<McMutableBuffer>,
    out_subaddress_spend_public_key: FfiMutPtr<McMutableBuffer>,
) -> bool {
    ffi_boundary(|| {
        let view_private_key = RistrettoPrivate::try_from_ffi(&view_private_key)
            .expect("view_private_key is not a valid RistrettoPrivate");
        let spend_private_key = RistrettoPrivate::try_from_ffi(&spend_private_key)
            .expect("spend_private_key is not a valid RistrettoPrivate");
        let account_key = AccountKey::new(&spend_private_key, &view_private_key);
        let out_subaddress_view_public_key = out_subaddress_view_public_key
            .into_mut()
            .as_slice_mut_of_len(RistrettoPublic::size())
            .expect("out_subaddress_view_public_key length is insufficient");
        let out_subaddress_spend_public_key = out_subaddress_spend_public_key
            .into_mut()
            .as_slice_mut_of_len(RistrettoPublic::size())
            .expect("out_subaddress_spend_public_key length is insufficient");

        let public_address = account_key.subaddress(subaddress_index);
        out_subaddress_view_public_key
            .copy_from_slice(&public_address.view_public_key().to_bytes());
        out_subaddress_spend_public_key
            .copy_from_slice(&public_address.spend_public_key().to_bytes());
    })
}

/// # Preconditions
///
/// * `account_key` - must be a valid `AccountKey` with `fog_info`.
/// * `out_fog_authority_sig` - length must be >= 64.
#[no_mangle]
pub extern "C" fn mc_account_key_get_public_address_fog_authority_sig(
    account_key: FfiRefPtr<McAccountKey>,
    subaddress_index: u64,
    out_fog_authority_sig: FfiMutPtr<McMutableBuffer>,
) -> bool {
    ffi_boundary(|| {
        let account_key = AccountKey::try_from_ffi(&account_key).expect("account_key is invalid");

        let public_address = account_key.subaddress(subaddress_index);
        let fog_authority_sig = public_address
            .fog_authority_sig()
            .expect("account_key does not contain fog info");

        let out_fog_authority_sig = out_fog_authority_sig
            .into_mut()
            .as_slice_mut_of_len(fog_authority_sig.len())
            .expect("out_fog_authority_sig length is insufficient");

        out_fog_authority_sig.copy_from_slice(fog_authority_sig);
    })
}

/* ==== PublicAddress ==== */

#[repr(C)]
pub struct McPublicAddress<'a> {
    /// 32-byte `CompressedRistrettoPublic`
    pub view_public_key: FfiRefPtr<'a, McBuffer<'a>>,
    /// 32-byte `CompressedRistrettoPublic`
    pub spend_public_key: FfiRefPtr<'a, McBuffer<'a>>,
    pub fog_info: FfiOptRefPtr<'a, McPublicAddressFogInfo<'a>>,
}

#[repr(C)]
pub struct McPublicAddressFogInfo<'a> {
    pub report_url: FfiStr<'a>,
    pub report_id: FfiStr<'a>,
    pub authority_sig: FfiRefPtr<'a, McBuffer<'a>>,
}

impl<'a> TryFromFfi<&McPublicAddress<'a>> for PublicAddress {
    type Error = LibMcError;

    fn try_from_ffi(src: &McPublicAddress<'a>) -> Result<Self, Self::Error> {
        let view_public_key = RistrettoPublic::try_from_ffi(&src.view_public_key)?;
        let spend_public_key = RistrettoPublic::try_from_ffi(&src.spend_public_key)?;

        if let Some(fog_info) = src.fog_info.as_option() {
            let fog_report_url = <&str>::try_from_ffi(fog_info.report_url)?;
            let fog_report_id = <String>::try_from_ffi(fog_info.report_id)?;
            let fog_authority_sig = fog_info.authority_sig.to_vec();
            Ok(PublicAddress::new_with_fog(
                &spend_public_key,
                &view_public_key,
                fog_report_url,
                fog_report_id,
                fog_authority_sig,
            ))
        } else {
            Ok(PublicAddress::new(&spend_public_key, &view_public_key))
        }
    }
}
