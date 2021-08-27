// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::{attest::McVerifier, common::*, LibMcError};
use core::convert::TryFrom;
use libc::ssize_t;
use mc_attest_core::Verifier;
use mc_crypto_keys::RistrettoPrivate;
use mc_fog_kex_rng::{BufferedRng, KexRngPubkey, NewFromKex, StoredRng, VersionedKexRng};
use mc_fog_report_validation::FogReportResponses;
use mc_util_ffi::*;
use mc_util_serial::Message;
use mc_util_uri::FogUri;
use std::str::FromStr;

/* ==== McFogResolver ==== */

pub type McFogResolver = (FogReportResponses, Verifier);
impl_into_ffi!((FogReportResponses, Verifier));

#[no_mangle]
pub extern "C" fn mc_fog_resolver_create(
    fog_report_verifier: FfiRefPtr<McVerifier>,
) -> FfiOptOwnedPtr<McFogResolver> {
    ffi_boundary(|| {
        (
            FogReportResponses::default(),
            (*fog_report_verifier).clone(),
        )
    })
}

#[no_mangle]
pub extern "C" fn mc_fog_resolver_free(fog_resolver: FfiOptOwnedPtr<McFogResolver>) {
    ffi_boundary(|| {
        let _ = fog_resolver;
    })
}

/// # Preconditions
///
/// * `report_url` - must be a nul-terminated C string containing a valid Fog
///   report uri.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_fog_resolver_add_report_response(
    fog_resolver: FfiMutPtr<McFogResolver>,
    report_url: FfiStr,
    report_response: FfiRefPtr<McBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let report_url =
            <&str>::try_from_ffi(report_url).expect("report_url isn't a valid C string");
        let report_url =
            FogUri::from_str(report_url).expect("report_url isn't a valid Fog report uri");
        let report_url = report_url.to_string();
        let report_response = mc_util_serial::decode(report_response.as_slice())?;

        fog_resolver
            .into_mut()
            .0
            .insert(report_url, report_response);
        Ok(())
    })
}

/* ==== McFogRng ==== */

pub type McFogRng = VersionedKexRng;
impl_into_ffi!(VersionedKexRng);

/// # Preconditions
///
/// * `subaddress_view_private_key` - must be a valid 32-byte Ristretto-format
///   scalar.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
/// * `LibMcError::UnsupportedCryptoBoxVersion`
#[no_mangle]
pub extern "C" fn mc_fog_rng_create(
    subaddress_view_private_key: FfiRefPtr<McBuffer>,
    rng_public_key: FfiRefPtr<McBuffer>,
    rng_version: u32,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> FfiOptOwnedPtr<McFogRng> {
    ffi_boundary_with_error(out_error, || {
        let subaddress_view_private_key =
            RistrettoPrivate::try_from_ffi(&subaddress_view_private_key)
                .expect("subaddress_view_private_key is not a valid RistrettoPrivate");

        let pubkey = KexRngPubkey {
            public_key: rng_public_key.to_vec(),
            version: rng_version,
        };
        Ok(VersionedKexRng::try_from_kex_pubkey(
            &pubkey,
            &subaddress_view_private_key,
        )?)
    })
}

#[no_mangle]
pub extern "C" fn mc_fog_rng_free(fog_rng: FfiOptOwnedPtr<McFogRng>) {
    ffi_boundary(|| {
        let _ = fog_rng;
    })
}

#[no_mangle]
pub extern "C" fn mc_fog_rng_clone(fog_rng: FfiRefPtr<McFogRng>) -> FfiOptOwnedPtr<McFogRng> {
    ffi_boundary(|| (*fog_rng).clone())
}

/// # Preconditions
///
/// * `out_fog_rng_proto_bytes` - must be null or else length must be >=
///   `encoded.len`.
#[no_mangle]
pub extern "C" fn mc_fog_rng_serialize_proto(
    fog_rng: FfiRefPtr<McFogRng>,
    out_fog_rng_proto_bytes: FfiOptMutPtr<McMutableBuffer>,
) -> ssize_t {
    ffi_boundary(|| {
        let stored_fog_rng: StoredRng = (*fog_rng).clone().into();
        let encoded_len = stored_fog_rng.encoded_len();
        if let Some(out_fog_rng_proto_bytes) = out_fog_rng_proto_bytes.into_option() {
            let out_fog_rng_proto_bytes = &mut out_fog_rng_proto_bytes
                .into_mut()
                .as_slice_mut_of_len(encoded_len)
                .expect("out_fog_rng_proto_bytes length is insufficient");
            stored_fog_rng
                .encode(out_fog_rng_proto_bytes)
                .expect("prost::encode with correctly-sized buffer is no fail");
        }
        ssize_t::ffi_try_from(encoded_len).expect("encoded.len could not be converted to ssize_t")
    })
}

/// # Errors
///
/// * `LibMcError::InvalidInput`
/// * `LibMcError::UnsupportedCryptoBoxVersion`
#[no_mangle]
pub extern "C" fn mc_fog_rng_deserialize_proto(
    fog_rng_proto_bytes: FfiRefPtr<McBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> FfiOptOwnedPtr<McFogRng> {
    ffi_boundary_with_error(out_error, || {
        let stored_fog_rng: StoredRng = mc_util_serial::decode(fog_rng_proto_bytes.as_slice())
            .map_err(|err| LibMcError::InvalidInput(format!("{:?}", err)))?;
        Ok(VersionedKexRng::try_from(stored_fog_rng)?)
    })
}

#[no_mangle]
pub extern "C" fn mc_fog_rng_index(fog_rng: FfiRefPtr<McFogRng>) -> i64 {
    ffi_boundary(|| {
        i64::ffi_try_from(fog_rng.index()).expect("fog_rng.index could not be converted to i64")
    })
}

#[no_mangle]
pub extern "C" fn mc_fog_rng_get_output_len(fog_rng: FfiRefPtr<McFogRng>) -> ssize_t {
    ffi_boundary(|| {
        ssize_t::ffi_try_from((*fog_rng).peek().len())
            .expect("output.len could not be converted to ssize_t")
    })
}

/// # Preconditions
///
/// * `out_output` - length must be >= `output.len`.
#[no_mangle]
pub extern "C" fn mc_fog_rng_peek(
    fog_rng: FfiRefPtr<McFogRng>,
    out_output: FfiMutPtr<McMutableBuffer>,
) -> bool {
    ffi_boundary(|| {
        let output = (*fog_rng).peek();
        out_output
            .into_mut()
            .as_slice_mut_of_len(output.len())
            .expect("out_output length is insufficient")
            .copy_from_slice(output);
    })
}

/// # Preconditions
///
/// * `out_output` - must be null or else length must be >= `output.len`.
#[no_mangle]
pub extern "C" fn mc_fog_rng_advance(
    fog_rng: FfiMutPtr<McFogRng>,
    out_output: FfiOptMutPtr<McMutableBuffer>,
) -> bool {
    ffi_boundary(|| {
        if let Some(out_output) = out_output.into_option() {
            let output = fog_rng.peek();
            out_output
                .into_mut()
                .as_slice_mut_of_len(output.len())
                .expect("out_output length is insufficient")
                .copy_from_slice(output);
        }
        fog_rng.into_mut().advance();
    })
}
