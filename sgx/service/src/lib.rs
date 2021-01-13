// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Provides safe interfaces to sgx_tservice functionality

#![no_std]
#![deny(missing_docs)]

use core::ptr;
use mc_sgx_types::{
    sgx_attributes_t, sgx_calc_sealed_data_size, sgx_create_report, sgx_get_add_mac_txt_len,
    sgx_get_encrypt_txt_len, sgx_report_data_t, sgx_report_t, sgx_seal_data_ex, sgx_sealed_data_t,
    sgx_status_t, sgx_target_info_t, sgx_unseal_data, sgx_verify_report, SGX_KEYPOLICY_MRENCLAVE,
    TSEAL_DEFAULT_FLAGSMASK, TSEAL_DEFAULT_MISCMASK,
};

////
// Report
////

/// Get a report
pub fn report(
    target_info: Option<&sgx_target_info_t>,
    report_data: Option<&sgx_report_data_t>,
) -> Result<sgx_report_t, sgx_status_t> {
    let mut report = sgx_report_t::default();
    let target_info: *const sgx_target_info_t = match target_info {
        Some(v) => v,
        None => ptr::null(),
    };
    let report_data: *const sgx_report_data_t = match report_data {
        Some(v) => v,
        None => ptr::null(),
    };
    match unsafe { sgx_create_report(target_info, report_data, &mut report) } {
        sgx_status_t::SGX_SUCCESS => Ok(report),
        status => Err(status),
    }
}

/// Verify a report
pub fn verify_report(report: &sgx_report_t) -> Result<(), sgx_status_t> {
    match unsafe { sgx_verify_report(report) } {
        sgx_status_t::SGX_SUCCESS => Ok(()),
        err_code => Err(err_code),
    }
}

////
// Sealing
////

// To keep things simple, we only allow MRENCLAVE identity and default flags
const KEY_POLICY: u16 = SGX_KEYPOLICY_MRENCLAVE;
const ATTRIBUTE_MASK: sgx_attributes_t = sgx_attributes_t {
    flags: TSEAL_DEFAULT_FLAGSMASK,
    xfrm: 0,
};
const MISC_MASK: u32 = TSEAL_DEFAULT_MISCMASK;

/// Convert a usize to u32 or else return invalid_parameter
fn usize_for_sgx(val: usize) -> Result<u32, sgx_status_t> {
    if val >= u32::max_value() as usize {
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }
    Ok(val as u32)
}

/// For a given plaintext length, how large an outbuffer should I use to seal it?
/// Note that using the wrong size is an error per intel SDK
/// Per Intel, the result is u32::max_value() if there is an error
pub fn calc_sealed_data_size(
    plaintext_len: usize,
    additional_mac_txt_len: usize,
) -> Result<u32, sgx_status_t> {
    let result = unsafe {
        sgx_calc_sealed_data_size(
            usize_for_sgx(additional_mac_txt_len)?,
            usize_for_sgx(plaintext_len)?,
        )
    };
    if result == u32::max_value() {
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }
    Ok(result)
}

/// Given a plaintext, seal it to MRENCLAVE identity
/// The entire outbuffer will be used
/// It is an error if out_buffer.len() does not equal calc_sealed_data_size(plaintext.len())
pub fn seal_data(
    plaintext: &[u8],
    additional_mac_txt: &[u8],
    out_buffer: &mut [u8],
) -> Result<(), sgx_status_t> {
    match unsafe {
        #[allow(clippy::cast_ptr_alignment)]
        sgx_seal_data_ex(
            KEY_POLICY,
            ATTRIBUTE_MASK,
            MISC_MASK,
            usize_for_sgx(additional_mac_txt.len())?,
            additional_mac_txt.as_ptr(),
            usize_for_sgx(plaintext.len())?,
            plaintext.as_ptr(),
            usize_for_sgx(out_buffer.len())?,
            out_buffer.as_mut_ptr() as *mut sgx_sealed_data_t,
        )
    } {
        sgx_status_t::SGX_SUCCESS => Ok(()),
        err_code => Err(err_code),
    }
}

/// Given sealed data, get the lengths of sealed payload and additional mac text.
/// Also double check that these numbers make sense given the length of the sealed data.
///
/// If the sealed blob has nonzero additional mac text, we fail with SGX_ERROR_UNEXPECTED
pub fn get_sealed_payload_sizes(sealed_data: &[u8]) -> Result<(u32, u32), sgx_status_t> {
    let sealed_len = usize_for_sgx(sealed_data.len())?;

    #[allow(clippy::cast_ptr_alignment)]
    let sealed_ptr = sealed_data.as_ptr() as *const sgx_sealed_data_t;

    let mac_len = unsafe { sgx_get_add_mac_txt_len(sealed_ptr) };
    let payload_len = unsafe { sgx_get_encrypt_txt_len(sealed_ptr) };

    // Check that the numbers in the header actually match the length of the buffer we recieved
    // If not then the input is malformed and we should not make allocations and should warn the user.
    if unsafe { sgx_calc_sealed_data_size(mac_len, payload_len) } != sealed_len {
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }

    Ok((payload_len, mac_len))
}

/// Unseal data sealed using seal_data, into an outbuffer
/// The length of the outbuffer should be determined using `authenticate_sealed`
///
/// Note that the MAC is actually checked in both `authenticate_sealed` and this function,
/// we want to make sure the MAC is checked before we get_encrypt_txt_len so that we don't get DOS'ed
/// by being forced to allocate a large buffer, but SGX does not provide a version of unseal that
/// doesn't check MAC.
///
/// If additional mac txt is present in the sealed blob, we fail with SGX_ERROR_UNEXPECTED.
/// If unsealing succeeds, we return the portion of the outbuffer that we wrote to (which is normally
/// the whole thing if you allocated the amount indicated by `authenticate_sealed`.
pub fn unseal_data(
    sealed_data: &[u8],
    plaintext_out: &mut [u8],
    additional_mac_txt_out: &mut [u8],
) -> Result<(), sgx_status_t> {
    let mut payload_len = usize_for_sgx(plaintext_out.len())?;
    let mut add_mac_len = usize_for_sgx(additional_mac_txt_out.len())?;

    #[allow(clippy::cast_ptr_alignment)]
    let sealed_ptr = sealed_data.as_ptr() as *const sgx_sealed_data_t;

    if payload_len != unsafe { sgx_get_encrypt_txt_len(sealed_ptr) }
        || add_mac_len != unsafe { sgx_get_add_mac_txt_len(sealed_ptr) }
    {
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }

    match unsafe {
        sgx_unseal_data(
            sealed_ptr,
            additional_mac_txt_out.as_mut_ptr(),
            &mut add_mac_len as *mut u32,
            plaintext_out.as_mut_ptr(),
            &mut payload_len as *mut u32,
        )
    } {
        sgx_status_t::SGX_SUCCESS => {
            if payload_len != plaintext_out.len() as u32
                || add_mac_len != additional_mac_txt_out.len() as u32
            {
                Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
            } else {
                Ok(())
            }
        }
        err_code => Err(err_code),
    }
}
