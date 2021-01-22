// Copyright (c) 2018-2021 The MobileCoin Foundation

/// mock_service is a series of stub implementations for functions from sgx_tservice,
/// used in unit tests that are not sgx enabled
use mc_sgx_types::{
    sgx_report_data_t, sgx_report_t, sgx_sealed_data_t, sgx_status_t, sgx_target_info_t,
};

/// Get a report (default)
pub fn report(
    _target_info: Option<&sgx_target_info_t>,
    _report_data: Option<&sgx_report_data_t>,
) -> Result<sgx_report_t, sgx_status_t> {
    Ok(Default::default())
}

/// Verify report (ok)
pub fn verify_report(_report: &sgx_report_t) -> Result<(), sgx_status_t> {
    Ok(())
}

const PREFIX_LEN: u32 = core::mem::size_of::<sgx_sealed_data_t>() as u32;

/// Calculate sealed data size
/// We are still using sgx_sealed_data_t layout, for compat with mc_attest_core::IntelSealed
pub fn calc_sealed_data_size(
    plaintext_len: usize,
    additional_mac_txt_len: usize,
) -> Result<u32, sgx_status_t> {
    if plaintext_len >= u32::max_value() as usize
        || additional_mac_txt_len >= u32::max_value() as usize
    {
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }
    Ok(PREFIX_LEN + plaintext_len as u32 + additional_mac_txt_len as u32)
}

/// Seal data
pub fn seal_data(
    plaintext: &[u8],
    additional_mac_txt: &[u8],
    out_buffer: &mut [u8],
) -> Result<(), sgx_status_t> {
    if out_buffer.len() >= u32::max_value() as usize
        || out_buffer.len() as u32
            != calc_sealed_data_size(plaintext.len(), additional_mac_txt.len())?
    {
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }

    let (prefix, plaintext_buf, mac_buf) = {
        let (prefix, temp) = out_buffer.split_at_mut(PREFIX_LEN as usize);
        let (plaintext_buf, mac_buf) = temp.split_at_mut(plaintext.len());
        (prefix, plaintext_buf, mac_buf)
    };

    {
        let mut prefix_val = sgx_sealed_data_t::default();
        prefix_val.plain_text_offset = PREFIX_LEN + plaintext.len() as u32;

        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            core::ptr::write(prefix.as_mut_ptr() as *mut sgx_sealed_data_t, prefix_val)
        };
    }

    plaintext_buf.copy_from_slice(plaintext);
    mac_buf.copy_from_slice(additional_mac_txt);
    Ok(())
}

/// Extract sealed payload sizes from a sealed blob
pub fn get_sealed_payload_sizes(sealed_data: &[u8]) -> Result<(u32, u32), sgx_status_t> {
    if sealed_data.len() < PREFIX_LEN as usize {
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }

    #[allow(clippy::cast_ptr_alignment)]
    let sealed_ptr = sealed_data.as_ptr() as *const sgx_sealed_data_t;
    let mac_text_offset = unsafe { (*sealed_ptr).plain_text_offset };

    let sealed_len = sealed_data.len() as u32;
    let mac_text_len = sealed_len - mac_text_offset;
    let payload_len = sealed_len - PREFIX_LEN - mac_text_len;

    Ok((payload_len, mac_text_len))
}

/// Unseal data
pub fn unseal_data(
    sealed_data: &[u8],
    plaintext_out: &mut [u8],
    additional_mac_txt_out: &mut [u8],
) -> Result<(), sgx_status_t> {
    let (plaintext_len, mac_txt_len) = get_sealed_payload_sizes(sealed_data)?;
    if plaintext_out.len() != plaintext_len as usize
        || additional_mac_txt_out.len() != mac_txt_len as usize
    {
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }
    plaintext_out
        .copy_from_slice(&sealed_data[PREFIX_LEN as usize..(PREFIX_LEN + plaintext_len) as usize]);
    additional_mac_txt_out.copy_from_slice(&sealed_data[(PREFIX_LEN + plaintext_len) as usize..]);
    Ok(())
}
