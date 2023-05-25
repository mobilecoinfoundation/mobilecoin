// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Parsing of hex values from `&str`

use hex::{FromHex, FromHexError};

/// Parse a hex string
///
/// # Arguments:
/// * `hex`- The hex string to parse
pub fn parse_hex<T: FromHex<Error = FromHexError>>(hex: &str) -> Result<T, FromHexError> {
    <T>::from_hex(hex)
}
