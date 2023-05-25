// Copyright (c) 2018-2022 The MobileCoin Foundation

use displaydoc::Display;

#[derive(Debug, Display)]
/// Array conversion errors.
pub enum ConvertError {
    /// Length mismatch. Expected `{0}`, got `{1}`
    LengthMismatch(usize, usize),
}
