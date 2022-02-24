//! Miscellaneous parsing and formatting utilities

#![deny(missing_docs)]

use core::fmt::Display;
use itertools::Itertools;
use std::{convert::TryFrom, fs, str::FromStr, time::Duration};

pub use mc_sgx_css::Signature as CssSignature;

/// Parse a number of seconds into a duration
///
/// This can be used with Clap
pub fn parse_duration_in_seconds(src: &str) -> Result<Duration, std::num::ParseIntError> {
    Ok(Duration::from_secs(u64::from_str(src)?))
}

/// Load a CSS file from disk. This represents a signature over an enclave,
/// and contains attestation parameters like MRENCLAVE and MRSIGNER as well
/// as other stuff.
pub fn load_css_file(filename: &str) -> Result<CssSignature, String> {
    let bytes =
        fs::read(filename).map_err(|err| format!("Failed reading file '{}': {}", filename, err))?;
    let signature = CssSignature::try_from(&bytes[..])
        .map_err(|err| format!("Failed parsing CSS file '{}': {}", filename, err))?;
    Ok(signature)
}

/// Helper to format a sequence as a comma-separated list
/// (This is used with lists of Ingest peer uris in logs,
/// because the debug logging of that object is harder to read)
///
/// To use this, wrap the value in SeqDisplay( ) then format it
pub struct SeqDisplay<T: Display, I: Iterator<Item = T> + Clone>(pub I);

impl<T: Display, I: Iterator<Item = T> + Clone> Display for SeqDisplay<T, I> {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(fmt, "[{}]", self.0.clone().format(", "))
    }
}
