// Copyright (c) 2018-2020 MobileCoin Inc.

use displaydoc::Display;

/// Check an entropy string for "obvious" statistical problems or blacklisted values.
///
/// Note: It would be good to try to make the checks constant-time, since the root
/// entropy is generally a secret value.
pub fn check_root_entropy(root_entropy: &[u8]) -> Result<(), RootEntropyProblem> {
    // Check the root entropy length
    if root_entropy.len() != 32 {
        return Err(RootEntropyProblem::UnexpectedNumBytes(root_entropy.len()));
    }

    // Count number of 1 bits in the root entropy string
    let count_ones = root_entropy
        .iter()
        .fold(0u32, |count, byte| count + byte.count_ones());

    // The expected number of 1's is 128, the scenarios we reject here are that
    // there are 3 times as many 1 bits as zero bits, or vice versa
    if count_ones < (128 - 64) || count_ones > (128 + 64) {
        return Err(RootEntropyProblem::BiasedBits(count_ones));
    }
    Ok(())
}

/// Represents a reason that a root entropy value (for key derivation) was rejected
#[derive(Display, Debug, Eq, PartialEq, Hash)]
pub enum RootEntropyProblem {
    /// Root entropy should contain 32 bytes, found {0}
    UnexpectedNumBytes(usize),
    /// The root entropy bitstring was biased, having 1 {0} times the root entropy out of 256 bits, suggesting bad randomness
    BiasedBits(u32),
}
