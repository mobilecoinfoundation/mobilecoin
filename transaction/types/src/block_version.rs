// Copyright (c) 2018-2022 The MobileCoin Foundation

use core::{fmt, hash::Hash, ops::Deref, str::FromStr};
use displaydoc::Display;
use mc_crypto_digestible::Digestible;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A block version number that is known to be less or equal to
/// BlockVersion::MAX
///
/// Note: BlockVersion::MAX may vary from client to client as we roll out
/// network upgrades. Software should handle errors where the block version of
/// the network is not supported, generally by requesting users to upgrade their
/// software.
///
/// If you need to manipulate block versions that come from the network, you
/// should use u32 to represent that.
///
/// Then, if you need to e.g. sign a transaction,
/// you should try to convert them to BlockVersion.
/// If that conversion fails, it means that this set of rules
/// is not understood by your version of `mc-transaction-core`.
/// This means that your build has reached end-of-life, and needs an update.
///
/// You should not assume that all block versions you will ever see will be
/// understood by your version of transaction core, otherwise there will be
/// no way for your software to help the user to upgrade when you reach EOL.
///
/// For example, `BlockVersion::try_from(...).unwrap()` is typically a bug
/// if it's not in test code.
#[derive(Clone, Copy, Debug, Default, Digestible, Eq, Hash, Ord, PartialOrd, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "u32"))]
pub struct BlockVersion(u32);

impl TryFrom<u32> for BlockVersion {
    type Error = BlockVersionError;

    fn try_from(src: u32) -> Result<Self, Self::Error> {
        if src <= *Self::MAX {
            Ok(Self(src))
        } else {
            Err(BlockVersionError::UnsupportedBlockVersion(src, *Self::MAX))
        }
    }
}

impl FromStr for BlockVersion {
    type Err = BlockVersionError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let src = u32::from_str(src).map_err(|_| BlockVersionError::Parse)?;
        Self::try_from(src)
    }
}

impl BlockVersion {
    /// The maximum value of block_version that this build of
    /// mc-transaction-core has support for
    pub const MAX: Self = Self(3);

    /// Refers to the block version number at network launch.
    pub const ZERO: Self = Self(0);

    /// Constant for block version one
    pub const ONE: Self = Self(1);

    /// Constant for block version two
    pub const TWO: Self = Self(2);

    /// Constant for block version three
    pub const THREE: Self = Self(3);

    /// Iterator over block versions from one up to max, inclusive. For use in
    /// tests.
    pub fn iterator() -> BlockVersionIterator {
        BlockVersionIterator(0)
    }

    /// The encrypted memos feature is introduced in v1.
    /// [MCIP #3](https://github.com/mobilecoinfoundation/mcips/pull/3)
    pub fn e_memo_feature_is_supported(&self) -> bool {
        self.0 >= 1
    }

    /// The confidential token ids feature is introduced in v2.
    /// [MCIP #25](https://github.com/mobilecoinfoundation/mcips/pull/25)
    pub fn masked_token_id_feature_is_supported(&self) -> bool {
        self.0 >= 2
    }

    /// Transactions must be sorted from v3 onward.
    /// [MCIP #34](https://github.com/mobilecoinfoundation/mcips/pull/34)
    pub fn validate_transaction_outputs_are_sorted(&self) -> bool {
        self.0 >= 3
    }

    /// Mint transactions are introduced in v2.
    /// [MCIP #37](https://github.com/mobilecoinfoundation/mcips/pull/37)
    pub fn mint_transactions_are_supported(&self) -> bool {
        self.0 >= 2
    }

    /// Minting_to_fog_addresses is supported in v3
    /// [MCIP #53](https://github.com/mobilecoinfoundation/mcips/pull/53)
    pub fn minting_to_fog_addresses_is_supported(&self) -> bool {
        self.0 >= 3
    }

    /// The extended message digest is used when signing MLSAGs
    /// in v2 and higher. This is described in
    /// [MCIP #25](https://github.com/mobilecoinfoundation/mcips/pull/25).
    pub fn mlsags_sign_extended_message_digest(&self) -> bool {
        self.0 >= 2
    }

    /// Mixed transactions are introduced in v3
    /// [MCIP #31](https://github.com/mobilecoinfoundation/mcips/pull/31)
    pub fn mixed_transactions_are_supported(&self) -> bool {
        self.0 >= 3
    }

    /// Signed input rules are introduced in v3.
    /// [MCIP #31](https://github.com/mobilecoinfoundation/mcips/pull/31)
    pub fn signed_input_rules_are_supported(&self) -> bool {
        self.0 >= 3
    }

    /// Masked amount V2 derivation introduced with block version 3.
    /// [MCIP #42](https://github.com/mobilecoinfoundation/mcips/pull/42)
    pub fn masked_amount_v2_is_supported(&self) -> bool {
        self.0 >= 3
    }

    /// `BlockData.metadata` is required starting from v3.
    /// [MCIP #43](https://github.com/mobilecoinfoundation/mcips/pull/43)
    pub fn require_block_metadata(&self) -> bool {
        self.0 >= 3
    }

    /// MLSAGs sign extended-message-and-tx-summary digest starting from v3.
    /// [MCIP #52](https://github.com/mobilecoinfoundation/mcips/pull/52)
    pub fn mlsags_sign_extended_message_and_tx_summary_digest(&self) -> bool {
        self.0 >= 3
    }

    /// Nested multisigs are supporoted starting from v3.
    /// [MCIP #TODO]
    pub fn nested_multisigs_are_supported(&self) -> bool {
        self.0 >= 3
    }
}

impl Deref for BlockVersion {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for BlockVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An iterator over block versions from 1 up to Max, for use in test code
#[derive(Debug, Clone)]
pub struct BlockVersionIterator(u32);

impl Iterator for BlockVersionIterator {
    type Item = BlockVersion;
    fn next(&mut self) -> Option<BlockVersion> {
        if self.0 <= *BlockVersion::MAX {
            let result = self.0;
            self.0 += 1;
            Some(BlockVersion(result))
        } else {
            None
        }
    }
}

/// An error that can occur when parsing a block version or interpreting u32 as
/// a block version
#[derive(Clone, Display, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum BlockVersionError {
    /// Unsupported block version: {0} > {1}. Try upgrading your software
    UnsupportedBlockVersion(u32, u32),
    /// Could not parse block version
    Parse,
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use alloc::vec::Vec;

    // Test that block_version::iterator is working as expected
    #[test]
    fn test_block_version_iterator() {
        let observed = BlockVersion::iterator().map(|x| *x).collect::<Vec<u32>>();
        let expected = (0..=*BlockVersion::MAX).collect::<Vec<u32>>();
        assert_eq!(observed, expected);
    }

    // Test that block_version::try_from is working as expected
    #[test]
    fn test_block_version_parsing() {
        BlockVersion::try_from(0).unwrap();
        for block_version in BlockVersion::iterator() {
            assert_eq!(
                block_version,
                BlockVersion::try_from(*block_version)
                    .expect("Could not parse *block version as block version")
            );
        }
        assert!(BlockVersion::try_from(*BlockVersion::MAX + 1).is_err());
        assert!(BlockVersion::try_from(*BlockVersion::MAX + 2).is_err());
    }
}
