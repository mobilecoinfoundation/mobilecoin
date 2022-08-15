//! Mobilecoin core constants

/// The BIP44 "usage" component of a BIP32 path.
///
/// See https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki for more details.
pub const USAGE_BIP44: u32 = 44;

/// The MobileCoin "coin type" component of a BIP32 path.
///
/// See https://github.com/satoshilabs/slips/blob/master/slip-0044.md for reference.
pub const COINTYPE_MOBILECOIN: u32 = 866;

/// Domain separator for hashing a private view key and index into a subaddress.
pub(crate) const SUBADDRESS_DOMAIN_TAG: &str = "mc_subaddress";

/// An account's "default address" is its zero^th subaddress.
pub const DEFAULT_SUBADDRESS_INDEX: u64 = 0;

/// u64::MAX is a reserved subaddress value for "invalid/none" (MCIP #36)
pub const INVALID_SUBADDRESS_INDEX: u64 = u64::MAX;

/// An account's "change address" is the 1st reserved subaddress,
/// counting down from `u64::MAX`. (See MCIP #4, MCIP #36)
pub const CHANGE_SUBADDRESS_INDEX: u64 = u64::MAX - 1;

/// The subaddress derived using u64::MAX - 2 is the reserved subaddress
/// for gift code TxOuts to be sent as specified in MCIP #32.
pub const GIFT_CODE_SUBADDRESS_INDEX: u64 = u64::MAX - 2;
