// Copyright (c) 2018-2022 The MobileCoin Foundation

/// Domain separator for hashing a private view key and index into a subaddress.
pub const SUBADDRESS_DOMAIN_TAG: &str = "mc_subaddress";

/// The constant used for hash-to-curve to produce burn address spend public.
/// This follows the style of the other domain separators in
/// mc-transaction-core.
pub const BURN_ADDRESS_DOMAIN_SEPARATOR: &str = "mc_burn_address_spend_public";
