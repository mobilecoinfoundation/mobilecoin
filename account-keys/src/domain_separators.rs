// Copyright (c) 2018-2020 MobileCoin Inc.

/// The tag for the signature context
pub const FOG_AUTHORITY_SIGNATURE_TAG: &[u8; 23] = b"Fog authority signature";

/// Domain separator for hashing a private view key and index into a subaddress.
pub const SUBADDRESS_DOMAIN_TAG: &str = "mc_subaddress";
