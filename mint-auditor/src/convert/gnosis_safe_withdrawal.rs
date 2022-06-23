// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from mc_mint_auditor_api::GnosisSafeWithdrawal.

use crate::{db::GnosisSafeWithdrawal as DbGnosisSafeWithdrawal, Error};
use hex::ToHex;
use mc_mint_auditor_api::GnosisSafeWithdrawal as ProtoGnosisSafeWithdrawal;

/// Convert DbGnosisSafeWithdrawal --> ProtoGnosisSafeWithdrawal
impl TryFrom<&DbGnosisSafeWithdrawal> for ProtoGnosisSafeWithdrawal {
    type Error = Error;

    fn try_from(src: &DbGnosisSafeWithdrawal) -> Result<Self, Error> {
        let mut dst = Self::new();
        dst.set_id(src.id().unwrap_or_default());
        dst.set_eth_tx_hash(src.eth_tx_hash().to_string());
        dst.set_eth_block_number(src.eth_block_number());
        dst.set_safe_addr(src.safe_address().to_string());
        dst.set_token_addr(src.token_address().to_string());
        dst.set_amount(src.amount());
        dst.set_mc_tx_out_pub_key((&src.mc_tx_out_public_key()?).into());
        Ok(dst)
    }
}

/// Convert ProtoGnosisSafeWithdrawal --> DbGnosisSafeWithdrawal
impl From<&ProtoGnosisSafeWithdrawal> for DbGnosisSafeWithdrawal {
    fn from(src: &ProtoGnosisSafeWithdrawal) -> Self {
        Self::new(
            if src.get_id() == 0 {
                None
            } else {
                Some(src.get_id())
            },
            src.get_eth_tx_hash().to_string(),
            src.get_eth_block_number(),
            src.get_safe_addr().to_string(),
            src.get_token_addr().to_string(),
            src.get_amount(),
            src.get_mc_tx_out_pub_key().get_data().encode_hex(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // DbGnosisSafeWithdrawal --> ProtoGnosisSafeWithdrawal -->
    // DbGnosisSafeWithdrawal should be the identity function.
    fn test_convert_gnosis_safe_withdrawal() {
        let source = DbGnosisSafeWithdrawal::new(
            Some(10),
            "0x0e781edb7739aa88ad2ffb6a69aab46ff9e32dbd0f0c87e4006a176838b075d2".to_string(),
            123456,
            "0xB0Dfaaa92e4F3667758F2A864D50F94E8aC7a56B".to_string(),
            "0xB0Dfaaa92e4F3667758F2A864D50F94E8aC7a56B".to_string(),
            333,
            "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        );

        // Converting should be the identity function.
        {
            let external = ProtoGnosisSafeWithdrawal::try_from(&source).unwrap();
            let recovered = DbGnosisSafeWithdrawal::from(&external);
            assert_eq!(source, recovered);
        }
    }
}
