// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from mc_mint_auditor_api::GnosisSafeWithdrawal.

use crate::{
    db::GnosisSafeWithdrawal as DbGnosisSafeWithdrawal,
    gnosis::{EthAddr, EthTxHash},
    Error,
};
use hex::ToHex;
use mc_mint_auditor_api::GnosisSafeWithdrawal as ProtoGnosisSafeWithdrawal;
use std::str::FromStr;

/// Convert DbGnosisSafeWithdrawal --> ProtoGnosisSafeWithdrawal
impl TryFrom<&DbGnosisSafeWithdrawal> for ProtoGnosisSafeWithdrawal {
    type Error = Error;

    fn try_from(src: &DbGnosisSafeWithdrawal) -> Result<Self, Error> {
        let mut dst = Self::new();
        dst.set_id(src.id().unwrap_or_default());
        dst.set_eth_tx_hash(src.eth_tx_hash().to_string());
        dst.set_eth_block_number(src.eth_block_number());
        dst.set_safe_addr(src.safe_addr().to_string());
        dst.set_token_addr(src.token_addr().to_string());
        dst.set_amount(src.amount());
        dst.set_mc_tx_out_pub_key((&src.mc_tx_out_public_key()?).into());
        Ok(dst)
    }
}

/// Convert ProtoGnosisSafeWithdrawal --> DbGnosisSafeWithdrawal
impl TryFrom<&ProtoGnosisSafeWithdrawal> for DbGnosisSafeWithdrawal {
    type Error = Error;

    fn try_from(src: &ProtoGnosisSafeWithdrawal) -> Result<Self, Error> {
        Ok(Self::new(
            match src.get_id() {
                0 => None,
                id => Some(id),
            },
            EthTxHash::from_str(src.get_eth_tx_hash())?,
            src.get_eth_block_number(),
            EthAddr::from_str(src.get_safe_addr())?,
            EthAddr::from_str(src.get_token_addr())?,
            src.get_amount(),
            src.get_mc_tx_out_pub_key().get_data().encode_hex(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::{ETH_TOKEN_CONTRACT_ADDR, SAFE_ADDR};

    #[test]
    // DbGnosisSafeWithdrawal --> ProtoGnosisSafeWithdrawal -->
    // DbGnosisSafeWithdrawal should be the identity function.
    fn test_convert_gnosis_safe_withdrawal() {
        let source = DbGnosisSafeWithdrawal::new(
            Some(10),
            EthTxHash::from_str(
                "0x0e781edb7739aa88ad2ffb6a69aab46ff9e32dbd0f0c87e4006a176838b075d2",
            )
            .unwrap(),
            123456,
            EthAddr::from_str(SAFE_ADDR).unwrap(),
            EthAddr::from_str(ETH_TOKEN_CONTRACT_ADDR).unwrap(),
            333,
            "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        );

        // Converting should be the identity function.
        {
            let external = ProtoGnosisSafeWithdrawal::try_from(&source).unwrap();
            let recovered = DbGnosisSafeWithdrawal::try_from(&external).unwrap();
            assert_eq!(source, recovered);
        }
    }
}
