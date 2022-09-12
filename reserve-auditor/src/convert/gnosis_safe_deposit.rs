// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from mc_reserve_auditor_api::GnosisSafeDeposit.

use crate::{
    db::GnosisSafeDeposit as DbGnosisSafeDeposit,
    gnosis::{EthAddr, EthTxHash},
    Error,
};
use mc_reserve_auditor_api::GnosisSafeDeposit as ProtoGnosisSafeDeposit;
use std::str::FromStr;

/// Convert DbGnosisSafeDeposit --> ProtoGnosisSafeDeposit
impl From<&DbGnosisSafeDeposit> for ProtoGnosisSafeDeposit {
    fn from(src: &DbGnosisSafeDeposit) -> Self {
        let mut dst = Self::new();
        dst.set_id(src.id().unwrap_or_default());
        dst.set_eth_tx_hash(src.eth_tx_hash().to_string());
        dst.set_eth_block_number(src.eth_block_number());
        dst.set_safe_addr(src.safe_addr().to_string());
        dst.set_token_addr(src.token_addr().to_string());
        dst.set_amount(src.amount());
        dst.set_expected_mc_mint_tx_nonce_hex(src.expected_mc_mint_tx_nonce_hex().to_string());
        dst
    }
}

/// Convert ProtoGnosisSafeDeposit --> DbGnosisSafeDeposit
impl TryFrom<&ProtoGnosisSafeDeposit> for DbGnosisSafeDeposit {
    type Error = Error;

    fn try_from(src: &ProtoGnosisSafeDeposit) -> Result<Self, Self::Error> {
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
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // DbGnosisSafeDeposit --> ProtoGnosisSafeDeposit --> DbGnosisSafeDeposit should
    // be the identity function.
    fn test_convert_gnosis_safe_withdrawal() {
        let source = DbGnosisSafeDeposit::new(
            Some(10),
            EthTxHash::from_str(
                "0x0e781edb7739aa88ad2ffb6a69aab46ff9e32dbd0f0c87e4006a176838b075d2",
            )
            .unwrap(),
            123456,
            EthAddr::from_str("0xB0Dfaaa92e4F3667758F2A864D50F94E8aC7a56B").unwrap(),
            EthAddr::from_str("0xB0Dfaaa92e4F3667758F2A864D50F94E8aC7a56B").unwrap(),
            333,
        );

        // Converting should be the identity function.
        {
            let external = ProtoGnosisSafeDeposit::from(&source);
            let recovered = DbGnosisSafeDeposit::try_from(&external).unwrap();
            assert_eq!(source, recovered);
        }
    }
}
