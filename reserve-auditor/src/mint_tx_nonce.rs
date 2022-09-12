// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{gnosis::EthTxHash, Error};
use mc_transaction_core::mint::constants::NONCE_LENGTH;

/// Data structure for representing what is encoded in a MintTx nonce.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MintTxNonce {
    /// A mint backed by a deposit to a Gnosis Safe on the Ethereum blockchain.
    EthereumGnosisDeposit(EthTxHash),
}

impl MintTxNonce {
    /// Nonce type identifier length.
    pub const IDENTIFIER_LEN: usize = 1;

    /// Bytes identifying each variant of [MintTxNonce].
    /// Future revisions might add different types of data stored in the nonce.
    pub const ETHEREUM_GNOSIS_DEPOSIT_IDENTIFIER: [u8; MintTxNonce::IDENTIFIER_LEN] = [0x01];

    /// Convert to the byte representation.
    pub fn to_bytes(&self) -> [u8; NONCE_LENGTH] {
        let mut bytes = [0u8; NONCE_LENGTH];
        match self {
            MintTxNonce::EthereumGnosisDeposit(eth_tx_hash) => {
                bytes[0..Self::IDENTIFIER_LEN]
                    .copy_from_slice(&MintTxNonce::ETHEREUM_GNOSIS_DEPOSIT_IDENTIFIER);
                bytes[Self::IDENTIFIER_LEN..Self::IDENTIFIER_LEN + EthTxHash::LEN]
                    .copy_from_slice(eth_tx_hash.as_ref())
            }
        }
        bytes
    }
}

impl TryFrom<&[u8]> for MintTxNonce {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != NONCE_LENGTH {
            return Err(Error::InvalidLength(NONCE_LENGTH, bytes.len()));
        }

        match &bytes[..Self::IDENTIFIER_LEN]
            .try_into()
            .map_err(|_| Error::InvalidNonceIdentifier(bytes[..Self::IDENTIFIER_LEN].to_vec()))?
        {
            &Self::ETHEREUM_GNOSIS_DEPOSIT_IDENTIFIER => {
                let eth_tx_hash = EthTxHash::try_from(
                    &bytes[Self::IDENTIFIER_LEN..Self::IDENTIFIER_LEN + EthTxHash::LEN],
                )?;
                Ok(MintTxNonce::EthereumGnosisDeposit(eth_tx_hash))
            }
            _ => Err(Error::InvalidNonceIdentifier(
                bytes[..Self::IDENTIFIER_LEN].to_vec(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_util_from_random::FromRandom;
    use std::str::FromStr;

    #[test]
    fn mint_tx_nonce_to_bytes_works() {
        let eth_tx_hash = EthTxHash::from_str(
            "0x0e781edb7739aa88ad2ffb6a69aab46ff9e32dbd0f0c87e4006a176838b075d2",
        )
        .unwrap();
        let mint_tx_nonce = MintTxNonce::EthereumGnosisDeposit(eth_tx_hash);
        let nonce_bytes = mint_tx_nonce.to_bytes();

        // Hardcoded indexes to ensure data ends up exactly where we think it should be.
        assert_eq!(
            nonce_bytes[0..1],
            MintTxNonce::ETHEREUM_GNOSIS_DEPOSIT_IDENTIFIER
        );
        assert_eq!(&nonce_bytes[1..33], eth_tx_hash.as_ref());
        assert_eq!(nonce_bytes[34..], [0u8; 64 - 34]);
    }

    #[test]
    fn mint_tx_nonce_from_bytes_works() {
        let mut rng = mc_util_test_helper::get_seeded_rng();

        // Invalid length is an error.
        assert!(MintTxNonce::try_from(&[0u8; NONCE_LENGTH - 1][..]).is_err());
        assert!(MintTxNonce::try_from(&[0u8; NONCE_LENGTH + 1][..]).is_err());

        // Invalid identifier is an error.
        assert!(MintTxNonce::try_from(&[10u8; NONCE_LENGTH][..]).is_err());

        // A valid EthereumGnosisDeposit nonce decodes successfully.
        let eth_tx_hash = EthTxHash::from_random(&mut rng);
        let mut bytes: [u8; NONCE_LENGTH] = [0u8; NONCE_LENGTH];
        bytes[..MintTxNonce::IDENTIFIER_LEN]
            .copy_from_slice(&MintTxNonce::ETHEREUM_GNOSIS_DEPOSIT_IDENTIFIER);
        bytes[MintTxNonce::IDENTIFIER_LEN..MintTxNonce::IDENTIFIER_LEN + EthTxHash::LEN]
            .copy_from_slice(eth_tx_hash.as_ref());
        let nonce = MintTxNonce::try_from(&bytes[..]).unwrap();

        assert_eq!(bytes, nonce.to_bytes());
        assert!(
            matches!(nonce, MintTxNonce::EthereumGnosisDeposit(ref eth_tx_hash_2) if &eth_tx_hash == eth_tx_hash_2)
        );
    }
}
