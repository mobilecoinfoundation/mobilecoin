// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::ReservedSubaddresses

use crate::{external, ConversionError};
use mc_account_keys::PublicAddress;
use mc_transaction_extra::ReservedSubaddresses;

impl From<&ReservedSubaddresses> for external::ReservedSubaddresses {
    fn from(src: &ReservedSubaddresses) -> Self {
        Self {
            primary_address: Some((&src.primary_address).into()),
            change_subaddress: Some((&src.change_subaddress).into()),
            gift_code_subaddress: Some((&src.gift_code_subaddress).into()),
        }
    }
}

impl TryFrom<&external::ReservedSubaddresses> for ReservedSubaddresses {
    type Error = ConversionError;

    fn try_from(src: &external::ReservedSubaddresses) -> Result<Self, Self::Error> {
        let primary_address =
            PublicAddress::try_from(src.primary_address.as_ref().unwrap_or(&Default::default()))?;
        let change_subaddress = PublicAddress::try_from(
            src.change_subaddress
                .as_ref()
                .unwrap_or(&Default::default()),
        )?;
        let gift_code_subaddress = PublicAddress::try_from(
            src.gift_code_subaddress
                .as_ref()
                .unwrap_or(&Default::default()),
        )?;

        Ok(ReservedSubaddresses {
            primary_address,
            change_subaddress,
            gift_code_subaddress,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_account_keys::AccountKey;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_reserved_subaddresses_conversion() {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);

        let account_key = AccountKey::random(&mut rng);
        let reserved_subaddresses = ReservedSubaddresses::from(&account_key);

        let proto_reserved_subaddresses =
            external::ReservedSubaddresses::from(&reserved_subaddresses);

        let reserved_subaddresses_converted =
            ReservedSubaddresses::try_from(&proto_reserved_subaddresses).unwrap();

        assert_eq!(reserved_subaddresses, reserved_subaddresses_converted);
    }
}
