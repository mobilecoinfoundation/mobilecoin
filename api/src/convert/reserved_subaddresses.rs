// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::ReservedSubaddresses

use crate::{external, ConversionError};
use mc_account_keys::PublicAddress;
use mc_transaction_extra::ReservedSubaddresses;

impl From<&ReservedSubaddresses> for external::ReservedSubaddresses {
    fn from(src: &ReservedSubaddresses) -> Self {
        let mut dst = external::ReservedSubaddresses::new();

        dst.set_primary_address(external::PublicAddress::from(&src.primary_address));
        dst.set_change_subaddress(external::PublicAddress::from(&src.change_subaddress));
        dst.set_gift_code_subaddress(external::PublicAddress::from(&src.gift_code_subaddress));

        dst
    }
}

impl TryFrom<&external::ReservedSubaddresses> for ReservedSubaddresses {
    type Error = ConversionError;

    fn try_from(src: &external::ReservedSubaddresses) -> Result<Self, Self::Error> {
        let primary_address = PublicAddress::try_from(src.get_primary_address())?;
        let change_subaddress = PublicAddress::try_from(src.get_change_subaddress())?;
        let gift_code_subaddress = PublicAddress::try_from(src.get_gift_code_subaddress())?;

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
