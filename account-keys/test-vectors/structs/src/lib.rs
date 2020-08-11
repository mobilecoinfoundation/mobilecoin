use mc_account_keys::{AccountKey, RootIdentity};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_util_test_vectors::TestVector;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct DefaultSubaddrKeysFromAcctPrivKeys {
    pub view_private_key: RistrettoPrivate,
    pub spend_private_key: RistrettoPrivate,
    pub subaddress_view_private_key: RistrettoPrivate,
    pub subaddress_spend_private_key: RistrettoPrivate,
    pub subaddress_view_public_key: RistrettoPublic,
    pub subaddress_spend_public_key: RistrettoPublic,
}

impl TestVector for DefaultSubaddrKeysFromAcctPrivKeys {
    const FILE_NAME: &'static str = "default_subaddr_keys_from_acct_priv_keys";
    const MODULE_SUBDIR: &'static str = "account_keys";

    fn generate() -> Vec<Self> {
        (0..10)
            .map(|n| {
                let account_key = AccountKey::from(&RootIdentity::from(&[n; 32]));
                let subaddress = account_key.default_subaddress();
                Self {
                    view_private_key: *account_key.view_private_key(),
                    spend_private_key: *account_key.spend_private_key(),
                    subaddress_view_private_key: account_key.default_subaddress_view_private(),
                    subaddress_spend_private_key: account_key.default_subaddress_spend_private(),
                    subaddress_view_public_key: *subaddress.view_public_key(),
                    subaddress_spend_public_key: *subaddress.spend_public_key(),
                }
            })
            .collect::<Vec<_>>()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubaddrKeysFromAcctPrivKeys {
    pub view_private_key: RistrettoPrivate,
    pub spend_private_key: RistrettoPrivate,
    pub subaddress_index: u64,
    pub subaddress_view_private_key: RistrettoPrivate,
    pub subaddress_spend_private_key: RistrettoPrivate,
    pub subaddress_view_public_key: RistrettoPublic,
    pub subaddress_spend_public_key: RistrettoPublic,
}

impl TestVector for SubaddrKeysFromAcctPrivKeys {
    const FILE_NAME: &'static str = "subaddr_keys_from_acct_priv_keys";
    const MODULE_SUBDIR: &'static str = "account_keys";

    fn generate() -> Vec<Self> {
        (0..10)
            .map(|n| {
                let account_key = AccountKey::from(&RootIdentity::from(&[n; 32]));
                let subaddress = account_key.subaddress(n as u64);
                Self {
                    view_private_key: *account_key.view_private_key(),
                    spend_private_key: *account_key.spend_private_key(),
                    subaddress_index: n as u64,
                    subaddress_view_private_key: account_key.subaddress_view_private(n as u64),
                    subaddress_spend_private_key: account_key.subaddress_spend_private(n as u64),
                    subaddress_view_public_key: *subaddress.view_public_key(),
                    subaddress_spend_public_key: *subaddress.spend_public_key(),
                }
            })
            .collect::<Vec<_>>()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcctPrivKeysFromRootEntropy {
    pub root_entropy: [u8; 32],
    pub view_private_key: RistrettoPrivate,
    pub spend_private_key: RistrettoPrivate,
}

impl TestVector for AcctPrivKeysFromRootEntropy {
    const FILE_NAME: &'static str = "acct_priv_keys_from_root_entropy";
    const MODULE_SUBDIR: &'static str = "identity";

    fn generate() -> Vec<Self> {
        (0..10)
            .map(|n| {
                let root_entropy = [n; 32];
                let account_key = AccountKey::from(&RootIdentity::from(&root_entropy));
                Self {
                    root_entropy,
                    view_private_key: *account_key.view_private_key(),
                    spend_private_key: *account_key.spend_private_key(),
                }
            })
            .collect::<Vec<_>>()
    }
}
