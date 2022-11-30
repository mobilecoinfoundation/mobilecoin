//! [AccountId] provides a unique identifier for a given MOB account
//! 

use mc_core_types::account::{Account, ViewAccount, RingCtAddress};

use crate::{consts::DEFAULT_SUBADDRESS_INDEX, subaddress::Subaddress};

/// Account ID object, derived from the default subaddress and used
/// to identify individual accounts.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct AccountId([u8; 32]);

/// Display [AccountId] as a hex encoded string
impl core::fmt::Display for AccountId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for v in self.0 {
            write!(f, "{:02X}", v)?;
        }
        Ok(())
    }
}

impl core::fmt::Debug for AccountId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "AccountId(")?;
        for v in self.0 {
            write!(f, "{:02X}", v)?;
        }
        write!(f, ")")
    }
}

/// Access raw [AccountId] hash
impl AsRef<[u8; 32]> for AccountId {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Create [AccountId] object from raw hash
impl From<[u8; 32]> for AccountId {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

/// Create [AccountId] object from raw hash
impl From<&[u8; 32]> for AccountId {
    fn from(value: &[u8; 32]) -> Self {
        Self(value.clone())
    }
}

/// PROPOSED: Compute AccountId from [Account] object
impl From<&Account> for AccountId {
    fn from(account: &Account) -> Self {
        let subaddress = account.subaddress(DEFAULT_SUBADDRESS_INDEX);

        let h = account_id_digest(subaddress);

        Self(h)
    }
}

/// PROPOSED: Compute AccountId from [ViewAccount] object
impl From<&ViewAccount> for AccountId {
    fn from(account: &ViewAccount) -> Self {
        let subaddress = account.subaddress(DEFAULT_SUBADDRESS_INDEX);

        let h = account_id_digest(subaddress);

        Self(h)
    }
}

/// PROPOSED: Compute merlin digest of an accounts default address to derive the [AccountId]
/// alternative to the full account_keys::PublicAddress derivation, though this may be preferred / worked around elsewhere.
fn account_id_digest(default_addr: impl RingCtAddress) -> [u8; 32] {
    let mut transcript = merlin::Transcript::new(b"account_id");

    let view_public_key = default_addr.view_public_key();
    let spend_public_key = default_addr.spend_public_key();

    transcript.append_message(b"view_public_key", &view_public_key.to_bytes());
    transcript.append_message(b"spend_public_key", &spend_public_key.to_bytes());
    
    let mut b = [0u8; 32];
    transcript.challenge_bytes(b"digest32", &mut b);

    b
}
