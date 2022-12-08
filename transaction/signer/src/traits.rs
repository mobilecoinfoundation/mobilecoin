//! Traits supporting driver (or other hardware) implementations

use core::{convert::Infallible, fmt::Debug};

use mc_core::{
    account::{Account, PublicSubaddress, ViewAccount},
    keys::TxOutPublic,
    subaddress::Subaddress,
};

use mc_crypto_ring_signature::{onetime_keys::recover_onetime_private_key, KeyImage};

/// View only account provider
pub trait ViewAccountProvider {
    /// [ViewAccountProvider] error
    type Error: Send + Sync + Debug;

    /// Fetch view account object
    fn account(&self) -> Result<ViewAccount, Self::Error>;
}

/// Basic view account provider for [Account] type
impl ViewAccountProvider for Account {
    type Error = Infallible;

    /// Fetch view account object
    fn account(&self) -> Result<ViewAccount, Self::Error> {
        Ok(ViewAccount::from(self))
    }
}

impl<T: ViewAccountProvider> ViewAccountProvider for &T {
    type Error = <T as ViewAccountProvider>::Error;

    fn account(&self) -> Result<ViewAccount, Self::Error> {
        <T as ViewAccountProvider>::account(self)
    }
}

/// Transaction key image computer
pub trait KeyImageComputer {
    /// [`KeyImageComputer`] error
    type Error: Send + Sync + Debug;

    /// Compute key image for a given subaddress index and tx_out_public_key
    fn compute_key_image(
        &self,
        subaddress_index: u64,
        tx_out_public_key: &TxOutPublic,
    ) -> Result<KeyImage, Self::Error>;
}

impl<T: KeyImageComputer> KeyImageComputer for &T {
    type Error = <T as KeyImageComputer>::Error;

    fn compute_key_image(
        &self,
        subaddress_index: u64,
        tx_out_public_key: &TxOutPublic,
    ) -> Result<KeyImage, Self::Error> {
        <T as KeyImageComputer>::compute_key_image(&self, subaddress_index, tx_out_public_key)
    }
}

/// Basic [KeyImageComputer] implementation for [Account] type
impl KeyImageComputer for Account {
    type Error = Infallible;

    /// Compute key image for a given subaddress index and tx_out_public_key
    fn compute_key_image(
        &self,
        subaddress_index: u64,
        tx_out_public_key: &TxOutPublic,
    ) -> Result<KeyImage, Self::Error> {
        // Compute subaddress from index
        let subaddress = self.subaddress(subaddress_index);

        // Recover onetime private key
        let onetime_private_key = recover_onetime_private_key(
            tx_out_public_key.as_ref(),
            self.view_private_key().as_ref(),
            subaddress.spend_private_key().as_ref(),
        );

        // Generate key image
        Ok(KeyImage::from(&onetime_private_key))
    }
}

/// Memo signer for generating memo HMACs
pub trait MemoHmacSigner {
    /// [`MemoHmacSigner`] error
    type Error: Send + Sync + Debug;

    /// Compute the HMAC signature for the provided memo and target address
    fn compute_memo_hmac_sig(
        &mut self,
        tx_public_key: &TxOutPublic,
        target_subaddress: PublicSubaddress,
        memo_type: &[u8; 2],
        memo_data_sans_hmac: &[u8; 48],
    ) -> Result<[u8; 16], Self::Error>;
}
