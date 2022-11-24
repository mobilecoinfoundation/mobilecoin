// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Traits supporting driver (or other hardware) implementations

use core::{convert::Infallible, fmt::Debug};

use mc_core_types::{
    account::{Account, PublicSubaddress, ViewAccount},
    keys::TxOutPublic,
};
use mc_crypto_keys::{
    CompressedRistrettoPublic, KexReusablePrivate, RistrettoPrivate, RistrettoPublic,
};
use mc_crypto_memo_mac::compute_category1_hmac;
use mc_crypto_ring_signature::{onetime_keys::recover_onetime_private_key, KeyImage};

use crate::{consts::DEFAULT_SUBADDRESS_INDEX, subaddress::Subaddress};

/// View only account provider
pub trait ViewAccountProvider {
    /// TODO:
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

/// Blanket [ViewAccountProvider] for `&T`
impl<T: ViewAccountProvider> ViewAccountProvider for &T {
    type Error = <T as ViewAccountProvider>::Error;

    fn account(&self) -> Result<ViewAccount, Self::Error> {
        <T as ViewAccountProvider>::account(self)
    }
}

/// Transaction key image computer
pub trait KeyImageComputer {
    /// TODO
    type Error: Send + Sync + Debug;

    /// Compute key image for a given subaddress index and tx_out_public_key
    fn compute_key_image(
        &self,
        subaddress_index: u64,
        tx_out_public_key: &TxOutPublic,
    ) -> Result<KeyImage, Self::Error>;
}

/// Blanket [KeyImageComputer] impl for `&T`
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
    /// TODO
    type Error: Send + Sync + Debug;

    /// Compute the HMAC signature for the provided memo and target address
    fn compute_memo_hmac_sig(
        &self,
        tx_out_public_key: &TxOutPublic,
        target_subaddress: PublicSubaddress,
        memo_type: &[u8; 2],
        memo_data_sans_hmac: &[u8; 48],
    ) -> Result<[u8; 16], Self::Error>;
}

/// Basic [MemoHmacSigner] using [Account] object
impl MemoHmacSigner for Account {
    type Error = Infallible;

    fn compute_memo_hmac_sig(
        &self,
        tx_out_public_key: &TxOutPublic,
        target_subaddress: PublicSubaddress,
        memo_type: &[u8; 2],
        memo_data_sans_hmac: &[u8; 48],
    ) -> Result<[u8; 16], Self::Error> {
        // Fetch sender default spend private for signing
        let subaddress = self.subaddress(DEFAULT_SUBADDRESS_INDEX);

        let sender_default_spend_private: &RistrettoPrivate = subaddress.spend_private.as_ref();
        let receiver_view_public: &RistrettoPublic = target_subaddress.view_public.as_ref();

        // Compute shared secret for HMAC
        let shared_secret = sender_default_spend_private.key_exchange(receiver_view_public);

        // Compute HMAC for memo data
        let tx_out_public_key: &RistrettoPublic = tx_out_public_key.as_ref();

        let hmac_value = compute_category1_hmac(
            shared_secret.as_ref(),
            &CompressedRistrettoPublic::from(tx_out_public_key),
            *memo_type,
            &memo_data_sans_hmac,
        );

        Ok(hmac_value)
    }
}

/// Blanket [MemoHmacSigner] impl for `&T`
impl<T: MemoHmacSigner> MemoHmacSigner for &T {
    type Error = <T as MemoHmacSigner>::Error;

    fn compute_memo_hmac_sig(
        &self,
        tx_out_public_key: &TxOutPublic,
        target_subaddress: PublicSubaddress,
        memo_type: &[u8; 2],
        memo_data_sans_hmac: &[u8; 48],
    ) -> Result<[u8; 16], Self::Error> {
        <T as MemoHmacSigner>::compute_memo_hmac_sig(
            &self,
            tx_out_public_key,
            target_subaddress,
            memo_type,
            memo_data_sans_hmac,
        )
    }
}
