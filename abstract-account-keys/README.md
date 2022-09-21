mc-abstract-account-keys
===============

This crate defines *traits* that abstract the functionality of a MobileCoin AccountKeys
object. The abstraction is meant to lend itself to the situation of hardware wallets,
where the spend key must remain on the hardware device. 

This crate must be maximally portable so that it can meet the needs of hardware wallets.
