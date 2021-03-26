//! MobileCoin SLIP-0010-Based Key Derivation

#![no_std]
#![warn(missing_docs)]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::borrow::ToOwned;
use bip39::{Mnemonic, Seed};
use core::{fmt::Display, result::Result as CoreResult};
use curve25519_dalek::scalar::Scalar;
use displaydoc::Display;
use hkdf::Hkdf;
use mc_account_keys::{AccountKey, Error as AccountKeyError};
use mc_crypto_keys::RistrettoPrivate;
use sha2::Sha512;
use zeroize::Zeroize;

/// An enumeration of errors which can occur while working with SLIP-0010 key
/// derivation
#[derive(Debug, Display, Eq, PartialEq)]
pub enum Error {
    /// The path provided contained a member that was not "hardened".
    // FIXME: this is currently unused, and the slip10_ed25519 crate clamps to the appropriate
    //        range.
    UnhardenedPath,
    /// There was an error creating the account key: {0}
    AccountKey(AccountKeyError),
}

/// The result type
pub type Result<T> = CoreResult<T, Error>;

/// A key derived using SLIP-0010 key derivation
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Slip10Key([u8; 32]);

impl AsRef<[u8]> for Slip10Key {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

/// Create the view and spend private keys, and return them in reverse order,
/// e.g. `(spend, view)`, to match `AccountKey::new()`
impl Into<(RistrettoPrivate, RistrettoPrivate)> for Slip10Key {
    fn into(self) -> (RistrettoPrivate, RistrettoPrivate) {
        let mut okm = [0u8; 64];

        let view_kdf = Hkdf::<Sha512>::new(Some(b"mobilecoin-ristretto255-view"), self.as_ref());
        view_kdf
            .expand(b"", &mut okm)
            .expect("Invalid okm length when creating private view key");
        let view_scalar = Scalar::from_bytes_mod_order_wide(&okm);
        let view_private_key = RistrettoPrivate::from(view_scalar);

        let spend_kdf = Hkdf::<Sha512>::new(Some(b"mobilecoin-ristretto255-spend"), self.as_ref());
        spend_kdf
            .expand(b"", &mut okm)
            .expect("Invalid okm length when creating private spend key");
        let spend_scalar = Scalar::from_bytes_mod_order_wide(&okm);
        let spend_private_key = RistrettoPrivate::from(spend_scalar);

        (spend_private_key, view_private_key)
    }
}

impl From<[u8; 32]> for Slip10Key {
    fn from(src: [u8; 32]) -> Self {
        Self(src)
    }
}

/// A common interface for constructing a Slip10Key at a particular path from
/// existing entropy
pub trait Slip10KeyGenerator {
    /// The type of error, if any, to be returned if it occurs
    type Error: Display;

    /// Derive a slip10 key for the given path from the current object
    fn derive_slip10_key(self, path: &[u32]) -> CoreResult<Slip10Key, Self::Error>;
}

// This lets us get to
// Mnemonic::from_phrases().derive_slip10_key(path).try_into_account_key(...)
impl Slip10KeyGenerator for Mnemonic {
    type Error = Error;

    fn derive_slip10_key(self, path: &[u32]) -> Result<Slip10Key> {
        // We explicitly do not support passphrases for BIP-39 mnemonics, please
        // see the Mobilecoin Key Derivation design specification, v1.0.0, for
        // design rationale.
        let seed = Seed::new(&self, "");
        let key = slip10_ed25519::derive_ed25519_private_key(seed.as_bytes(), path);

        Ok(Slip10Key(key))
    }
}

// TODO: Slip10KeyGenerator for Seed
//
// This is a tougher call, since there doesn't appear to be any way to ensure
// the password is blank for this---and From<[u8; 32]> may be all we need for HW
// wallets...

impl Slip10Key {
    /// Try to construct a new AccountKey from an existing Slip10Key.
    // In the future, AccountKey::new_with_fog will be fallible.
    pub fn try_into_account_key(
        self,
        fog_report_url: &str,
        fog_report_id: &str,
        fog_authority_spki: &[u8],
    ) -> Result<AccountKey> {
        let (spend_private_key, view_private_key) = self.into();
        Ok(AccountKey::new_with_fog(
            &spend_private_key,
            &view_private_key,
            fog_report_url,
            fog_report_id.to_owned(),
            fog_authority_spki,
        ))
    }
}

impl From<Slip10Key> for AccountKey {
    fn from(src: Slip10Key) -> AccountKey {
        let (spend_private_key, view_private_key) = src.into();
        AccountKey::new(&spend_private_key, &view_private_key)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bip39::Language;

    /// Test vector built using SLIP10 outputs and ristretto vectors
    struct SlipToRistretto {
        slip10_hex: &'static str,
        view_hex: &'static str,
        spend_hex: &'static str,
    }

    /// An array of slip-to-ristretto test vectors, generated using the
    /// slip2ristrettovec.py script.
    const SLIPKEY_TO_RISTRETTO_TESTS: [SlipToRistretto; 12] = [
        // Seed1, chain m
        SlipToRistretto {
            slip10_hex: "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
            view_hex: "5a8d2f490f1e76ca0b7d14f37ce2b1a797b8e5e5c88b636e0c9b4b27b83c017a87cbd4a31a6f09ff0a896575f7a950743035cbe887c0e739d0104ed351397950",
            spend_hex: "34359a3c11ee05fa89fee68c66310448be52e4aacd21df68b1ea0e192786f2743c79edd445b14e411e96fdd6916721a31da4e0eb20011df9861269ac8ca76651",
        },
        // Seed1, chain m/0h
        SlipToRistretto {
            slip10_hex: "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
            view_hex: "ed78027e8bbfed790bfd82c8a7b09d4ebdeae64a34c9bccd8ba8b5f53e8175cb1f39a25a6e7af66ce164221d66ddcaabcfc3b46e9d2016c6853a58104bcb966e",
            spend_hex: "e9977192e47181c745ef2ec6aea0891317e286eff2b79839038ed69fc8a9607801b63d400f3f8225758b0033bef0044006e9aa1d801af3cde2d10bd885b23219",
        },
        // Seed1, chain m/0h/1h
        SlipToRistretto {
            slip10_hex: "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
            view_hex: "8da3648d1287e149ecaef02262c10b553e9db725513a16b4e551b5905b1c584835609d6f5de35a599042b4aca518be8d245dfd23ab85d888d9b8878d390dd0d3",
            spend_hex: "e5e34e1df7a634bcd5c5dabe4165f8fe4563e6eca60d140d64a60553d91b5612f7b5433e0e9b2a0b5db8890565480ec2b0cc36c83abc53b9d830bdd8ba89b339",
        },
        // Seed1, chain m/0h/1h/2h
        SlipToRistretto {
            slip10_hex: "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
            view_hex: "704e6f3367f791a92a2f51b7464a9c0939069588184f889db79fa41296579bc45467108987d53c2db9721ab9e8b83c8fb8a221b8ed0d2f25ed499c8ffa463cf4",
            spend_hex: "3da2b9a45da40a74ef575cc1f797f1af9d8aaa0c56e3aa5d4c4fe9d9fefc7ed8ab6605a527425c333877e3d860a38916f37cec3e3eca30e596fa72bf13ec72de",
        },
        // Seed1, chain m/0h/1h/2h/2h
        SlipToRistretto {
            slip10_hex: "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
            view_hex: "17c55ed9d315d3354d9002585e9e36d8d4a59c2d81dbf6f79f34cde17c037bb5a75369a06013eea62b7d031cf6d29e4aa2076f9616515eadc80f13c4d5e8d335",
            spend_hex: "b4e77a241249fb329edc03b5e23ad55c4ac59c624937e13f53e9f8cb1d48b519e60b01c40f7a390cf2ccc5ddfc50aa9eabaa5fe45467fc306c84e643740d2eaa",
        },
        // Seed1, chain m/0h/1h/2h/2h/1000000000h
        SlipToRistretto {
            slip10_hex: "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
            view_hex: "cc1625738ea9cd53c5249e5d7a8d48137954bd0635a4c9de8d66e05ea85b26685dfc02d96d2b801870b43df2f9ab4d5a8d99795ebc2612bbdbd1f47ee93ad437",
            spend_hex: "e66dbc9006aa58d33ab44f09cc8430617836e5be3445d5ef4e4a72d7a9e08aa8562464cbdcbf5fd04c5cd0a606b9ab263742ef0833a6a383ada36464512543dc",
        },

        // Seed 2, chain m
        SlipToRistretto {
            slip10_hex: "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
            view_hex: "252b64e72ce233d4f0722271a87800b30066e02d88888f5f02e118c17fd5fec6d575f629655fcb290fe0c0af3753cc11059d2905b60e966f1149dfcfebc41911",
            spend_hex: "60b498483f453f941e9de4f2f5f77aef14662fd03091f9dad337a2e7dd0935b56200a943749b31400f13c750c694114d8b0824e036db456bb90d41a96355c845",
        },
        // Seed 2, chain m/0h
        SlipToRistretto {
            slip10_hex: "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
            view_hex: "e38c79fde4d2765d12194877c609ca71f4b9dec9fe3257f73d984be88dae3b40645b89a122ce6c58f91d00ac4e1c2dab8f270946cc622e18557a0c8c32c8324e",
            spend_hex: "46cecebccce9dd56f668f73d401304acc1a99a790fb6fe4e42e007e0affcef5367284f8e2ae3cef534ef9d8494ffaa9aba077f1b907e38c33e8a904bbe0db646",
        },
        // Seed 2, chain m/0h/2147483647h
        SlipToRistretto {
            slip10_hex: "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
            view_hex: "338b5d54caa54d6603a965eaefa5496b3f080e91d040eedee68861845dacf36aa9e0290e2132657d146e2c99993e0f6ff07427571856e56bb1f789bfda73ca9c",
            spend_hex: "3d50ae00c8c57754251c6e56da7a3225319d17b522d26cd68db65819b2241fe8d0745269f2452c65a87cfb0c01e01e99524932635f0f901d22b9a90d0417c736",
        },
        // Seed 2, chain m/0h/2147483647h/1h
        SlipToRistretto {
            slip10_hex: "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
            view_hex: "692cf43116bf4d7c916b20ddafc9994af1ec0f44cd1442b7a97f1f132b0851561a890d9fb7fd3fc4a7bc518d7cd59fb376f5c26f1bddbc06cfbd55f706a86dce",
            spend_hex: "caef63e15caee473afc52cc7dbdec61a04bb076a40a51d7acc534266a79c83c881219a1dd1961a3afa9ad4490a0da1759e7cc29a490d706dd5892119c5d14636",
        },
        // Seed 2, chain m/0h/2147483647h/1h/2147483646h
        SlipToRistretto {
            slip10_hex: "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
            view_hex: "f304957a698bb5bb8bdba551fb41d09989da619c220a471f14481e0c6517d5802bb243abe85b356e0f9787f130cf32a47f0742527e205c42434dad1ab8c0f173",
            spend_hex: "8df044dfcdc8a4bce6cac272def5de78538200c6d6fac148a4c3cdf45a6be60c368e3f187d32155e1b75fd936e1ef97af6f5604cd876075c4171ea0f56c8a3cd",
        },
        // Seed 2, chain m/0h/2147483647h/1h/2147483646h/2h
        SlipToRistretto {
            slip10_hex: "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
            view_hex: "54236b7a6c8edc075f36faf4a8fa253cede026c655dc8b32bd87edb8cb18a76e30639f4f384cd2986e813ac74ce213199315847fef246092dbdab06c8163f104",
            spend_hex: "68a4ac670f7431ebdfde157ee4ab2a9a84e539f438acd364bc0543bf4deb3d106cbea42e0682de712e018b92503344b80e698a701e3bcba4ffceeb0f4afd3086",
        },
    ];

    #[test]
    fn slip10key_into_account_key() {
        for data in SLIPKEY_TO_RISTRETTO_TESTS.iter() {
            // Maybe make Slip10Key implement hex::FromHex?
            let mut key_bytes = [0u8; 32];
            hex::decode_to_slice(data.slip10_hex, &mut key_bytes[..])
                .expect("Could not decode SLIP10 test vector output");

            let slip10_key = Slip10Key::from(key_bytes);

            let mut expected_view_bytes = [0u8; 64];
            hex::decode_to_slice(data.view_hex, &mut expected_view_bytes)
                .expect("Could not decode view-key bytes");
            let expected_view_scalar = Scalar::from_bytes_mod_order_wide(&expected_view_bytes);
            let expected_view_key = RistrettoPrivate::from(expected_view_scalar);

            let mut expected_spend_bytes = [0u8; 64];
            hex::decode_to_slice(data.spend_hex, &mut expected_spend_bytes)
                .expect("Could not decode spend-key bytes");
            let expected_spend_scalar = Scalar::from_bytes_mod_order_wide(&expected_spend_bytes);
            let expected_spend_key = RistrettoPrivate::from(expected_spend_scalar);

            let account_key = AccountKey::from(slip10_key);

            assert_ne!(
                AsRef::<[u8]>::as_ref(&expected_view_key),
                AsRef::<[u8]>::as_ref(&expected_spend_key)
            );
            assert_eq!(
                AsRef::<[u8]>::as_ref(&expected_view_key),
                AsRef::<[u8]>::as_ref(account_key.view_private_key())
            );
            assert_eq!(
                AsRef::<[u8]>::as_ref(&expected_spend_key),
                AsRef::<[u8]>::as_ref(account_key.spend_private_key())
            );
        }
    }

    /// A test vector using
    struct MnemonicToRistretto {
        phrase: &'static str,
        view_hex: &'static str,
        spend_hex: &'static str,
    }

    /// These are the strings used in the [BIP39 test vectors](https://github.com/trezor/python-mnemonic/blob/master/vectors.json).
    ///
    /// In those tests it's assumed the password is "TREZOR", but it's safe to
    /// assume these are burned.
    const EN_MNEMONIC_STRINGS: [MnemonicToRistretto; 24] = [
        MnemonicToRistretto {
            phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            view_hex: "8bd04a61f03bb35a3ce59120089e6cc1a7887fa127f904725ade32474e43550a996eb3732b671ae2e4e1914aafde9afc11c7d353bda1c55505c173c6705b57f3",
            spend_hex: "815b3648210dc2f25a54bb0c19b721ebe170564446a7a3794c540ba6d9b7b5f58a19dfc3d15f283de210d913d31cbb142fa4f49ec5377494e76d059fa71664d5",
        },
        MnemonicToRistretto {
            phrase: "legal winner thank year wave sausage worth useful legal winner thank yellow",
            view_hex: "378a7738a8798e7584b3fbdb776c515a8fcd3c2cd73bf46a0fbf9f49ac6f04cfcc3529673ca4383456bc6125e44440ae1ae4cad4507d45d70fae2de123c9913b",
            spend_hex: "08dd28ef8d2727c2f8e7dcc21f5f39f89d9ec2b41144fccd00e1cc1953515f4c82c9e7b66c8882baad6cfb7e95030c9dd65d0389a46718ea92549bf47bc9b34b",
        },
        MnemonicToRistretto {
            phrase: "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            view_hex: "c66be3d420665d3299f7e59f5c1f79aa22c9706010cd3a4428d7c7f624d684ac161e47ae8bc7091c53dcc19d3d342d8352a9a499c18c59bc89518ea73159290d",
            spend_hex: "9c40fe0b1d19be68b64c878673a537eedeb8d40483fcc5a553d59961a0c6f341cba36f920eab22aa543e83780d0a336398ac0663fb8db00d3ebe51ef3c55eec4",
        },
        MnemonicToRistretto {
            phrase: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            view_hex: "f148170960ce77008f3899660dc61868d2de595e7508e4e2d224d356529ac4705b7560a12d2516193f402e7024dcf178a53a700d28e863683fb7c671a487484c",
            spend_hex: "2bda81c4cb985ea1394d879ebf43d15dae5d7df699b0275e52b7984ff0c28378c0c3970c9aaaee0efec9c23606deec2d0e72f5b4f97d68a2990c078e50c6e5fb",
        },
        MnemonicToRistretto {
            phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
            view_hex: "4e60a45f45ab52cac11c35a333326491d784b91960d666212f316b713d9c7310421b0605bfd3884cc79f342ea1ab1b8bbb097407feb08aae0e91bc5e0576e3c1",
            spend_hex: "2d80efd9584e5aa0e2323fe97b50d2e597a6fa6bbb01da11cab583c5dc7b166f8eb6d9d39b5dec120bbef2da794ad48aaec86e44af6528fec4856f8ae9322fb2",
        },
        MnemonicToRistretto {
            phrase: "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
            view_hex: "fd679b5eafefa5d391eb2fb7ccef3b5afbf6dda598451f1a04cc2f5ddd5536c387f398ba67efc6d9af693aefda620437bc792718d21790c592dafadc5ef3629c",
            spend_hex: "e84e4f9d3fba03d1c6c76691e778ed92edce2a4c3526df057ec9451218d000cf5194be9916154e6d092f6bad532e6ca719ca0eaa50ad7781f93ac20fd37e14b8",
        },
        MnemonicToRistretto {
            phrase: "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
            view_hex: "1ba2004b0c19341e73acc24fc1a4308bb38b40da220721caeb3bff8496ffa7f6970d2de5da7bae93eadc0a47b8ee05cfce69b96e18384859ee7bab8342fcd37a",
            spend_hex: "4ec968404233f1667d4a7599c3678817edba281472277b881e46a0df677df46d04acc59fb23a347d711517dc887c4e8fd9a22300537941c9521c9c83ee93567b",
        },
        MnemonicToRistretto {
            phrase: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
            view_hex: "d01e1224470a1f1eb21a4170b75c2c60afbd42db1925693f553c733f446fb061d3edacf82d82d24bc6c7f961c695ba6664edf58cbc19a621ef84ee03525793aa",
            spend_hex: "4828d56b3ebdaa030562fa9d2729ad2f08ef830b72513b012ce2afcb8a96f0d443af88cdf4937a3be6ba54ffcde7279955e99831870c5db6d2d510b49df0c2eb",
        },
        MnemonicToRistretto {
            phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            view_hex: "9e66e10c06f193bea050531f3efcf2beeced7ecaddbc517bafea06d063e202589abbdaf75ad4f5ea0c13c8ba3dbadce06a8907fc5d9d6f46d58b8b92f4de160e",
            spend_hex: "56a4352d24b73484901e8875e4945eb2435d8530e5fccfdb7c2c536d02d05cae462689973c7bdc88910c0c5ac64494826d27d944a7a7064c436f99f9262cf859",
        },
        MnemonicToRistretto {
            phrase: "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
            view_hex: "696a398414350f7ded40d67aa0cd276635b05f8c4b98735457433195bfca465d8b4a294bc76b310643e92a648de1d5a46a7c21fbe8fd1fb8eb0e0182887984c4",
            spend_hex: "efab7c8c87c95e5225b5e6f716b18d8b23c9fed2605ff8e3aeceddd7335448910886e8447587018b732087c47ef82508978c6a572f46c43d1bfa9a0d57dcf96d",
        },
        MnemonicToRistretto {
            phrase: "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
            view_hex: "04f44228aec47f77ed64498979ac544843ec4231eea1ce9608d49c481394a3f302d0df228adb7354a2b65d9edd9481023e4197f165521dad1ba38f450d45407c",
            spend_hex: "8babcba4a096292f4d471232d90b9a75ff0f6cdce718e11d8026baff84cb2c871d5d1257bfe12ab83223ab3f6845455fe464c032a4a8e135abb52287787b4182",
        },
        MnemonicToRistretto {
            phrase: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            view_hex: "7ebba2e3fc3e6bd6104c6c88e8055ce354f3f440861a4e2e6d668337e552648f30f8c062d50865accff92e4e1e3800052b4086bf8830e493144ba4520191af93",
            spend_hex: "9c806b3234fc81352ce80f5f71dfc764a9018b6bfb8ad9692ac86ef1fe1c7031dd086e22911b6ae052d564a752762de1d69d9546fcad941c0b2a87ba2d8dd467",
        },
        MnemonicToRistretto {
            phrase: "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
            view_hex: "55492f2c512e6fe19de9b819d8cacf15d56f19685a87725ab7d00ccd112dd9af6baefbff6b842f260157d3c5a59412e17214005eedd45aa6f516557edacbfa2d",
            spend_hex: "5bb705e5d7a923ef48dfe369e1453f27934f484b9ccc56f67610102cff3c2c16aac0392bce1d4ed41ce7c5c42ad6141e397114581db56dfaaa47455893f155db",
        },
        MnemonicToRistretto {
            phrase: "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
            view_hex: "68eeea32075781760ac7eb0fe97efc9d8a18f3932ae61462c3f50d7e01982061304d1e629b484e42e38c79a8acc9f8d49bde51aeef4d2d87b83990ae6907dd71",
            spend_hex: "577db5cb77e28e50fb793bca4e665723d81c8781145bac9c377a60cf2797d81861000778bba327ac655f75444d45fb3a2d0e4bcad3c2f4dfb790ecb518fb8d7f",
        },
        MnemonicToRistretto {
            phrase: "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
            view_hex: "e230711aa9e2ef8d662f38bab22242a271dcbed98ee1ac3195fba7bd7fd1cde567a744c3fb6d6f9049fabb1ef83598ccb3ce3165b5bae741b63f9109161b5225",
            spend_hex: "11dee61157dc185c3eabe4e2ceb31058cdc82c10ecf58542e67c06bc50b98d93757d1c8139867c9ba68ef9bc8b5b141183fd072636b84e45603f180d53dc43b5",
        },
        MnemonicToRistretto {
            phrase: "scheme spot photo card baby mountain device kick cradle pact join borrow",
            view_hex: "e697f302dfab59beed28509bd63b3b0a8205a5edfe389dfed1d35863f3ed8037498f4d506c88bec92d436e134a89ec301e0da90f73ff14fe00c759548945701e",
            spend_hex: "8d5e53a200f1fe85f2817aa51e81979d57e50ffcf1891f3865bdc5be2d2b770123dbb1a81844b26a3104173f1fe462c7fec1282a562007adf353f930ea2c3ca4",
        },
        MnemonicToRistretto {
            phrase: "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
            view_hex: "d5b5eff3d6b32736c68dbb282b2db6eac35d4a91a0c588cf54b56883d72ec7156b5cf946ad9e4f47f0c54320c80e9c189072c91c4c8a0f780b3ab85350b26f5e",
            spend_hex: "b2dd6490b3a44a1b064807e4352fe46ea6934d3100c3aafc1dbd9877bcb0069b495d8403c61472da83d1018fd7dda4e9b370a5cd34ff95769e715d5d1b8a58a4",
        },
        MnemonicToRistretto {
            phrase: "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
            view_hex: "ecd6f35a8107a1efedf2f783a3c7c84e48d8c13d407812ce2a13892d9bcafeda9538188c2608cb67abf1566d76b60d7a511a1c12fb65fc11a3856c19129ee732",
            spend_hex: "a014d8ffdd98ec1c2475bebc2263516363458225563b99b5e0a7ea9538fe463337838452fc9c17ed1d6a89a03c3e823186ff11087d869df0cd8ccbc55f5ae410",
        },
        MnemonicToRistretto {
            phrase: "cat swing flag economy stadium alone churn speed unique patch report train",
            view_hex: "bbdac4f43a2279249fc51717e5fef6af266ef1dc7179c3b2ca35e00dd4bcef5d29ad61486c2f221871d97e7df5c58b435caaac27fff3e84c492c2fcdbdd7f2d9",
            spend_hex: "1eacb453ce8b25235b1dd541b0e8308cfa4e52cd1ee0f57d3f951b885acf4be24657f2f6eb54325d6aa6b206cec4155ad8e2c614999ce9f3c662f6b8c0488e7e",
        },
        MnemonicToRistretto {
            phrase: "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
            view_hex: "3b88e1b554ec9adbcfc63bfcfd3722e22cc07836fdbbffd36082f678f851efc6f61971903e64f00b6feb5e7b51c72eec5badbc6b0feedd4bd5f94d291875501d",
            spend_hex: "d14a61deac228aadccc2b07bc43ae773c65199b8eb9ae49cd74002406059decdbb6f6ebcbdb1e0e698732c6f610a83527ce83f00dbcbf085b281502a5245cee9",
        },
        MnemonicToRistretto {
            phrase: "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
            view_hex: "6a198583006bd3af8fa37f81678d934048f4bbd6cb04221781851b69293419a459c2f8f6caf1abd4f997f3d28f6aebc8fae8942ec809a248e1901c86c94687ff",
            spend_hex: "44a0cc673efc7512edb076a7c253c08523e6ab9b2e38d105e812ae908524484e134b40ef074f276706fda2b4386d2e721525f8bdb263f91db5fd05b828426514",
        },
        MnemonicToRistretto {
            phrase: "vessel ladder alter error federal sibling chat ability sun glass valve picture",
            view_hex: "4da2769c4014e242935edcec09cb218630ec902983e114de4dded2103c9e014b2ca1a8998ebd37dee388647f2f637d6181a7abb871649610f44efe3054257810",
            spend_hex: "a3b6c66456686ec326cb099cd3ee1b00ee7b71b4ca93b31a18a5553e75d4d8b7027430908592576cf25145e9a7c8b1af98383b334e40fad1031b5d217fb46ee1",
        },
        MnemonicToRistretto {
            phrase: "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
            view_hex: "4c6a8bbfe8c74ca2c6b9a896606b9e1656169b8dcad42ee74cf3d21f924a3600cf333ce153a9370e2327d909b2c382f57bf18e6747dd21b626b167467feee1ac",
            spend_hex: "d598faeb6f5d373544e204fa7006c880459eaa485ae09603f6201212c5f749c6f4bb59a2c025ca219b14905be3c291900ff65922975b95df1c8cf28a0ea03a92",
        },
        MnemonicToRistretto {
            phrase: "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
            view_hex: "bb668a4f525442a87f14451afa0fd823fe8e1dd46c0fbd3169db65098b17b0f4a07bac6036a8765d2ad33c3629d207f704b7441408d71019e3115c4c767888be",
            spend_hex: "1d62e1f31d69b00f57e5d1ac5abcbc0cf77f719262dbe9a065d3dfa7c3fc60e85cc6d053f536cba7a23aa65d506e6dce4468bc9be25266ce772fa7bda8f11978",
        },
    ];

    #[test]
    fn mnemonic_into_account_key() {
        for data in EN_MNEMONIC_STRINGS.iter() {
            let mnemonic = Mnemonic::from_phrase(data.phrase, Language::English)
                .expect("Could not read test phrase into mnemonic");
            let key = mnemonic
                .derive_slip10_key(&[])
                .expect("Could not derive slip key from mnemonic for the 'm' path");
            let account_key = AccountKey::from(key);

            let mut expected_view_bytes = [0u8; 64];
            hex::decode_to_slice(data.view_hex, &mut expected_view_bytes)
                .expect("Could not decode view-key bytes");
            let expected_view_scalar = Scalar::from_bytes_mod_order_wide(&expected_view_bytes);
            let expected_view_key = RistrettoPrivate::from(expected_view_scalar);

            let mut expected_spend_bytes = [0u8; 64];
            hex::decode_to_slice(data.spend_hex, &mut expected_spend_bytes)
                .expect("Could not decode spend-key bytes");
            let expected_spend_scalar = Scalar::from_bytes_mod_order_wide(&expected_spend_bytes);
            let expected_spend_key = RistrettoPrivate::from(expected_spend_scalar);

            assert_ne!(
                AsRef::<[u8]>::as_ref(&expected_view_key),
                AsRef::<[u8]>::as_ref(&expected_spend_key)
            );
            assert_eq!(
                AsRef::<[u8]>::as_ref(&expected_view_key),
                AsRef::<[u8]>::as_ref(account_key.view_private_key())
            );
            assert_eq!(
                AsRef::<[u8]>::as_ref(&expected_spend_key),
                AsRef::<[u8]>::as_ref(account_key.spend_private_key())
            );
        }
    }
}
