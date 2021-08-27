// Copyright (c) 2018-2021 The MobileCoin Foundation

// BufferedRng gets Iterator<Vec<u8>> for free, which allows using `.take()`
// syntax
macro_rules! impl_iterator_for_buffered_rng {
    ($name: ty) => {
        impl Iterator for $name {
            type Item = Vec<u8>;
            fn next(&mut self) -> Option<Vec<u8>> {
                let result = self.peek().to_vec();
                self.advance();
                Some(result)
            }
        }
    };
}

// Implement a multiversion buffered kex rng type, by listing identifiers and
// core types. A default type must be specified also.
macro_rules! impl_multiversion_kex_rng_enum {
    ($enum_name: ident,
     kex: $kex: ty,
     default: $def_name: ident => $def_type: ty,
     $($rng_name: ident => $rng_core_type: ty,)+
    ) => {
        /// An enum representing one of several possible BufferedKexRng implementations
        #[derive(Clone)]
        pub enum $enum_name {
            /// The $rng_name variant
            $($rng_name(BufferedKexRng::<$rng_core_type, $kex>),)+
        }

        impl KexRng<$kex> for $enum_name {}
        impl NewFromKex<$kex> for $enum_name {
            // Just build the default version
            fn new_from_ephemeral_static<T: RngCore + CryptoRng>(rng: &mut T, pubkey: &<$kex as Kex>::Public) -> (KexRngPubkey, Self) {
                let (kex_pubkey, buf) = BufferedKexRng::<$def_type, $kex>::new_from_ephemeral_static(rng, pubkey);
                (kex_pubkey, Self::$def_name(buf))
            }
            // Just build the default version
            fn new_from_static_static(our_private: &<$kex as Kex>::Private, pubkey: &<$kex as Kex>::Public) -> (KexRngPubkey, Self) {
                let (kex_pubkey, buf) = BufferedKexRng::<$def_type, $kex>::new_from_static_static(our_private, pubkey);
                (kex_pubkey, Self::$def_name(buf))
            }
            // Try to infer version from pubkey.version
            fn try_from_kex_pubkey(pubkey: &KexRngPubkey, private_key: &<$kex as Kex>::Private) -> Result<Self, Error> {
                match pubkey.version {
                    $(<$rng_core_type>::VERSION_ID => Ok(Self::$rng_name(BufferedKexRng::<$rng_core_type, $kex>::try_from_kex_pubkey(pubkey, private_key)?)),)+
                    _ => Err(Error::UnknownVersion(pubkey.version))
                }
            }
        }

        // Try to infer version from src.version
        impl TryFrom<StoredRng> for $enum_name {
            type Error = Error;
            fn try_from(src: StoredRng) -> Result<Self, Error> {
                match src.version {
                    $(<$rng_core_type>::VERSION_ID => Ok(Self::$rng_name(BufferedKexRng::<$rng_core_type, $kex>::try_from(src)?)),)+
                    _ => Err(Error::UnknownVersion(src.version))
                }
            }
        }

        // Forward to inner
        impl From<$enum_name> for StoredRng {
            fn from(src: $enum_name) -> StoredRng {
                match src {
                    $($enum_name::$rng_name(inner) => inner.into(),)+
                }
            }
        }

        // Forward to inner
        impl BufferedRng for $enum_name {
            fn peek(&self) -> &[u8] {
                match self {
                    $(Self::$rng_name(ref inner) => inner.peek(),)+
                }
            }
            fn advance(&mut self) {
                match self {
                    $(Self::$rng_name(ref mut inner) => inner.advance(),)+
                }
            }
            fn index(&self) -> u64 {
                match self {
                    $(Self::$rng_name(ref inner) => inner.index(),)+
                }
            }
            fn version_id(&self) -> u32 {
                match self {
                    $(Self::$rng_name(ref inner) => inner.version_id(),)+
                }
            }
        }

        impl_iterator_for_buffered_rng!($enum_name);

        $(impl_iterator_for_buffered_rng!(BufferedKexRng::<$rng_core_type, $kex>);)+
    }
}
