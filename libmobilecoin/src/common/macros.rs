// Copyright (c) 2018-2021 The MobileCoin Foundation

#![macro_use]

#[macro_export]
macro_rules! impl_into_ffi {
    ($T:ty) => {
        impl $crate::common::IntoFfi<::mc_util_ffi::FfiOptOwnedPtr<Self>> for $T
        where
            $T: Sync + Sized,
        {
            #[inline]
            fn error_value() -> ::mc_util_ffi::FfiOptOwnedPtr<Self> {
                ::core::default::Default::default()
            }

            #[inline]
            fn into_ffi(self) -> ::mc_util_ffi::FfiOptOwnedPtr<Self> {
                ::mc_util_ffi::FfiOwnedPtr::new(self).into()
            }
        }
    };
}
