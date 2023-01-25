
/// Marker trait for types encodable by [prost::Message] when the `prost` feature is enabled.
#[cfg(feature = "prost")]
pub trait MaybeProst: prost::Message {}

/// Default implementation of [MaybeProst] when the `prost` feature is enabled.
#[cfg(feature = "prost")]
impl <T: prost::Message> MaybeProst for T {}

/// Marker trait for types encodable by [prost::Message] when `prost` feature is enabled.
#[cfg(not(feature = "prost"))]
pub trait MaybeProst {}

/// Default implementation of [MaybeProst] when the `prost` feature is disabled.
#[cfg(not(feature = "prost"))]
impl <T> MaybeProst for T {}

/// Marker trait for serde encode/decode types when `serde` feature is enabled.
#[cfg(feature = "serde")]
pub trait MaybeSerde: serde::Serialize + serde::de::DeserializeOwned {}

/// Default implementation of [MaybeSerde] when the `serde` feature is enabled.
#[cfg(feature = "serde")]
impl <T: serde::Serialize + serde::de::DeserializeOwned> MaybeSerde for T {}

/// Marker trait for serde encode/decode types when `serde` feature is disabled.
#[cfg(not(feature = "serde"))]
pub trait MaybeSerde {}

/// Default implementation of [MaybeSerde] when the `serde` feature is disabled.
#[cfg(not(feature = "serde"))]
impl <T> MaybeSerde for T {}


/// Marker trait for `Into<Vec<u8>>` when `alloc` feature is enabled
#[cfg(feature = "alloc")]
pub trait MaybeAlloc: Into<Vec<u8>> {}

#[cfg(feature = "alloc")]
impl<T: Into<Vec<u8>>> MaybeAlloc for T {}

/// Marker trait for `Into<Vec<u8>>` when `alloc` feature is disabled
#[cfg(not(feature = "alloc"))]
pub trait MaybeAlloc {}

#[cfg(not(feature = "alloc"))]
impl<T> MaybeAlloc for T {}
