// Copyright (c) 2018-2021 The MobileCoin Foundation

/// Implement an enum over a list of memo types.
///
/// All memo types must implement RegisteredMemoType.
///
/// This enum will implement TryFrom<&MemoPayload>,
/// which will try to match the memo type bytes against known memo types,
/// or return an error if it can't.
///
/// This is exported to allow that third parties can potentially implement
/// proprietary memo types in their own crate, and create their own version of
/// the "enum over all memos" using the same framework. However, if you are
/// doing this, we encourage you to eventually create an MCIP and propose your
/// memo types to be standardized.
///
/// Note: If two memo types are created with the same MEMO_TYPE_BYTES in their
/// impl RegisteredMemoType, this is not itself an error. However, if you
/// attempt to use both types in the `impl_memo_enum`, then you will have
/// identical match arms in the `TryFrom<&MemoPayload>` implementation, and rust
/// will issue a warning. You are strongly encouraged to compile with warnings
/// as errors.
#[macro_export]
macro_rules! impl_memo_enum {
    ($enum_name: ident,
     $($memo_name: ident ( $memo_type: ty ),)+
    ) => {
        /// The $enum_name enum is an enum over all the defined memo types, at this revision.
        ///
        /// It implements TryFrom<&MemoPayload>, and this is the intended high-level way
        /// to interpret MemoPayload objects.
        ///
        /// Most memo types require further validation before they can be considered
        /// to be "trusted" data. When handling a memo type that you recieved
        /// from the blockchain, see the documentation for that specific memo
        /// to determine how it can be validated.
        #[derive(Clone, Debug)]
        pub enum $enum_name {
            $(
                /// The $memo_name variant
                $memo_name($memo_type),
            )+
        }

        // Try to match memo type from src.get_memo_type
        impl TryFrom<&crate::MemoPayload> for $enum_name {
            type Error = crate::MemoDecodingError;
            fn try_from(src: &crate::MemoPayload) -> Result<Self, Self::Error> {
                let memo_type_bytes: [u8; 2] = *src.get_memo_type();

                match memo_type_bytes {
                    $(<$memo_type as crate::RegisteredMemoType>::MEMO_TYPE_BYTES => Ok($enum_name::$memo_name(<$memo_type>::from(src.get_memo_data()))),)+
                    _ => Err(crate::MemoDecodingError::UnknownMemoType(memo_type_bytes))
                }
            }
        }

        // Implement From<$enum_name> for MemoPayload
        impl From<$enum_name> for crate::MemoPayload {
            fn from(src: $enum_name) -> crate::MemoPayload {
                match src {
                    $($enum_name::$memo_name(memo) => memo.into(),)+
                }
            }
        }
    }
}

/// Implement From<$memo_type> for MemoPayload
///
/// for a registered memo type.
///
/// This is not legal as a true blanket impl due to orphan rules, so we provide
/// a macro to generate impl's such as this instead.
#[macro_export]
macro_rules! impl_memo_type_conversions {
    ($memo_type: ty) => {
        impl From<$memo_type> for crate::MemoPayload {
            fn from(src: $memo_type) -> crate::MemoPayload {
                crate::MemoPayload::new(
                    <$memo_type as crate::RegisteredMemoType>::MEMO_TYPE_BYTES,
                    src.into(),
                )
            }
        }
    };
}
