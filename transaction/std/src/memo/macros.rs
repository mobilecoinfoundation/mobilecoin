// Copyright (c) 2018-2021 The MobileCoin Foundation

// Implement an enum over a list of memo types.
//
// All memo types must implement RegisteredMemoType.
//
// This enum will implement TryFrom<&MemoPayload>,
// and will try to match the memo type bytes against known memo types,
// or return an error if it can't.
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
        /// to be "trusted" data, see documentation.
        #[derive(Clone, Debug)]
        pub enum $enum_name {
            $(
                /// The $memo_name variant
                $memo_name($memo_type),
            )+
        }

        // Try to match memo type from src.get_memo_type
        impl TryFrom<&MemoPayload> for $enum_name {
            type Error = MemoDecodingError;
            fn try_from(src: &MemoPayload) -> Result<Self, Self::Error> {
                let memo_type_bytes: [u8; 2] = *src.get_memo_type();

                match memo_type_bytes {
                    $(<$memo_type as RegisteredMemoType>::MEMO_TYPE_BYTES => Ok($enum_name::$memo_name(<$memo_type>::from(src.get_memo_data()))),)+
                    _ => Err(MemoDecodingError::UnknownMemoType(memo_type_bytes))
                }
            }
        }

        // Blanket impl of Into<MemoPayload> for a RegisteredMemoType
        // This is not legal as a true blanket impl due to orphan rules
        $(impl Into<MemoPayload> for $memo_type {
            fn into(self) -> MemoPayload {
                MemoPayload::new(<Self as RegisteredMemoType>::MEMO_TYPE_BYTES, self.into())
            }
        })+

        // Implement Into<MemoPayload> for the enum
        impl Into<MemoPayload> for $enum_name {
            fn into(self) -> MemoPayload {
                match self {
                    $($enum_name::$memo_name(memo) => memo.into(),)+
                }
            }
        }
    }
}
