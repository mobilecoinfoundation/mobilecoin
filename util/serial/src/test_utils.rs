// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Test helpers

use crate::encode;
use prost::Message;

/// Take a prost type and try to roundtrip it through another prost type
pub fn round_trip_message<
    SRC: Message + PartialEq + Default,
    DEST: Message + PartialEq + Default,
>(
    src: &SRC,
) {
    let src_bytes = encode(src);
    let dest = DEST::decode(&src_bytes[..]).unwrap_or_else(|err| {
        panic!(
            "Failed to decode source as dest type: {}; src={:?}",
            err, src
        )
    });

    let dest_bytes = encode(&dest);
    let recovered = SRC::decode(&dest_bytes[..]).unwrap_or_else(|err| {
        panic!(
            "Failed to decode dest as source type: {}; dest={:?}",
            err, dest
        )
    });

    assert_eq!(src, &recovered);
}

/// Take a prost type and try to roundtrip it through another prost type
pub fn round_trip_message_and_conversion<SRC, DEST>(src: &SRC)
where
    for<'a> SRC: Message + PartialEq + Default + TryFrom<&'a DEST>,
    for<'a> DEST: Message + PartialEq + Default + From<&'a SRC>,
    for<'a> <SRC as TryFrom<&'a DEST>>::Error: core::fmt::Debug,
{
    round_trip_message::<SRC, DEST>(src);

    let dest = DEST::from(src);
    let recovered = SRC::try_from(&dest).unwrap();
    assert_eq!(src, &recovered);
}
