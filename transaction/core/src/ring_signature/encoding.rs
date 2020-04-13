// Copyright (c) 2018-2020 MobileCoin Inc.

//! Encoding/Decoding utilities.

use core::convert::TryInto;

use mcserial::{
    prost::{
        bytes::{Buf, BufMut},
        encoding::{check_wire_type, decode_varint, encode_key, encode_varint, WireType},
    },
    DecodeError,
};

/// Writes `tag` and the 32-byte value to `buf`.
pub fn write_u8_32<B: BufMut>(value: [u8; 32], tag: u32, buf: &mut B) {
    encode_key(tag, WireType::LengthDelimited, buf);
    encode_varint(32 as u64, buf);
    buf.put_slice(&value[..]);
}

/// Reads a 32-byte value from `buf`.
pub fn read_u8_32<B: Buf>(wire_type: WireType, buf: &mut B) -> Result<[u8; 32], DecodeError> {
    check_wire_type(WireType::LengthDelimited, wire_type)?;
    let len = decode_varint(buf)?;
    if len > buf.remaining() as u64 {
        return Err(DecodeError::new("Buffer underflow."));
    }
    let bytes: [u8; 32] = (&buf.bytes()[0..32]).try_into().unwrap();
    buf.advance(32);
    Ok(bytes)
}

#[cfg(test)]
mod encoding_tests {
    use super::*;
    use alloc::vec::Vec;
    use mcserial::prost::encoding::{encoded_len_varint, key_len};

    #[test]
    // read_u8_32 should recover the value written by write_u8_32.
    fn test_write_read() {
        let value = [77u8; 32];
        let tag = 999;

        let mut buf: Vec<u8> = Vec::new();
        write_u8_32(value, tag, &mut buf);

        // `buf` should contain the correct number of bytes.
        let expected_len = key_len(tag) + encoded_len_varint(32 as u64) + 32;
        assert_eq!(buf.len(), expected_len);

        let mut read_buf = &buf[..];
        assert_eq!(read_buf.remaining(), expected_len);

        // Skip over the tag.
        read_buf.advance(key_len(tag));

        let recovered_value = read_u8_32(WireType::LengthDelimited, &mut read_buf).unwrap();
        assert_eq!(value, recovered_value);

        // All bytes should have been read.
        assert_eq!(read_buf.remaining(), 0);
    }
}
