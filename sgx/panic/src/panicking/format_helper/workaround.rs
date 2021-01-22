// Copyright (c) 2018-2021 The MobileCoin Foundation

// Using the rust core::fmt library to format to a fixed buffer on the stack,
// in a no_std context, is unfortunately difficult.
// While code like this will work with `std::io`:
//
// let mut buf = [0u8; 1024];
// write!(&mut buf, "foo bar {}", 45).unwrap();
//
// it does not work with core::fmt because the core::fmt::Write trait has not
// been specialized for &mut [u8], as the std::io::Write trait has.
// It appears that there is no technical reason for this.
//
// However we cannot directly specialize the trait ourselves because the trait
// belongs to core and the type is a built-in. We must create a wrapper struct
// specific to our crate.
//
// This is described by Shepmaster in this SO post:
// https://stackoverflow.com/questions/39488327/how-to-write-an-integer-as-a-string-to-a-byte-array-with-no-std
// and we are taking his wrapper implementation to accomplish this, however,
// we fixup some of the error handling around it (bounds checking)

use core::fmt;

pub struct Wrapper<'a> {
    buf: &'a mut [u8],
    offset: usize,
}

impl<'a> Wrapper<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Wrapper { buf, offset: 0 }
    }

    pub fn get_buf(&mut self) -> &mut [u8] {
        self.buf
    }
    pub fn get_offset(&self) -> usize {
        self.offset
    }
}

impl<'a> fmt::Write for Wrapper<'a> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();

        // Skip over already-copied data
        let remainder = &mut self.buf[self.offset..];
        // Check if there is space remaining (return error instead of panicking)
        if remainder.len() < bytes.len() {
            return Err(core::fmt::Error);
        }
        // Make the two slices the same length
        let remainder = &mut remainder[..bytes.len()];
        // Copy
        remainder.copy_from_slice(bytes);

        // Update offset to avoid overwriting
        self.offset += bytes.len();

        Ok(())
    }
}
