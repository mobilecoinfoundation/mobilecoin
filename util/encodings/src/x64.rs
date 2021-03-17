// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Intel x86_64 C Structure Layout Serialization

use alloc::vec;

use alloc::vec::Vec;

/// The size of a u16 on x86_64
pub const INTEL_U16_SIZE: usize = 2;

/// The size of a u32 on x86_64
pub const INTEL_U32_SIZE: usize = 4;

/// The size of a u64 on x86_64
pub const INTEL_U64_SIZE: usize = 8;

/// A trait containing the basic supports necessary to support
/// serialization/deserialization as x64 bytes.
pub trait IntelLayout {
    /// The default size required for the x86_64 C representations of the
    /// underlying structure
    const X86_64_CSIZE: usize;

    /// Retrieve the number of bytes required to represent a structure as it's
    /// underlying bytes
    #[inline(always)]
    fn intel_size(&self) -> usize {
        Self::X86_64_CSIZE
    }
}

/// A trait which creates a new object from a raw byte slice of an x64 C ABI
/// bytes.
pub trait FromX64: IntelLayout + Sized {
    /// The type of errors to be returned
    type Error;

    /// Construct a new object from the given slice
    fn from_x64(src: &[u8]) -> Result<Self, Self::Error>;
}

/// A trait which writes the contents of a structure as x86_64 C ABI bytes.
pub trait ToX64: IntelLayout + Sized {
    /// Write the x86_64 C ABI version of this structure into a byte slice
    fn to_x64(&self, dest: &mut [u8]) -> Result<usize, usize>;

    /// Write the x86_64 C ABI version of this structure into a newly allocated
    /// vector.
    fn to_x64_vec(&self) -> Vec<u8> {
        let mut retval = vec![0u8; self.intel_size()];
        let len = self
            .to_x64(retval.as_mut_slice())
            .expect("Self::intel_size() returned an incorrect value, it should have returned");
        retval.truncate(len);
        retval
    }
}
