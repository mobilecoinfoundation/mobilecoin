// Copyright (c) 2018-2021 The MobileCoin Foundation

// Expose retrying wrappers for RDRAND 32 and 64 versions as appropriate
// Note: Only expeted to compile on x86 and x86_64

// Intel recommends doing a loop of 10 retries when using rdrand
// https://software.intel.com/en-us/articles/intel-digital-random-number-generator-drng-software-implementation-guide
const RETRIES: i32 = 10;

#[inline]
pub fn next_rdrand_u32_or_panic() -> u32 {
    // Get rdrand compiler intrinsics for 32 bits
    #[cfg(target_arch = "x86")]
    use core::arch::x86::_rdrand32_step;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::_rdrand32_step;

    let mut result: u32 = 0;
    let mut retries = RETRIES;
    while retries > 0 {
        if 1 == unsafe { _rdrand32_step(&mut result) } && result != 0 && result != 0xFFFF_FFFFu32 {
            return result;
        }
        retries -= 1;
    }
    panic!("_rdrand32_step unexpectedly failed {} times", RETRIES);
}

#[cfg(target_arch = "x86_64")]
#[inline]
pub fn next_rdrand_u64_or_panic() -> u64 {
    // Get rdrand compiler intrinsic for 64 bits
    use core::arch::x86_64::_rdrand64_step;

    let mut result: u64 = 0;
    let mut retries = RETRIES;
    while retries > 0 {
        if 1 == unsafe { _rdrand64_step(&mut result) }
            && result != 0
            && result != 0xFFFF_FFFF_FFFF_FFFFu64
        {
            return result;
        }
        retries -= 1;
    }
    panic!("_rdrand64_step unexpectedly failed {} times", RETRIES);
}
