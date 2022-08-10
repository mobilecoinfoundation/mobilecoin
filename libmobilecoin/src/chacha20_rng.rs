use crate::common::*;
use mc_util_ffi::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use rand_core::RngCore;
use std::sync::Mutex;
use std::convert::TryInto;


pub type McChaCha20Rng = ChaCha20Rng;

pub struct McU128 {
    pub bytes: [u8; 16]    
}

impl McU128 {
    pub fn from_u128(val: u128) -> McU128 {
        McU128 {
            bytes: val.to_be_bytes(),
        }
    }

    pub fn to_u128(&self) -> u128 {
        u128::from_be_bytes(self.bytes)
    }
}

impl IntoFfi<McU128> for McU128 {
    #[inline]
    fn error_value() -> McU128 {
        McU128 {
            bytes: [u8::MAX; 16],
        }
    }

    #[inline]
    fn into_ffi(self) -> McU128 {
        self
    }
}

impl_into_ffi!(FfiOwnedPtr<McU128>);
impl_into_ffi!(Mutex<McChaCha20Rng>);

#[no_mangle]
pub extern "C" fn mc_chacha20_rng_create_with_long(long_val: u64) -> FfiOptOwnedPtr<Mutex<McChaCha20Rng>> {
    ffi_boundary(|| {
        Mutex::new(McChaCha20Rng::seed_from_u64(long_val))
    })
}

#[no_mangle]
pub extern "C" fn mc_chacha20_rng_create_with_bytes(bytes: FfiRefPtr<McBuffer>) -> FfiOptOwnedPtr<Mutex<McChaCha20Rng>> {
    ffi_boundary(|| {
        let bytes: [u8; 32] = bytes.as_slice().try_into().expect("seed size must be 32 bytes");
        Mutex::new(McChaCha20Rng::from_seed(bytes))
    })
}

#[no_mangle]
pub extern "C" fn mc_chacha20_get_word_pos(
    chacha20_rng: FfiMutPtr<Mutex<McChaCha20Rng>>,
    out_word_pos: FfiMutPtr<McMutableBuffer>,
) {
    ffi_boundary(|| {
        let word_pos = chacha20_rng.lock().unwrap().get_word_pos();
        let mc_u128 = McU128::from_u128(word_pos);

        let out_word_pos = out_word_pos
            .into_mut()
            .as_slice_mut_of_len(16)
            .expect("word_pos length is not exaclty 16 bytes");

        out_word_pos.copy_from_slice(&mc_u128.bytes);
    })
}

#[no_mangle]
pub extern "C" fn mc_chacha20_set_word_pos(chacha20_rng: FfiMutPtr<Mutex<McChaCha20Rng>>, bytes: FfiRefPtr<McBuffer>) {
    ffi_boundary(|| {
        let mc_u128 = McU128 {
            bytes: bytes.as_slice().try_into().expect("word_pos length is not exaclty 16 bytes")
        };
        let word_pos = mc_u128.to_u128();
        chacha20_rng.lock().unwrap().set_word_pos(word_pos);
    })
}

#[no_mangle]
pub extern "C" fn mc_chacha20_rng_next_long(chacha20_rng: FfiMutPtr<Mutex<McChaCha20Rng>>) -> u64 {
    ffi_boundary(|| {
        let next = chacha20_rng.lock().unwrap().next_u64();
        next
    })
}

#[no_mangle]
pub extern "C" fn mc_chacha20_rng_free(chacha20_rng: FfiOptOwnedPtr<Mutex<McChaCha20Rng>>) {
    ffi_boundary(|| {
        let _ = chacha20_rng;
    })
}