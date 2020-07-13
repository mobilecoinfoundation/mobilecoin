// Copyright (c) 2018-2020 MobileCoin Inc.

use libc::uintptr_t;
/// This module implements backtrace *tracing* in sgx
///
/// This is based largely on fortanix impl of `unwind_backtrace` function, see
/// fortanix impl of `unwind_backtrace` src/libstd/sys/sgx/backtrace.rs
///
/// To see where it is used, check
/// (1) src/libstd/sys_common/backtrace.rs `_print` function
/// (2) Caller of that in `panicking.rs` in the default hook
///
//use sys_mc_common::backtrace::Frame;
use libc::Frame;
use unwind as uw;
// TODO(chris) use image_base
//use sys::sgx::abi::mem::image_base;

struct Context<'a> {
    idx: usize,
    frames: &'a mut [Frame],
}

#[derive(Debug)]
pub struct UnwindError(uw::_Unwind_Reason_Code);

/*
impl Error for UnwindError {
    fn description(&self) -> &'static str {
        "unexpected return value while unwinding"
    }
}

impl ::fmt::Display for UnwindError {
    fn fmt(&self, f: &mut ::fmt::Formatter) -> ::fmt::Result {
        write!(f, "{}: {:?}", self.description(), self.0)
    }
}
*/

/// unwind_backtrace writes the backtrace for the current thread
/// into a &mut slice of frames
///
/// It returns the number of frames written, or an error if unwinding failed.
///
#[inline(never)] // this function call can be skipped it when tracing.
pub fn unwind_backtrace(frames: &mut [Frame]) -> Result<usize, UnwindError> {
    let mut cx = Context { idx: 0, frames };
    let result_unwind =
        unsafe { uw::_Unwind_Backtrace(trace_fn, &mut cx as *mut Context as *mut libc::c_void) };
    // See libunwind:src/unwind/Backtrace.c for the return values.
    // No, there is no doc.
    match result_unwind {
        // These return codes seem to be benign and need to be ignored for backtraces
        // to show up properly on all tested platforms.
        uw::_URC_END_OF_STACK | uw::_URC_FATAL_PHASE1_ERROR | uw::_URC_FAILURE => Ok(cx.idx),
        _ => Err(UnwindError(result_unwind)),
    }
}

extern "C" fn trace_fn(
    ctx: *mut uw::_Unwind_Context,
    arg: *mut libc::c_void,
) -> uw::_Unwind_Reason_Code {
    let cx = unsafe { &mut *(arg as *mut Context) };
    if cx.idx >= cx.frames.len() {
        return uw::_URC_NORMAL_STOP;
    }

    let mut ip_before_insn = 0;
    let mut ip = unsafe { uw::_Unwind_GetIPInfo(ctx, &mut ip_before_insn) as *mut libc::c_void };
    if !ip.is_null() && ip_before_insn == 0 {
        // this is a non-signaling frame, so `ip` refers to the address
        // after the calling instruction. account for that.
        ip = (ip as usize - 1) as *mut _;
    }

    let symaddr = unsafe { uw::_Unwind_FindEnclosingFunction(ip) } as uintptr_t;
    // Note(chris): Now we have the actual address at which the function exists
    // while the enclave is running, but what is more useful is to subtract
    // the base address of the image (where the enclave.so starts).
    // This allows to symbolicate against an enclave.so with debugging info,
    // because it will match the addreses in elf, since enclave is all -fPIC.
    // Note(chris): If the enclave will start implementing some kind of ASLR
    // e.g. SGX-Shield
    // then that will also need to be accounted for here if we want backtraces
    // to still work
    let adjusted_symaddr = symaddr.wrapping_sub(image_base_addr());
    // See also: https://github.com/rust-lang/rust/blob/master/src/libstd/sys/sgx/backtrace.rs#L87
    cx.frames[cx.idx] = Frame {
        symbol_addr: adjusted_symaddr as *mut u8,
        exact_position: ip as *mut u8,
        inline_context: 0,
    };
    cx.idx += 1;

    uw::_URC_NO_REASON
}

// Note(chris):
// This code relies on the existence of the linker line
// 	-Wl,--defsym,__ImageBase=0
// in our makefile
// We inherited this from Rust-sgx-sdk, and Yu Ding confirmed that he inherited
// that from sample code in intel sgx sdk makefiles.
//
// I have confirmed that in nm and objdump, the enclave.so file always has
// __ImageBase at address 0
//
// See also fortanix ABI: `image_base()` function:
// https://github.com/rust-lang/rust/blob/master/src/libstd/sys/sgx/abi/mem.rs
#[inline(always)]
fn image_base_addr() -> uintptr_t {
    let base;
    unsafe { llvm_asm!("lea __ImageBase(%rip),$0":"=r"(base)) };
    base
}
