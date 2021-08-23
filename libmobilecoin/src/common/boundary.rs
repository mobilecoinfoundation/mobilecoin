// Copyright (c) 2018-2021 The MobileCoin Foundation

use super::{IntoFfi, McError};
use crate::LibMcError;
use mc_util_ffi::{FfiOptMutPtr, FfiOptOwnedPtr, FfiOwnedPtr};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    process::abort,
};

/// This function should be used as the outer-most "layer" protecting Rust code
/// from unwinding across the FFI boundary in the event of a panic. All Rust
/// code in FFI functions (e.g. `extern "C"` functions) should be executed
/// within the closure passed as parameter `f`. This function ensures FFI safety
/// by catching unwind panics, logging the panic, and returning the
/// sentinel error value returned by a call to `R::error_value()`.
pub(crate) fn ffi_boundary<R, I>(f: impl (FnOnce() -> R)) -> I
where
    R: IntoFfi<I>,
{
    ffi_boundary_impl(|| {
        let result = f().into_ffi();
        Ok(result)
    })
    .unwrap_or_else(|err| {
        log_error(err);
        R::error_value()
    })
}

/// This function should be used as the outer-most "layer" protecting Rust code
/// from unwinding across the FFI boundary in the event of a panic. All Rust
/// code in FFI functions (e.g. `extern "C"` functions) should be executed
/// within the closure passed as parameter `f`. This function ensures FFI safety
/// by catching unwind panics, saving the panic as a `LibMcError` to the
/// `out_error` (if `out_error` is non-null), and returning the sentinel error
/// value returned by a call to `R::error_value()`.
pub(crate) fn ffi_boundary_with_error<R, I>(
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
    f: impl (FnOnce() -> Result<R, LibMcError>),
) -> I
where
    R: IntoFfi<I>,
{
    ffi_boundary_impl(|| {
        let result = f()?.into_ffi();
        Ok(result)
    })
    .unwrap_or_else(|err| {
        set_error_or_log(err, out_error);
        R::error_value()
    })
}

fn ffi_boundary_impl<R>(f: impl (FnOnce() -> Result<R, LibMcError>)) -> Result<R, LibMcError> {
    // Run f within catch_unwind
    //
    // Note: this is using AssertUnwindSafe because some of the TransactionBuilder
    // types are abstracted behind Box<dyn ... + Send + Sync>, but rust does not
    // allow such types to be UnwindSafe because they may exhibit interior
    // mutability. OTOH if we do not put + Send + Sync, then it is illegal to
    // put TransactionBuilder behind a Mutex, which prevents the android
    // bindings from building.
    //
    // The reason we use Box<dyn + ...> at all is to avoid making everything
    // a generic parameter of transaction builder, which multiplies the number of
    // types that might have to have cross-language bindings.
    //
    // UnwindSafe is too restrictive -- the goal of UnwindSafe is that if a panic is
    // caught, we cannot "easily" observe a broken invariant. However, the only
    // thing we actually need at an ffi boundary is to prevent unwinding across
    // stackframes into swift etc.
    catch_unwind(AssertUnwindSafe(f))
        // Return a `LibMcError` if we panic. However, we still need to be mindful of panics while
        // formatting the panic error so that we don't accidentally unwind across the FFI boundary.
        .unwrap_or_else(|panic_error| {
            // We assert `panic_error` is unwind safe because, since we won't be modifying
            // it, we know that no harm will come if we panic while trying to
            // process it.
            let panic_error = AssertUnwindSafe(panic_error);
            catch_unwind(|| Err(LibMcError::Panic(format!("{:?}", panic_error.0))))
                // If this also panics then we just abort because at this point it's likely
                // something terrible has gone wrong and the situation is no longer tenable.
                .unwrap_or_else(|_| abort())
        })
}

fn set_error_or_log(err: LibMcError, out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>) {
    error_handling_ffi_boundary(|| {
        if let Some(error) = out_error.into_mut() {
            *error = FfiOwnedPtr::new(McError::from(err)).into();
        } else {
            eprintln!("LibMobileCoin Error: {}", err);
        }
    });
}

fn log_error(err: LibMcError) {
    error_handling_ffi_boundary(|| eprintln!("LibMobileCoin Error: {}", err))
}

fn error_handling_ffi_boundary(f: impl FnOnce()) {
    let _ = ffi_boundary_impl(|| {
        f();
        Ok(())
    })
    // If we fail while handling the original error, it necessarily must have been from a panic
    // while doing so (and possibly we panicked while trying to format the panic).
    // Let's try to just print out the panic. If we panic while doing that, not much can be done
    // except fail silently and move on (we could also abort, but we're trying to avoid doing that).
    .map_err(|panic_error| {
        let panic_error = AssertUnwindSafe(panic_error);
        // guard against panics while printing
        let _ = catch_unwind(|| {
            let panic_error = panic_error.0;
            // In theory, we should still have the original err at this point, but move
            // semantics make it difficult to hold onto if we panicked.
            eprintln!(
                "LibMobileCoin panicked during error handling: {}",
                panic_error
            );
        });
    });
}
