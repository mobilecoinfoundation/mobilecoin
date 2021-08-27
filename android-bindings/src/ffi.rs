// Copyright (c) 2018-2021 The MobileCoin Foundation

//! FFI support utilities.

use crate::error::McError;
use jni::{objects::JObject, JNIEnv};
use std::{
    any::Any,
    panic::{catch_unwind, AssertUnwindSafe, UnwindSafe},
    process::abort,
};

/// The default field name in the Java world that holds a pointer to the Rust
/// object.
pub const RUST_OBJ_FIELD: &str = "rustObj";

/// Performs an FFI-wrapped call with a return value that implements Default.
/// See `jni_ffi_call_or` for more details.
pub fn jni_ffi_call<R: Default>(
    env: &JNIEnv,
    f: impl (FnOnce(&JNIEnv) -> Result<R, McError>) + UnwindSafe,
) -> R {
    jni_ffi_call_or(|| Ok(R::default()), &env, f)
}

/// Performs an FFI-wrapped call. The purpose of this is to provide a wrapper
/// for functions that return Result<_, McError>, converting Err(McError) into a
/// Java exception. Since JNI's API for throwing an exception (`throw_new`) does
/// not have a way of aborting execution, we are still forced to come up with a
/// return value even though it would never make it to Java-land. This is the
/// purpose of the `or_err` argument.
pub fn jni_ffi_call_or<R>(
    on_err: impl (FnOnce() -> Result<R, McError>) + UnwindSafe,
    env: &JNIEnv,
    f: impl (FnOnce(&JNIEnv) -> Result<R, McError>) + UnwindSafe,
) -> R {
    let result = catch_unwind(|| f(env)).unwrap_or_else(|panic_error| {
        // We assert `panic_error` is unwind safe because, since we won't be modifying
        // it, we know that no harm will come if we panic while trying to
        // process it.
        let panic_error = AssertUnwindSafe(panic_error);
        catch_unwind(|| Err(McError::Panic(format_panic(panic_error.0))))
            // If this also panics then we just abort because at this point it's likely
            // something terrible has gone wrong and the situation is no longer tenable.
            .unwrap_or_else(|_| abort())
    });

    match result {
        Ok(val) => val,
        Err(err) => {
            // TODO We could throw an object that has an actual enum that matches McError if
            // we need more usable info.
            env.throw_new(
                "java/lang/Exception",
                format!("jni_ffi_call exception: {}", err),
            )
            .expect("throw_new failed");

            // JNI still requires us to return something even after throwing an exception.
            // If this fails, we have nothing we could return so we panic.
            on_err().expect("failed calling on_err")
        }
    }
}

/// Gets a u64 value out of a Java BigInteger object.
pub fn jni_big_int_to_u64(env: &JNIEnv, obj: JObject) -> Result<u64, McError> {
    let jni_big_int_bytes = env.call_method(obj, "toByteArray", "()[B", &[])?;
    let mut bytes_vec = env
        .convert_byte_array(jni_big_int_bytes.l()?.into_inner())?
        .to_vec();

    // bytes_vec is a big endian representation of the BigInteger value.
    // strip any leading zeros - this is needed since for u64::max this method
    // returns [0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff].
    while bytes_vec.get(0) == Some(&0) {
        bytes_vec.remove(0);
    }

    // Convert to u64.
    if bytes_vec.len() > 8 {
        return Err(McError::Other(format!(
            "value is bigger than u64::max ({:?})",
            bytes_vec
        )));
    }

    let mut be_bytes = [0; 8];
    be_bytes[8 - bytes_vec.len()..].copy_from_slice(&bytes_vec[..]);
    Ok(u64::from_be_bytes(be_bytes))
}

/// Utility method to convert a panic error, as represented by Rust's unwinding
/// mechanism into a meaningful string that can be displayed to the user.
fn format_panic(panic_error: Box<dyn Any>) -> String {
    let panic_error = match panic_error.downcast::<String>() {
        Ok(msg) => return msg.to_string(),
        Err(panic_error) => panic_error,
    };

    let _panic_error = match panic_error.downcast::<&'static str>() {
        Ok(msg) => return msg.to_string(),
        Err(panic_error) => panic_error,
    };

    "Panic happened, reason was not a string.".to_owned()
}
