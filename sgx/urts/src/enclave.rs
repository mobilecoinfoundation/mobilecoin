// Copyright (C) 2017-2018 Baidu, Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use mc_sgx_types::*;
use std::{
    ffi::{CStr, CString},
    io,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

///
/// Loads the enclave using its file name and initializes it using a launch token.
///
/// # Description
///
/// The rsgx_create_enclave function will load and initialize the enclave using
/// the enclave file name and a launch token. If the launch token is incorrect, it will
/// get a new one and save it back to the input parameter “token”, and the parameter
/// “updated” will indicate that the launch token was updated.
///
/// If both enclave and launch token are valid, the function will return a value of
/// SGX_SUCCESS. The enclave ID (handle) is returned via the enclave_id parameter.
///
/// The library libsgx_urts.a provides this function to load an enclave with
/// Intel(R) SGX hardware, and it cannot be used to load an enclave linked with
/// the simulation library. On the other hand, the simulation library libsgx_
/// urts_sim.a exposes an identical interface which can only load a simulation
/// enclave. Running in simulation mode does not require Intel(R) SGX hardware/
/// driver. However, it does not provide hardware protection.
///
/// The randomization of the load address of the enclave is dependent on the
/// operating system. The address of the heap and stack is not randomized and is
/// at a constant offset from the enclave base address. A compromised loader or
/// operating system (both of which are outside the TCB) can remove the randomization
/// entirely. The enclave writer should not rely on the randomization
///  of the base address of the enclave.
///
/// # Parameters
///
/// **file_name**
///
/// Name or full path to the enclave image.
///
/// **debug**
///
/// The valid value is 0 or 1.
///
/// 0 indicates to create the enclave in non-debug mode. An enclave created in
/// non-debug mode cannot be debugged.
///
/// 1 indicates to create the enclave in debug mode. The code/data memory
/// inside an enclave created in debug mode is accessible by the debugger or
/// other software outside of the enclave and thus is not under the same memory
/// access protections as an enclave created in non-debug mode.
///
/// Enclaves should only be created in debug mode for debug purposes. A helper
/// macro SGX_DEBUG_FLAG is provided to create an enclave in debug mode. In
/// release builds, the value of SGX_DEBUG_FLAG is 0. In debug and pre-release
/// builds, the value of SGX_DEBUG_FLAG is 1 by default.
///
/// **launch_token**
///
/// A pointer to an sgx_launch_token_t object used to initialize the enclave to be
/// created. Must not be NULL. The caller can provide an all-0 buffer as the sgx_
/// launch_token_t object, in which case, the function will attempt to create a
/// valid sgx_launch_token_t object and store it in the buffer. The caller should
/// store the sgx_launch_token_t object and re-use it in future calls to create the
/// same enclave. Certain platform configuration changes can invalidate a previously
/// stored sgx_launch_token_t object. If the token provided is not valid,
/// the function will attempt to update it to a valid one.
///
/// **launch_token_updated**
///
/// The output is 0 or 1. 0 indicates the launch token has not been updated. 1
/// indicates the launch token has been updated.
///
/// **misc_attr**
///
/// A pointer to an sgx_misc_attribute_t structure that receives the misc select
/// and attributes of the enclave.
///
/// # Requirements
///
/// Header: sgx_urts.h
///
/// Library: libsgx_urts.a
///
/// # Return value
///
/// The sgx_enclave_id_t returned.
///
/// # Errors
///
/// **SGX_ERROR_INVALID_ENCLAVE**
///
/// The enclave file is corrupted.
///
/// **SGX_ERROR_INVALID_PARAMETER**
///
/// The ‘enclave_id’, ‘updated’ or ‘token’ parameter is NULL.
///
/// **SGX_ERROR_OUT_OF_MEMORY**
///
/// Not enough memory available to complete rsgx_create_enclave().
///
/// **SGX_ERROR_ENCLAVE_FILE_ACCESS**
///
/// The enclave file can’t be opened. It may be caused by enclave file not being
/// found or no privilege to access the enclave file.
///
/// **SGX_ERROR_INVALID_METADATA**
///
/// The metadata embedded within the enclave image is corrupt or missing.
///
/// **SGX_ERROR_INVALID_VERSION**
///
/// The enclave metadata version (created by the signing tool) and the untrusted
/// library version (uRTS) do not match.
///
/// **SGX_ERROR_INVALID_SIGNATURE**
///
/// The signature for the enclave is not valid.
///
/// **SGX_ERROR_OUT_OF_EPC**
///
/// The protected memory has run out. For example, a user is creating too many
/// enclaves, the enclave requires too much memory, or we cannot load one of the
/// Architecture Enclaves needed to complete this operation.
///
/// **SGX_ERROR_NO_DEVICE**
///
/// The Intel SGX device is not valid. This may be caused by the Intel SGX driver
/// not being installed or the Intel SGX driver being disabled.
///
/// **SGX_ERROR_MEMORY_MAP_CONFLICT**
///
/// During enclave creation, there is a race condition for mapping memory
/// between the loader and another thread. The loader may fail to map virtual
/// address. If this error code is encountered, create the enclave again.
///
/// **SGX_ERROR_DEVICE_BUSY**
///
/// The Intel SGX driver or low level system is busy when creating the enclave. If
/// this error code is encountered, we suggest creating the enclave again.
///
/// **SGX_ERROR_MODE_INCOMPATIBLE**
///
/// The target enclave mode is incompatible with the mode of the current RTS.
/// For example, a 64-bit application tries to load a 32-bit enclave or a simulation
/// uRTS tries to load a hardware enclave.
///
/// **SGX_ERROR_SERVICE_UNAVAILABLE**
///
/// rsgx_create_enclave() needs the AE service to get a launch token. If the
/// service is not available, the enclave may not be launched.
///
/// **SGX_ERROR_SERVICE_TIMEOUT**
///
/// The request to the AE service timed out.
///
/// **SGX_ERROR_SERVICE_INVALID_PRIVILEGE**
///
/// The request requires some special attributes for the enclave, but is not privileged.
///
/// **SGX_ERROR_NDEBUG_ENCLAVE**
///
/// The enclave is signed as a product enclave and cannot be created as a debuggable enclave.
///
/// **SGX_ERROR_UNDEFINED_SYMBOL**
///
/// The enclave contains an undefined symbol.
/// The signing tool should typically report this type of error when the enclave is
/// built.
///
/// **SGX_ERROR_INVALID_MISC**
///
/// The MiscSelct/MiscMask settings are not correct.
///
/// **SGX_ERROR_UNEXPECTED**
///
/// An unexpected error is detected.
///
pub fn rsgx_create_enclave(
    file_name: &CStr,
    debug: i32,
    launch_token: &mut sgx_launch_token_t,
    launch_token_updated: &mut i32,
    misc_attr: &mut sgx_misc_attribute_t,
) -> SgxResult<sgx_enclave_id_t> {
    let mut enclave_id: sgx_enclave_id_t = 0;
    let ret = unsafe {
        sgx_create_enclave(
            file_name.as_ptr() as *const c_schar,
            debug as int32_t,
            launch_token as *mut sgx_launch_token_t,
            launch_token_updated as *mut int32_t,
            &mut enclave_id as *mut sgx_enclave_id_t,
            misc_attr as *mut sgx_misc_attribute_t,
        )
    };
    match ret {
        sgx_status_t::SGX_SUCCESS => Ok(enclave_id),
        _ => Err(ret),
    }
}

///
/// The function destroys an enclave and frees its associated resources.
///
/// # Description
///
/// The rsgx_destroy_enclave function destroys an enclave and releases its
/// associated resources and invalidates the enclave ID or handle.
///
/// The function will block until no other threads are executing inside the enclave.
///
/// It is highly recommended that the sgx_destroy_enclave function be
/// called after the application has finished using the enclave to avoid possible
/// deadlocks.
///
/// # Parameters
///
/// **enclave_id**
///
/// An enclave ID or handle that was generated by rsgx_create_enclave.
///
/// # Requirements
///
/// Header: sgx_urts.h
///
/// Library: libsgx_urts.a
///
/// # Errors
///
/// **SGX_ERROR_INVALID_ENCLAVE_ID**
///
/// The enclave ID (handle) is not valid. The enclave has not been loaded or the
/// enclave has already been destroyed.
///
pub fn rsgx_destroy_enclave(enclave_id: sgx_enclave_id_t) -> SgxError {
    let ret = unsafe { sgx_destroy_enclave(enclave_id) };
    match ret {
        sgx_status_t::SGX_SUCCESS => Ok(()),
        _ => Err(ret),
    }
}

fn cstr(path: &Path) -> io::Result<CString> {
    Ok(CString::new(path.as_os_str().as_bytes())?)
}

#[derive(Default, Debug)]
pub struct SgxEnclave {
    id: sgx_enclave_id_t,
    debug: i32,
    path: PathBuf,
}

impl SgxEnclave {
    pub fn create<P: AsRef<Path>>(
        file_name: P,
        debug: i32,
        launch_token: &mut sgx_launch_token_t,
        launch_token_updated: &mut i32,
        misc_attr: &mut sgx_misc_attribute_t,
    ) -> SgxResult<SgxEnclave> {
        let path: CString =
            cstr(file_name.as_ref()).map_err(|_| sgx_status_t::SGX_ERROR_INVALID_ENCLAVE)?;

        let enclave = rsgx_create_enclave(
            path.as_c_str(),
            debug,
            launch_token,
            launch_token_updated,
            misc_attr,
        )
        .map(|eid| SgxEnclave {
            id: eid,
            debug,
            path: file_name.as_ref().to_owned(),
        })?;

        enclave.init();
        Ok(enclave)
    }

    pub fn destroy(self) {
        // destroy takes ownership over self, so it
        // will be dropped (and the enclave destroyed)
        // before this function returns.
    }

    pub fn geteid(&self) -> sgx_enclave_id_t {
        self.id
    }

    fn exit(&self) {}

    fn init(&self) {
        // Store enclave id -> pathbuf in the map, for backtrace functionality
        #[cfg(feature = "backtrace")]
        self.store_id_and_path();
    }

    #[cfg(feature = "backtrace")]
    fn store_id_and_path(&self) {
        let mut lk = crate::backtrace::ENCLAVE_PATH_MAP
            .lock()
            .expect("Could not lock enclave path map!");
        let maybe_old_path = lk.insert(self.id, self.path.clone());
        if let Some(old_path) = maybe_old_path {
            panic!(
                "The eid is already in the enclave path map! eid: {} old_path: {} new_path: {}",
                self.id,
                old_path.display(),
                self.path.display()
            );
        }
    }
}

impl Drop for SgxEnclave {
    fn drop(&mut self) {
        self.exit();
        let _ = rsgx_destroy_enclave(self.id);
    }
}
