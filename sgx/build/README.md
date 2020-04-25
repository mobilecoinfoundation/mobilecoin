mc-sgx-build
=========

Helper objects for `build.rs` scripts related to sgx enclaves

This crate supports the following build strategy:

- Enclave crate is responsible to build a statically-linked `no_std` library `enclave.so`
- Enclave crate `build.rs` is responsible to run Intel edger8r tool, both trusted and untrusted codegen.
  It places untrusted results in a new subdirectory of its `target` directory, named `target/untrusted`
- Server crate `build.rs` is responsible to `cargo build` the enclave
- Server crate `build.rs` is responsible to sign the enclave and move it into its `target` dir
- Server crate `build.rs` is responsbile to build and link the edger8r untrusted output

The rationale here is
- We must avoid feature contamination between the server and enclave builds so we want these to be distinct workspaces / cargo invocations.
- `cargo` generally wants that outputs of `build.rs` should go in `OUT_DIR` of current crate, for stale detection to work properly
- In cargo, there is no "post-build` script, so the enclave cannot sign and measure itself.
  (As a workaround we could contemplate making a third crate the `enclave_package`, which depends on `enclave`)
- In cargo, `build.rs` can post values, as environment variables, to `build.rs` of crates that depend on them, but not the reverse direction
- In cargo, it's not straightforward for the enclave crate to tell the server `build.rs` about paths to `.edl` files, if the server is shelling out to `cargo build`
  the enclave. So it's simpler for enclave crate to do all of the edger8r stuff.
- Untrusted codegen is placed in `src/enclave/target/untrusted` because then `cargo clean` will work correctly.
  If it goes in `OUT_DIR` instead then we must somehow communicate the value of `OUT_DIR` during `build.rs` of enclave to the `build.rs` of consensus server.

This crate also provides support that helps `build.rs` emit appropriate linker directives
when linking into Intel SDK C libraries.

---

This crate is largely factored out of Intel example enclave build (https://github.com/intel/linux-sgx/blob/master/SampleCode/SampleEnclave/Makefile),
and it relies on some of the same environment variables

- `SGX_SDK`: Path to Intel SGX SDK installation. Defaults to /opt/intel/sgxsdk
- `SGX_MODE`: Whether we are in SW or HW mode. In SW mode the `_sim` libraries are used. This is required and in scripts, HW is the recommended safe default.
- `LD`: Invoked to link the enclave to intel sdk
