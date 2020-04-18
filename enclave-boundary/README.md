## mc-enclave-boundary

This crate contains infrastructure to (effectively) allow making ECALL's with
variable return buffer size.

- Intel ECALL's are C API definitions, but memory between enclave and caller is strictly
  separated. So if an ECALL's semantics are that it returns a buffer to the caller, the caller must allocate it.
- If the caller cannot know in advance how large a buffer is needed, which is typical,
  then the only way forward is some sort of two-step calling process.

This crate provides details for such a two-step calling process.

We provide for the enclave a "retry buffer" which queues up buffers that
the untrusted still needs to obtain. And we provide a helper for untrusted code
which carries out this retry protocol.

The "retry buffer" is expected to be instantiated as a lazy static called directly from the ECALL implementation
in trusted.

The retry buffer must be provided with a handler function which takes bytes and produces bytes or an SGX error code.
Typically it is expected to deserialize the input, do something, and then serialize a Rust Result type.
These serialization details represent another layer of abstraction over what code exists in this crate.
