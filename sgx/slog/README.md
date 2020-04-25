mc-sgx-slog
=========

This crate provides glueing code for using `slog` inside an enclave. It uses an OCALL to forward log data to untrusted code.

It is expected that this will only be used for debugging during development.
