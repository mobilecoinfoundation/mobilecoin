enclave_connection
==================

Enclave Connection is a medium-level abstraction of an attested connection to an enclave.
It takes the Url and the Grpc object and exposes an API for sending serialized requests
over an encrypted attested channel to the enclave, and returning the result.

When using it in practice, pick a specific enclave, use a grpc channel generated from its
.proto, make attests using the objects in its proto file, and make sure you get the right
measurements, product id, security version.
