# Attested gRPC APIs

The APIs contained within this module provide a common network API to entities which want to perform a key exchange with an enclave, and transmit instructions over a secure channel.

This crate provides two API methods, `Auth`, and `Call`, which are more extensively documented alongside the calls in question.

## Auth

This method takes an `AuthRequest` structure, which contains the DER serialized ephemeral public key of the initiator and the algorithm selection, and a transcript hash. It returns an `AuthResponse` structure, which contains the DER-serialized ephemeral public key of the responder, the next step of the transcript hash, and an encrypted blob containing the server's DER-encoded static, public-identity key, an updated transcript hash (including the identity key), and a second, inner cipher text containing the server's cached IAS verification report.

## Call

This method has different behavior depending on the context. In all cases it will use the outer, plaintext transcript from `AuthResponse` as the session_id, and an encrypted payload. The first encrypted message after an `Auth` call will contain the client's DER-encoded, static, public-identity key, an updated transcript, and an inner ciphertext containing either a cryptonote transaction (when called from a client), or a cached IAS verification report and forwarded transaction (when called from another node)

The next request to the Call method should contain only the encrypted transaction.

## Optional: grpcurl for command line queries

Optionally, you can install [grpcurl](https://github.com/fullstorydev/grpcurl), a command-line utility for convenient
 `curl`-like interaction with a gRPC server. It requires Go.

```commandline
sudo apt  install golang-go
go get github.com/fullstorydev/grpcurl
go install github.com/fullstorydev/grpcurl/cmd/grpcurl
```

You may need to add these binaries to your path; for example, by adding these lines to your `.bashrc` file:

```commandline
export GOPATH=$HOME/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
```

In order to use `grpcurl`, you must generate a `.protoset` file describing the service:

```commandline
protoc --proto_path=./attest/api/proto/ --descriptor_set_out=attest_api.protoset --include_imports ./attest/api/proto/attest.proto
```

Try it out with:
```commandline
grpcurl -protoset ./attest_api.protoset list
```
