# mc-consensus-api

gRPC API for client-to-node and node-to-node requests.

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
protoc --proto_path=./src/blockchain_api/proto/ --descriptor_set_out=blockchain_api.protoset --include_imports ./src/blockchain_api/proto/block_headers.proto
```

Try it out with:
```commandline
grpcurl -protoset ./blockchain_api.protoset list
```
