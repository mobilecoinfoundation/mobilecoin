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
protoc --proto_path=./consensus/api/proto/ --proto_path=./api/proto/ --descriptor_set_out=consensus_common.protoset --include_imports ./consensus/api/proto/consensus_common.proto
```

Try it out with:
```commandline
grpcurl  -protoset ./consensus_common.protoset node1.test.mobilecoin.com:443 consensus_common.BlockchainAPI.GetLastBlockInfo
```
