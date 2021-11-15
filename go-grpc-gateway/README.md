go-grpc-gateway
===============

The go-grpc-gateway is a go program that takes HTTP requests and maps them onto grpc
requests corresponding to the mobilecoin and fog APIs. Then it waits for a grpc response
and maps it back onto an HTTP response for the client.

First install go tools using `install_tools.sh`.
The target is built using `build.sh`.
The target works equally well for all fog and consensus servers, being compiled against
all of their proto files.
