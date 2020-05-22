#!/bin/sh

case "$(uname -s)" in
  CYGWIN*|MINGW32*|MSYS*|MINGW*)
    py.exe -m grpc_tools.protoc -I../../../../api/proto --python_out=. ../../../../api/proto/external.proto
    py.exe -m grpc_tools.protoc -I../../../../api/proto --python_out=. ../../../../api/proto/blockchain.proto
    py.exe -m grpc_tools.protoc -I../../../../mobilecoind/api/proto -I../../../../consensus/api/proto -I../../../../api/proto --python_out=. --grpc_python_out=. ../../../../mobilecoind/api/proto/mobilecoind_api.proto
  ;;

  *)
    python3 -m grpc_tools.protoc -I../../../../api/proto --python_out=. ../../../../api/proto/external.proto
    python3 -m grpc_tools.protoc -I../../../../api/proto --python_out=. ../../../../api/proto/blockchain.proto
    python3 -m grpc_tools.protoc -I../../../../mobilecoind/api/proto -I../../../../consensus/api/proto -I../../../../api/proto --python_out=. --grpc_python_out=. ../../../../mobilecoind/api/proto/mobilecoind_api.proto
  ;;
esac
