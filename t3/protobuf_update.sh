#!/bin/bash

if ! command -v buf &> /dev/null
then
    echo "buf could not be found. Install with:"
    echo ""
    echo "$ brew install bufbuild/buf/buf"
    echo ""
    echo "then login with"
    echo ""
    echo "$ buf registry login"
    echo ""
    echo "More information about installation can be found in the README.md"
    exit
fi

if ! which protoc &> /dev/null
then
    echo "protoc could not be found. Install with:"
    echo ""
    echo "$ brew install protobuf"
    exit
fi

echo "exporting..."

# generate files from buf.build
buf export buf.build/mobilecoin-inc/trusted-transparent-transactions --output=api/proto

echo "done"
