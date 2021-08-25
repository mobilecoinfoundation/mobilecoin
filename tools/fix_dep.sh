#!/bin/bash

# This script can be used to scan all Cargo.toml in the project for dependencies
# on an external crate, and set all of the version requirements to be the same.
#
# This might be handy if we are reconfiguring a low level library e.g. serde
# and changing either its versions or its features across the whole project.
#
# Usage:
#   fix_dep.sh rand "0.7"
#     will replace all lines of the form `rand = ...` in any Cargo.toml in the
#     project with `rand = "0.7"`
#
#   fix_dep.sh serde "{ version = \"1.0\", default-features = false }"
#     will replace all lines `serde = ..." in Cargo.toml with
#     `serde = { version = "1.0", default-features = false}`

find . -type f -name "Cargo.toml" -not -path "./cargo/*" -exec sed -i "s|^$1 = .*|$1 = $2|g" {} +
