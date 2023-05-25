#!/bin/bash

set -exo pipefail

export GO111MODULES=on

# Change to tools directory (to avoid modifying go.mod)
cd tools

# Install needed tools
cat tools.go | grep _ | awk -F'"' '{print $2}' | xargs -tI % go install %
