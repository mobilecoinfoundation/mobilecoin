#!/bin/bash
set -ex

IMAGE=$(./mob default-tag)
./mob image --verbose
docker image push $IMAGE
# Legacy tag
docker tag $IMAGE gcr.io/mobilenode-211420/mobilenode:builder-install
