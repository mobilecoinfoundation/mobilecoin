#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Generate metadata for GitHub Actions workflows.
#

set -e

export TMPDIR=".tmp"

error_exit()
{
  msg="${1}"

  echo "${msg}" 1>&2
  exit 1
}

is_set()
{
  var_name="${1}"

  if [ -z "${!var_name}" ]; then
    error_exit "${var_name} is not set."
  fi
}

# check for github reference variables.
is_set GITHUB_REF_NAME
is_set GITHUB_REF_TYPE
is_set GITHUB_RUN_NUMBER
is_set GITHUB_SHA

if [[ "${GITHUB_REF_TYPE}" != "branch" ]]
then
    echo "not a 'branch' reference type - ${GITHUB_REF_TYPE}"
    exit 1
fi

# Remove leading branch designator.
branch=$(echo "${GITHUB_REF_NAME}" | sed -E 's/(feature|deploy|release)\///')

if [[ "${GITHUB_REF_NAME}" =~ ^release/ ]]
then
    echo "Release Branch detected: ${GITHUB_REF_NAME}"
    version="${branch}"
    # check to see if remaining version is basic semver
    if [[ ! "${version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
    then
        echo "release/<version> not basic semver: ${version}"
        echo "branch name invalid"
        exit 1
    fi
else
    version="v0.0.0"
    echo "Not a release branch, set default version of v0.0.0"
fi

echo "Clean up branch. Remove feature|deploy|release prefix and replace ._/ with - '${branch}'"
branch=$(echo "${branch}" | sed -e 's/[._/]/-/g')
sha="${GITHUB_SHA:0:8}"

# Set tag/docker_tag
tag="${version}-${branch}.${GITHUB_RUN_NUMBER}.sha-${sha}"
docker_tag="type=raw,value=${tag}"

# override tag/docker_tag for release
if [[ "${GITHUB_REF_NAME}" =~ ^release/ ]]
then
    docker_tag="type=raw,value=${version}-dev,priority=20%0Atype=raw,value=${version}-${GITHUB_RUN_NUMBER}.sha-${sha},priority=10"
    tag=${version}-dev
fi

# Get commit flags
if [ -f "${GITHUB_EVENT_PATH}" ]
then
    # override tag if commit message has [tag="tag"]
    msg=$(jq -r '.head_commit.message' < "${GITHUB_EVENT_PATH}")
    if [[ "${msg}" =~ /\[tag=.*\]/ ]]
    then
        tag=$(echo "${msg}" | sed -r 's/.*\[use=(.*)\].*/\1/')
    fi
fi

echo "::set-output name=version::${version}"
echo "::set-output name=branch::${branch}"
echo "::set-output name=namespace::mc-${branch}"
echo "::set-output name=sha::${sha}"
echo "::set-output name=tag::${tag}"
echo "::set-output name=docker_tag::${docker_tag}"
