#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Generate metadata for GitHub Actions workflows.
#

set -e

export TMPDIR=".tmp"

is_set()
{
  var_name="${1}"

  if [ -z "${!var_name}" ]; then
    echo "${var_name} is not set."
    exit 1
  fi
}

normalize_ref_name()
{
    name="${1}"

    echo "${name}" | sed -E 's/(feature|release)\///' | sed -e 's/[._/]/-/g'
}

# check for github reference variables.
is_set GITHUB_REF_NAME
is_set GITHUB_REF_TYPE
is_set GITHUB_RUN_NUMBER
is_set GITHUB_SHA

# Make sure prefix is less that 18 characters or k8s limits.
namespace_prefix="mc"
sha="sha-${GITHUB_SHA:0:8}"

# Set branch name. Where we get this ref is different for branch, pull_request or delete event
branch="${GITHUB_REF_NAME}"

# Override branch name with head when event is a PR
if [[ -n "${GITHUB_HEAD_REF}" ]]
then
    branch="${GITHUB_HEAD_REF}"
fi

# Override branch with delete ref if set.
if [[ -n "${DELETE_REF_NAME}" ]]
then
    branch="${DELETE_REF_NAME}"
fi

case "${GITHUB_REF_TYPE}" in
    tag)
        # check for valid tag and set outputs
        version="${GITHUB_REF_NAME}"
        if [[ ! "${version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+.* ]]
        then
            echo "GitHub Tag ${version} is not valid semver."
            exit 1
        fi

        if [[ "${version}" =~ - ]]
        then
            echo "Found pre-release tag."
            # set artifact tag
            tag="${version}"
        else
            echo "Found release tag."
            # set artifact tag
            tag="${version}-dev"
        fi

        # Set docker metadata action compatible tag. Short tag + metadata tag.
        docker_tag=$(cat << EOF
type=raw,value=${tag},priority=20
type=raw,value=${tag}.${GITHUB_RUN_NUMBER}.${sha},priority=10
EOF
)

        normalized_tag=$(normalize_ref_name "${tag}")
        namespace="${namespace_prefix}-${normalized_tag}"

        # just make sure we have these set to avoid weird edge cases.
        is_set tag
        is_set docker_tag
    ;;
    # Branches and pull requests will set type as branch.
    # Don't filter on "valid" branches, rely on workflows to filter out their accepted events.
    branch)
        # All branch builds will just have a "dummy" tag.
        version="v0"

        echo "Clean up branch. Remove feature|deploy|release prefix and replace ._/ with -"
        normalized_branch="$(normalize_ref_name "${branch}")"

        # Check and truncate branch name if total tag length exceeds the 63 character K8s label value limit.
        label_limit=63
        version_len=${#version}
        sha_len=${#sha}
        run_number_len=${#GITHUB_RUN_NUMBER}
        # number of separators in tag
        dots=3

        cutoff=$((label_limit - version_len - sha_len - run_number_len - dots))

        if [[ ${#normalized_branch} -gt ${cutoff} ]]
        then
            cut_branch=$(echo "${normalized_branch}" | cut -c -${cutoff})
            echo "Your branch name ${normalized_branch} + metadata exceeds the maximum length for K8s identifiers, truncating to ${cut_branch}"
            normalized_branch="${cut_branch}"
        fi

        echo "Before: '${branch}'"
        echo "After: '${normalized_branch}'"

        # Set artifact tag
        tag="${version}-${normalized_branch}.${GITHUB_RUN_NUMBER}.${sha}"
        # Set docker metadata action compatible tag
        docker_tag="type=raw,value=${tag}"
        # Set namespace from normalized branch value
        namespace="${namespace_prefix}-${normalized_branch}"
    ;;
    *)
        echo "${GITHUB_REF_TYPE} is an unknown GitHub Reference Type"
        exit 1
    ;;
esac

# Set GHA output vars
cat <<EOO >> "${GITHUB_OUTPUT}"
version=${version}
namespace=${namespace}
sha=${sha}
tag=${tag}
docker_tag<<EOF
${docker_tag}
EOF
EOO

cat "${GITHUB_OUTPUT}"
