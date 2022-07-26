#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Bump cargo versions for packages owned by MobileCoin.
#
# This script requires dasel https://github.com/TomWright/dasel for parsing toml

set -e

usage()
{
    echo "Usage:"
    echo "${0} --current-tag <tag> --new-tag <tag> [--author <author>]"
    echo "    --current-tag - current tag defined in Cargo.toml"
    echo "        as a safeguard against updating packages that are not in sync with the repo version"
    echo "    --new-tag - new tag to replace current"
    echo "    --author - (Optional) author= string to match. Default 'MobileCoin'"
    echo "    --dry-run - (Optional) parse files and show error/actions, but don't change versions"
    echo ""
    echo "Example:"
    echo "${0} --current-tag 1.2.2 --new-tag 1.2.3"
    echo ""
}

is_set()
{
    var_name="${1}"
    if [ -z "${!var_name}" ]
    then
        echo "${var_name} is not set."
        usage
        exit 1
    fi
}

while (( "$#" ))
do
    case "${1}" in
        --help | -h)
            usage
            exit 0
            ;;
        --current-tag)
            current_tag="${2}"
            shift 2
            ;;
        --new-tag)
            new_tag="${2}"
            shift 2
            ;;
        --author)
            author="${2}"
            shift 2
            ;;
        --dry-run)
            dry_run="true"
            shift
            ;;
        *)
            echo "${1} unknown option"
            usage
            exit 1
            ;;
    esac
done

if ! which dasel >/dev/null 2>&1
then
    echo "This script requires dasel https://github.com/TomWright/dasel for parsing toml. Please install it in your PATH"
    exit 1
fi

is_set current_tag
is_set new_tag

# set author
author=${author:-MobileCoin}

# Get list of Cargo.toml files, exclude ./cargo and ./target directories
files=$(find . \( -path ./cargo -o -path ./target \) -prune -o -name Cargo.toml -print)

for f in ${files}
do
    echo "-- Checking File: ${f}"
    # does the authors block exist?
    if dasel get -f "${f}" -m --plain -s '.package.authors.[*]' >/dev/null 2>&1
    then
        # Get authors for package and make sure the list matches --author
        authors=$(dasel get -f "${f}" -m --plain -s '.package.authors.[*]')
        if [[ "${authors}" == "${author}" ]]
        then
            # Check to make sure current package version matches current_tag
            p_version=$(dasel get -f "${f}" -m --plain -s '.package.version')
            if [[ "${p_version}" == "${current_tag}" ]]
            then
                # I would use dasel here, but the output file ends up with properties in alpha order. this will make a mess :-(
                # so punt and use sed.
                if [[ -n "${dry_run}" ]]
                then
                    echo "sed -i -e \"s/version = \\\"${current_tag}\\\"/version = \\\"${new_tag}\\\"/g\" ${f}"
                else
                    sed -i -e "s/version = \"${current_tag}\"/version = \"${new_tag}\"/g" "${f}"
                fi
            else
                echo "!! File current version ${p_version} doesn't match --current-tag ${current_tag} - skipping"
            fi
        else
            echo "!! File authors don't match --author value ${author} found ${authors} - skipping"
        fi
    else
        echo "!! File doesn't have a .packages.authors array - skipping"
    fi
done

# bump gradle file
echo "-- Update android-bindings/publish.gradle version"
if [[ -n "${dry_run}" ]]
then
    echo "Update version in android-bindings/lib-wrapper/android-bindings/publish.gradle"
else
    sed -i -e "s/${current_tag}/${new_tag}/g" android-bindings/lib-wrapper/android-bindings/publish.gradle
fi

# update Cargo.locks with cargo check, use mob image for sane build env.
mobconf="./.mobconf"
mob_image_tag=$(cat ./docker/Dockerfile-version)
mob_image_org=$(grep repository "${mobconf}" | awk '{print $3}')
mob_image_repo=$(grep target "${mobconf}" | awk '{print $3}')
mob_image="${mob_image_org}${mob_image_repo}:${mob_image_tag}"

echo "-- Update Cargo.lock files with mob docker image - cargo check"
if [[ -n "${dry_run}" ]]
then
    cat <<EOF
docker run -it --rm
    -e CARGO_HOME=/cargo
    -e IAS_MODE=DEV
    -e SGX_MODE=SW
    -e RUST_BACKTRACE=full
    -v "$(pwd):/tmp/mobilenode"
    --workdir "/tmp/mobilenode"
    "${mob_image}"
    /bin/bash -c "cargo check"
EOF

else
    docker run -it --rm \
        -e CARGO_HOME=/cargo \
        -e IAS_MODE=DEV \
        -e SGX_MODE=SW \
        -e RUST_BACKTRACE=full \
        -v "$(pwd):/tmp/mobilenode" \
        --workdir "/tmp/mobilenode" \
        "${mob_image}" \
        /bin/bash -c "cargo check"

fi
