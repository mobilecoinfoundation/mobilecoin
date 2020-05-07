#!/bin/bash
#
# This script will checkout and compile the llvm-bolt executable from
# the signalapp fork of the facebook BOLT project.
#

set -u
set -eE

BASE_DIR=$(mktemp -d)

LLVM_GIT_REV="f137ed238db11440f03083b1c88b7ffc0f4af65e"
LLVM_URL="https://github.com/llvm-mirror/llvm/archive/${LLVM_GIT_REV}.tar.gz"
LLVM_DIR="${BASE_DIR}/llvm-${LLVM_GIT_REV}"
LLVM_TOOLS_DIR="${LLVM_DIR}/tools"

BOLT_GIT_REV="0655e9a71f43b3fc6a87e3c9be779dc76bc9efb9"
BOLT_URL="https://github.com/signalapp/BOLT/archive/${BOLT_GIT_REV}.tar.gz"
BOLT_DIR="${BASE_DIR}/BOLT-${BOLT_GIT_REV}"
BOLT_SYMLINK="${LLVM_TOOLS_DIR}/llvm-bolt"
BOLT_PATCH="${BOLT_DIR}/llvm.patch"

BUILD_DIR="${BASE_DIR}/build"

BOLT_EXE="${BUILD_DIR}/bin/llvm-bolt"

function traphandler() {
    echo "Installation of llvm-bolt failed, build located at ${BASE_DIR}"
}

trap traphandler ERR

echo -n "Downloading and patching LLVM..."

curl -qLsf ${LLVM_URL} | tar -zxf - -C ${BASE_DIR}
curl -qLsf ${BOLT_URL} | tar -zxf - -C ${BASE_DIR}
ln -sf ${BOLT_DIR} "${BOLT_SYMLINK}"
patch -d ${LLVM_DIR} -p1 -T < "${BOLT_PATCH}"

mkdir -p "${BUILD_DIR}"

echo " Done."

pushd "${BUILD_DIR}"

cmake -G Ninja "${LLVM_DIR}" -DLLVM_TARGETS_TO_BUILD=X86 -DCMAKE_BUILD_TYPE=Release
ninja

install -Dbpm 0755 ${BOLT_EXE} "${HOME}/.local/bin/llvm-bolt"

popd >/dev/null

rm -rf ${BASE_DIR}
