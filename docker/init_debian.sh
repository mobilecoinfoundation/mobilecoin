#!/usr/bin/env bash

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# Note: When modifying this file, increment the Dockerfile-version minor version number
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#
# This is needed for mob tool to be able to pull the right image from the farm,
# if it isn't done, bad things will happen to local builds and CI using mob tool
# See mob tool comments for extended discussion

set -e  # Die on any errors

cd /tmp

# Certain Installers make 'installations' easier by having a nice front-end. While this is great when you have a manual install, this becomes an issue during automated installations.
export DEBIAN_FRONTEND=noninteractive

# Install build tools and dependencies
apt-get update -q -q
apt-get upgrade --yes
apt-get install --yes \
  alien \
  apt-transport-https \
  autoconf \
  automake \
  binutils-dev \
  build-essential \
  clang \
  cmake \
  curl \
  git \
  jq \
  libclang-dev \
  libcurl4-openssl-dev \
  libdw-dev \
  libiberty-dev \
  libpq-dev \
  libprotobuf-c-dev \
  libprotobuf-dev \
  libssl-dev \
  libssl1.1 \
  libsystemd-dev \
  libtool \
  libxml2-dev \
  llvm-dev \
  nano \
  nginx \
  ninja-build \
  ocaml-native-compilers \
  ocamlbuild \
  patch \
  pkg-config \
  postgresql-10 \
  prometheus \
  protobuf-c-compiler \
  protobuf-compiler \
  psmisc \
  python \
  python3-pip \
  sqlite3 \
  systemd \
  unzip \
  uuid-dev \
  wget \
  zlib1g-dev
# psmisc = killall
# prometheus = helps with running slam scripts locally

# For use in CI
# TODO: Do we need this outside CI?
pip3 install awscli black

# filebeat is used for logs when running slam scripts locally
# via https://www.elastic.co/guide/en/beats/filebeat/current/setup-repositories.html
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" >> /etc/apt/sources.list.d/elastic-7.x.list
apt-get update && apt-get install filebeat
systemctl enable filebeat

# Install go 1.16 release
GO_PKG=go1.16.4.linux-amd64.tar.gz
wget https://golang.org/dl/$GO_PKG -O go.tgz
tar -C /usr/local -xzf go.tgz
rm -rf go.tgz

# Install SQLite release.
SQLITE=sqlite-autoconf-3350400
SQLITE_PKG=$SQLITE.tar.gz
wget https://www.sqlite.org/2021/$SQLITE_PKG
tar xf $SQLITE_PKG
pushd $SQLITE
./configure
make install
popd
rm -r $SQLITE*

# set rust toolchain, defaulting to nightly
RUST_TOOLCHAIN=${RUST_TOOLCHAIN:-nightly}
if [ -f "$RUST_TOOLCHAIN_PATH" ]; then
  RUST_TOOLCHAIN=`cat "$RUST_TOOLCHAIN_PATH"`
fi

# Fetch rustup, and tell it to install $RUST_TOOLCHAIN
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain $RUST_TOOLCHAIN -y
source $HOME/.cargo/env
rustup component add \
  clippy \
  llvm-tools-preview \
  rust-analysis \
  rust-src \
  rustfmt
cargo install sccache cargo-cache cargo2junit cargo-tree cargo-feature-analyst cbindgen && \
cargo install diesel_cli --no-default-features --features postgres

# Install kcov. So that we don't have to do this again with every build in ci.
# TODO: Replace with `apt-get install kcov` when we upgrade builder image to
# Ubuntu 20
mkdir -p /tmp/kcov
cd /tmp/kcov
wget https://github.com/SimonKagstrom/kcov/archive/v36.tar.gz
tar xvf v36.tar.gz
cd kcov-36
cmake .
make install

echo "Successfully installed packages."
