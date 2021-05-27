# Copyright (c) 2018-2021 The MobileCoin Foundation

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# Note: When modifying this file, increment the Dockerfile-version minor version number
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#
# This is needed for mob tool to be able to pull the right image from the farm,
# if it isn't done, bad things will happen to local builds and CI using mob tool
# See mob tool comments for extended discussion

# builder-install contains dependencies but doesn't copy our sources in, so it can be
# cached in google cloud.
#
# ##################################### #
#  builder-install - Build environment  #
# ##################################### #

# Ubuntu 18.04
FROM ubuntu@sha256:538529c9d229fb55f50e6746b119e899775205d62c0fc1b7e679b30d02ecb6e8 AS builder-install

# Party like it's June 8th, 1989.
#
SHELL ["/bin/bash", "-c"]

# Certain Installers make 'installations' easier by having a nice front-end. While this is great when you have a manual install, this becomes an issue during automated installations.
ENV DEBIAN_FRONTEND=noninteractive

# Install build tools and dependencies
#
RUN apt-get update -q -q && \
 apt-get upgrade --yes --force-yes && \
 apt-get install --yes --force-yes \
  alien \
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
  systemd \
  unzip \
  uuid-dev \
  wget \
  zlib1g-dev
# psmisc = killall
# prometheus = helps with running slam scripts locally

# Install go 1.16 release
RUN wget https://golang.org/dl/go1.16.4.linux-amd64.tar.gz && \
    mv go1.16.4.linux-amd64.tar.gz go.tgz && \
    tar -C /usr/local -xzf go.tgz  && \
    rm -rf go.tgz
ENV PATH="/usr/local/go/bin:$PATH"
ENV GOPATH=/opt/go/
ENV PATH=$PATH:$GOPATH/bin

# Install SQLite latest release.
ENV SQLITE=sqlite-autoconf-3350400
RUN wget https://www.sqlite.org/2021/$SQLITE.tar.gz && \
    tar xf $SQLITE.tar.gz && \
    mkdir bld && \
    pushd bld && \
    ../$SQLITE/configure && \
    make && \
    make install && \
    popd && \
    rm -r bld $SQLITE.tar.gz

# For use in CI
RUN pip3 install awscli black

# filebeat is used for logs when running slam scripts locally
RUN curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.4.2-amd64.deb && \
    dpkg -i filebeat-7.4.2-amd64.deb && \
    rm filebeat-7.4.2-amd64.deb

# set rust nightly
#
RUN mkdir -p /tmp/rustup
WORKDIR /tmp/rustup
COPY --chown=root:root rust-toolchain .
RUN wget https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init && \
  chmod +x rustup-init && \
  ./rustup-init --default-toolchain $(cat rust-toolchain) -y && \
  /root/.cargo/bin/rustup component add \
    clippy \
    llvm-tools-preview \
    rls \
    rust-analysis \
    rust-src \
    rustfmt && \
  /root/.cargo/bin/cargo install sccache cargo-cache cargo2junit cargo-tree cargo-feature-analyst cbindgen && \
  /root/.cargo/bin/cargo install diesel_cli --no-default-features --features postgres

# Set PATH in the container environment to include cargo bin
ENV PATH="/root/.cargo/bin:$PATH"

# Install kcov. So that we don't have to do this again with every build in ci.
RUN mkdir -p /tmp/kcov
WORKDIR /tmp/kcov
RUN wget https://github.com/SimonKagstrom/kcov/archive/v36.tar.gz && \
    tar xvf v36.tar.gz && \
    cd kcov-36 && \
    cmake . && \
    make && \
    make install

# Conditionally install intel SGX libs

ARG DOCKER_NO_SGX=false

COPY --chown=root:root install_sgx.sh /tmp
RUN if [ "$DOCKER_NO_SGX" = "false" ] ; then cd /tmp && chmod +x install_sgx.sh && ./install_sgx.sh; else echo 'skipping sgx'; fi

# Setup postgresql for local testing
RUN sed -ie 's|host    all             all             127.0.0.1/32            md5|host    all             all             127.0.0.1/32            trust|' /etc/postgresql/10/main/pg_hba.conf && \
    sed -ie 's|host    all             all             ::1/128                 md5|host    all             all             ::1/128                 trust|' /etc/postgresql/10/main/pg_hba.conf && \
    service postgresql start && \
    su postgres -c "createuser --superuser root"

# Export postgres database url's for build environment, for local testing and conformance tests
ENV DATABASE_URL="postgres://localhost"
ENV TEST_DATABASE_URL="postgres://localhost"

# Export sgx sdk environment variables
# Doing this here means that we don't have to constantly source /opt/intel/sgxsdk/environment
# Docker doesn't appear to allow conditional ENV setting, but if DOCKER_NO_SGX is true then they won't use any of this I think
ENV SGX_SDK=/opt/intel/sgxsdk
ENV PATH=$PATH:$SGX_SDK/bin:$SGX_SDK/bin/x64
ENV PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$SGX_SDK/pkgconfig
ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$SGX_SDK/sdk_libs:$SGX_SDK/lib64

WORKDIR /
