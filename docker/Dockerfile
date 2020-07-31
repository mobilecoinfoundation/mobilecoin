# Copyright (c) 2018-2020 MobileCoin Inc.

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

FROM ubuntu:18.04 AS builder-install

# Party like it's June 8th, 1989.
#
SHELL ["/bin/bash", "-c"]

# Install build tools and dependencies
#
RUN apt-get update -q -q && \
 apt-get upgrade --yes --force-yes && \
 apt-get install --yes --force-yes \
  automake \
  autoconf \
  alien \
  binutils-dev \
  build-essential \
  libclang-dev \
  clang \
  cmake \
  curl \
  libcurl4-openssl-dev \
  libdw-dev \
  git \
  golang \
  libiberty-dev \
  jq \
  llvm-dev \
  nano \
  ninja-build \
  ocaml-native-compilers \
  ocamlbuild \
  patch \
  protobuf-compiler \
  protobuf-c-compiler \
  libprotobuf-c-dev \
  libprotobuf-dev \
  psmisc \
  pkg-config \
  prometheus \
  python \
  python3-pip \
  libssl1.1 \
  libssl-dev \
  systemd \
  libsystemd-dev \
  libtool \
  unzip \
  uuid-dev \
  wget \
  libxml2-dev \
  zlib1g-dev

# psmisc = killall
# prometheus = helps with running slam scripts locally

# For use in CI
RUN pip3 install awscli

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
  /root/.cargo/bin/cargo install sccache cargo-cache cargo2junit cargo-tree cargo-feature-analyst

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

# Patch and install the patched LLVM BOLT utility

COPY --chown=root:root install-bolt.sh /tmp
RUN /bin/bash /tmp/install-bolt.sh

# Conditionally install intel SGX libs

ARG DOCKER_NO_SGX=false

COPY --chown=root:root install_sgx.sh /tmp
RUN if [ "$DOCKER_NO_SGX" = "false" ] ; then cd /tmp && chmod +x install_sgx.sh && ./install_sgx.sh; else echo 'skipping sgx'; fi

# Export sgx sdk environment variables
# Doing this here means that we don't have to constantly source /opt/intel/sgxsdk/environment
# Docker doesn't appear to allow conditional ENV setting, but if DOCKER_NO_SGX is true then they won't use any of this I think
ENV SGX_SDK=/opt/intel/sgxsdk
ENV PATH=$PATH:$SGX_SDK/bin:$SGX_SDK/bin/x64
ENV PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$SGX_SDK/pkgconfig
ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$SGX_SDK/sdk_libs:$SGX_SDK/lib64

WORKDIR /
