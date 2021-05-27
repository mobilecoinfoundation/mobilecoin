#!/bin/sh

# Copyright (c) 2018-2021 The MobileCoin Foundation

set -e -x

# ############################################### #
# builder-install-sgx - Add SGX SDK and reinstall protobuf
# (Note(chris): I don't understand the protobuf part right now)
#
# Inspired by:
# https://github.com/sebva/docker-sgx
# Note: The example is FROM ubuntu:bionic, which is 18.04
# Note: Not just 'FROM'ing it because they make no maintenance promises
# ############################################### #

set -e
set -u

cd /tmp

# Install SGX Ubuntu/Debian Repo
# NB: When updating dependencies, please remember to update the instructions in BUILD.md as well
(
	. /etc/os-release

	wget "https://download.01.org/intel-sgx/sgx-linux/2.13.3/distro/ubuntu${VERSION_ID}-server/sgx_linux_x64_sdk_2.13.103.1.bin"

	echo "deb [arch=amd64 signed-by=/etc/apt/trusted.gpg.d/intel-sgx-archive-keyring.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu/ ${UBUNTU_CODENAME} main" > /etc/apt/sources.list.d/intel-sgx.list
)

wget -O- https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | \
	gpg --dearmor > /etc/apt/trusted.gpg.d/intel-sgx-archive-keyring.gpg

# Actually install stuff
apt-get update
apt-get install -yq --no-install-recommends \
	ca-certificates \
	build-essential \
	ocaml \
	ocamlbuild \
	automake \
	autoconf \
	libtool \
	wget \
	python \
	libssl-dev \
	libcurl4-openssl-dev \
	protobuf-compiler \
	git \
	libprotobuf-dev \
	alien \
	cmake \
	debhelper \
	uuid-dev \
	libxml2-dev \
	libsgx-uae-service \
	sgx-aesm-service

chmod +x ./sgx_linux_x64_sdk_2.13.103.1.bin
./sgx_linux_x64_sdk_2.13.103.1.bin --prefix=/opt/intel

# Update .bashrc to source sgxsdk
echo 'source /opt/intel/sgxsdk/environment' >> /root/.bashrc

# Protobuf
#
#  When you absolutely, positively, can't depend on this getting installed properly...
#
mkdir -p /tmp/protoc

cd /tmp/protoc
wget https://github.com/protocolbuffers/protobuf/releases/download/v3.6.1/protoc-3.6.1-linux-x86_64.zip
unzip protoc-3.6.1-linux-x86_64.zip
cp bin/protoc /usr/bin/protoc
