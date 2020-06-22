#!/bin/sh

# Copyright (c) 2018-2020 MobileCoin Inc.

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

# NB: When updating dependencies, please remember to update the instructions in BUILD.md as well
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
	libssl-dev \
	libcurl4-openssl-dev \
	protobuf-compiler \
	git \
	libprotobuf-dev \
	alien \
	cmake \
	debhelper \
	uuid-dev \
	libxml2-dev

# Install SGX Development Environment
# NB: When updating dependencies, please remember to update the instructions in BUILD.md as well
mkdir -p /tmp/sgx-install
cd /tmp/sgx-install
cat <<EOF | wget -nv -i-
https://download.01.org/intel-sgx/sgx-linux/2.9.1/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.9.101.2.bin
https://download.01.org/intel-sgx/sgx-linux/2.9.1/distro/ubuntu18.04-server/debian_pkgs/utils/libsgx-ae-epid/libsgx-ae-epid_2.9.101.2-bionic1_amd64.deb
https://download.01.org/intel-sgx/sgx-linux/2.9.1/distro/ubuntu18.04-server/debian_pkgs/utils/libsgx-ae-pce/libsgx-ae-pce_2.9.101.2-bionic1_amd64.deb
https://download.01.org/intel-sgx/sgx-linux/2.9.1/distro/ubuntu18.04-server/debian_pkgs/utils/libsgx-aesm-epid-plugin/libsgx-aesm-epid-plugin_2.9.101.2-bionic1_amd64.deb
https://download.01.org/intel-sgx/sgx-linux/2.9.1/distro/ubuntu18.04-server/debian_pkgs/utils/libsgx-aesm-pce-plugin/libsgx-aesm-pce-plugin_2.9.101.2-bionic1_amd64.deb
https://download.01.org/intel-sgx/sgx-linux/2.9.1/distro/ubuntu18.04-server/debian_pkgs/libs/libsgx-enclave-common/libsgx-enclave-common_2.9.101.2-bionic1_amd64.deb
https://download.01.org/intel-sgx/sgx-linux/2.9.1/distro/ubuntu18.04-server/debian_pkgs/libs/libsgx-epid/libsgx-epid_2.9.101.2-bionic1_amd64.deb
https://download.01.org/intel-sgx/sgx-linux/2.9.1/distro/ubuntu18.04-server/debian_pkgs/libs/libsgx-pce-logic/libsgx-pce-logic_1.6.100.2-bionic1_amd64.deb
https://download.01.org/intel-sgx/sgx-linux/2.9.1/distro/ubuntu18.04-server/debian_pkgs/libs/libsgx-urts/libsgx-urts_2.9.101.2-bionic1_amd64.deb
https://download.01.org/intel-sgx/sgx-linux/2.9.1/distro/ubuntu18.04-server/debian_pkgs/utils/sgx-aesm-service/sgx-aesm-service_2.9.101.2-bionic1_amd64.deb
EOF

dpkg --install *.deb

chmod +x ./sgx_linux_x64_sdk_2.9.101.2.bin
./sgx_linux_x64_sdk_2.9.101.2.bin --prefix=/opt/intel

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
