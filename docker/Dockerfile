# Copyright (c) 2018-2022 The MobileCoin Foundation

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# Note: When modifying this file, increment the Dockerfile-version minor version number
# This is needed for mob tool to be able to pull the right image from the farm,
# if it isn't done, bad things will happen to local builds and CI using mob tool
# See mob tool comments for extended discussion
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

# builder-install contains dependencies but doesn't copy
# our sources in, so it can be cached in google cloud.


# ##################################### #
#  builder-install - Build environment  #
# ##################################### #
# Ubuntu 18.04
FROM ubuntu@sha256:538529c9d229fb55f50e6746b119e899775205d62c0fc1b7e679b30d02ecb6e8 AS builder-install

# Party like it's June 8th, 1989.
#
SHELL ["/bin/bash", "-c"]

# Specify the rust-toolchain for init script.
COPY rust-toolchain /tmp
ENV RUST_TOOLCHAIN_PATH=/tmp/rust-toolchain

COPY init_debian.sh /tmp
RUN bash /tmp/init_debian.sh

# Unfortunately we cannot update ENV from the init script.
# See https://github.com/docker/docker/issues/29110
ENV GOPATH=/opt/go/
ENV PATH="/usr/local/go/bin:$GOPATH/bin:$PATH"
# Set PATH in the container environment to include cargo bin
ENV PATH="/root/.cargo/bin:$PATH"

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
