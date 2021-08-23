FROM rust:1.49 AS android-bindings-builder
USER root
ENV SDK_URL="https://dl.google.com/android/repository/commandlinetools-linux-6200805_latest.zip" \
    ANDROID_HOME="/usr/local/android-sdk" \
    ANDROID_VERSION=29 \
    ANDROID_BUILD_TOOLS_VERSION=30.0.3 \
    PATH="$PATH":/usr/local/bin:/usr/local/google-cloud-sdk/bin \
    GCLOUD_URL="https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-294.0.0-linux-x86_64.tar.gz"

# Install Build Essentials
RUN apt-get update && apt-get install --yes \
    apt-utils \
    build-essential \
    cmake \
    default-jdk \
    file \
    libc6-dev-i386 \
    python \
    python3-pip \
    libclang-dev \
    protobuf-compiler

# Download Android SDK
RUN mkdir "$ANDROID_HOME" .android \
    && cd "$ANDROID_HOME" \
    && mkdir cmdline-tools \
    && cd cmdline-tools \
    && curl -o sdk.zip $SDK_URL \
    && unzip sdk.zip \
    && rm sdk.zip \
    && mkdir "$ANDROID_HOME/licenses" || true \
    && ls "$ANDROID_HOME" \
    && echo "24333f8a63b6825ea9c5514f83c2829b004d1fee" > "$ANDROID_HOME/licenses/android-sdk-license" \
    && echo "y" | $ANDROID_HOME/cmdline-tools/tools/bin/sdkmanager --licenses

# Install Android Build Tool and Libraries
RUN $ANDROID_HOME/cmdline-tools/tools/bin/sdkmanager --update
RUN $ANDROID_HOME/cmdline-tools/tools/bin/sdkmanager "build-tools;${ANDROID_BUILD_TOOLS_VERSION}" \
    "platforms;android-${ANDROID_VERSION}" \
    "platform-tools" \
    "ndk-bundle"

# Add NDK to PATH

ENV NDK_HOME=${ANDROID_HOME}/ndk-bundle
ENV PATH ${PATH}:${NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin

RUN mkdir -p /usr/local/cargo/git
VOLUME ["/usr/local/cargo/git"]

# Install the specific rust toolchain
COPY rust-toolchain .
RUN rustup toolchain install $(cat rust-toolchain) \
    && rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android \
    && rustup update \
    && rustup component add rustfmt \
    && cargo install sccache

# AWS tools (needed by CI)
RUN pip3 install awscli
