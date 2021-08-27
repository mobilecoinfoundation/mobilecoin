# Copyright (c) 2018-2021 The MobileCoin Foundation

# Working directory is the root of the project
pwd=$(shell pwd)/../

.PHONY : build test libs docker_image clean setup all default strip copy_artifacts dist
default: build

export SGX_MODE ?= HW
export IAS_MODE ?= DEV

CARGO_PROFILE ?= mobile
ARCHS = aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
DOCKER_BUILDER_IMAGE_TAG = gcr.io/mobilenode-211420/android-bindings-builder:1_3
CARGO_BUILD_FLAGS += -Zunstable-options --profile=$(CARGO_PROFILE)
BUILD_DEPS_FOLDER = /tmp/build/deps/
MIN_API_LEVEL = 19
MIN_API_LEVEL_64_BIT = 21

aarch64-linux-android: CARGO_ENV_FLAGS += \
	ISYSROOT=$(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/sysroot \
	ISYSTEM=$(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include/aarch64-linux-android \
	CXX=aarch64-linux-android$(MIN_API_LEVEL_64_BIT)-clang++ \
	CC=aarch64-linux-android$(MIN_API_LEVEL_64_BIT)-clang \
	CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=aarch64-linux-android$(MIN_API_LEVEL_64_BIT)-clang \
	CARGO_TARGET_AARCH64_LINUX_ANDROID_AR=aarch64-linux-android-ar \
	CMAKE_TARGET_OVERRIDE=aarch64-linux-android$(MIN_API_LEVEL_64_BIT)

armv7-linux-androideabi: CARGO_ENV_FLAGS += \
	ISYSROOT=$(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/sysroot \
	ISYSTEM=$(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include/arm-linux-androideabi \
	CXX=armv7a-linux-androideabi$(MIN_API_LEVEL)-clang++ \
	CC=armv7a-linux-androideabi$(MIN_API_LEVEL)-clang \
	CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER=armv7a-linux-androideabi$(MIN_API_LEVEL)-clang \
	CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_AR=arm-linux-android-ar \
	CMAKE_TARGET_OVERRIDE=armv7a-linux-androideabi$(MIN_API_LEVEL)

i686-linux-android: CARGO_ENV_FLAGS += \
	ISYSROOT=$(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/sysroot \
	ISYSTEM=$(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include/i686-linux-android \
	CXX=i686-linux-android$(MIN_API_LEVEL)-clang++ \
	CC=i686-linux-android$(MIN_API_LEVEL)-clang \
	CARGO_TARGET_I686_LINUX_ANDROID_LINKER=i686-linux-android$(MIN_API_LEVEL)-clang \
	CARGO_TARGET_I686_LINUX_ANDROID_AR=i686-linux-android-ar \
	CMAKE_TARGET_OVERRIDE=i686-linux-android$(MIN_API_LEVEL)

x86_64-linux-android: CARGO_ENV_FLAGS += \
	ISYSROOT=$(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/sysroot \
	ISYSTEM=$(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include/x86_64-linux-android \
	CXX=x86_64-linux-android$(MIN_API_LEVEL_64_BIT)-clang++ \
	CC=x86_64-linux-android$(MIN_API_LEVEL_64_BIT)-clang \
	CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER=x86_64-linux-android$(MIN_API_LEVEL_64_BIT)-clang \
	CARGO_TARGET_X86_64_LINUX_ANDROID_AR=x86_64-linux-android-ar \
	CMAKE_TARGET_OVERRIDE=x86_64-linux-android$(MIN_API_LEVEL_64_BIT)

$(ARCHS):
	$(CARGO_ENV_FLAGS) cargo build \
		$(CARGO_BUILD_FLAGS) \
		--target $@

libs: $(ARCHS) strip copy_artifacts

copy_artifacts:
	mkdir -p build/jniLibs/arm64-v8a
	mkdir -p build/jniLibs/armeabi-v7a
	mkdir -p build/jniLibs/x86
	mkdir -p build/jniLibs/x86_64
	mkdir -p build/proto
	cp -f ../target/aarch64-linux-android/$(CARGO_PROFILE)/libmobilecoin_android.so build/jniLibs/arm64-v8a/libmobilecoin.so
	cp -f ../target/armv7-linux-androideabi/$(CARGO_PROFILE)/libmobilecoin_android.so build/jniLibs/armeabi-v7a/libmobilecoin.so
	cp -f ../target/i686-linux-android/$(CARGO_PROFILE)/libmobilecoin_android.so build/jniLibs/x86/libmobilecoin.so
	cp -f ../target/x86_64-linux-android/$(CARGO_PROFILE)/libmobilecoin_android.so build/jniLibs/x86_64/libmobilecoin.so
	cp -f ../api/proto/blockchain.proto build/proto/
	cp -f ../api/proto/printable.proto build/proto/
	cp -f ../consensus/api/proto/consensus_client.proto build/proto/
	cp -f ../api/proto/external.proto build/proto/
	cp -f ../consensus/api/proto/consensus_common.proto build/proto/
	cp -f ../consensus/api/proto/consensus_peer.proto build/proto/
	cp -f ../attest/api/proto/attest.proto build/proto/
	cp -f ../fog/report/api/proto/report.proto build/proto/
	cp -f ../fog/api/proto/view.proto build/proto/
	cp -f ../fog/api/proto/fog_common.proto build/proto/
	cp -f ../fog/api/proto/kex_rng.proto build/proto/
	cp -f ../fog/api/proto/ledger.proto build/proto/
	cp -f ../fog/api/proto/ingest.proto build/proto/
	cp -f ../fog/api/proto/ingest_common.proto build/proto/

strip:
	aarch64-linux-android-strip ../target/aarch64-linux-android/$(CARGO_PROFILE)/libmobilecoin_android.so
	arm-linux-androideabi-strip ../target/armv7-linux-androideabi/$(CARGO_PROFILE)/libmobilecoin_android.so
	i686-linux-android-strip ../target/i686-linux-android/$(CARGO_PROFILE)/libmobilecoin_android.so
	x86_64-linux-android-strip ../target/x86_64-linux-android/$(CARGO_PROFILE)/libmobilecoin_android.so

build: setup
	docker run \
		--rm \
		-v $(pwd):/home/rust/ \
		-v $(BUILD_DEPS_FOLDER):/usr/local/cargo/git \
		-w /home/rust/android-bindings \
		$(DOCKER_BUILDER_IMAGE_TAG) \
		make libs

dist: build
	tar -czf android-bindings.tar.gz -C build .

docker_image:
	docker build \
		-t $(DOCKER_BUILDER_IMAGE_TAG) \
		-f docker/Dockerfile ../

publish_docker_image: docker_image
	docker image push $(DOCKER_BUILDER_IMAGE_TAG)

clean:
	docker run \
		--rm \
		-v $(pwd):/home/rust/ \
		-v /tmp/deps:/usr/local/cargo/git \
		-w /home/rust/android-bindings \
		$(DOCKER_BUILDER_IMAGE_TAG) \
		cargo clean

bash: setup
	docker run \
		--rm \
		-it \
		-v $(pwd):/home/rust/ \
		-v /tmp/deps:/usr/local/cargo/git \
		-w /home/rust/android-bindings \
		$(DOCKER_BUILDER_IMAGE_TAG) \
		bash

setup: docker_image
	mkdir -p $(BUILD_DEPS_FOLDER)

all: setup clean dist
