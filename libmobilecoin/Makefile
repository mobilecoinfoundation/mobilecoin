# Copyright (c) 2018-2021 The MobileCoin Foundation

####################################
######### Public Variables #########
####################################

### Project Environment Variables

export SGX_MODE ?= HW
export IAS_MODE ?= DEV

### Build Configuration

CARGO_PROFILE ?= mobile-release
CARGO_BUILD_FLAGS ?=
CARGO_TARGET_DIR ?= ../target
RUST_BITCODE_DIR ?= rust-bitcode

$(info profile: $(CARGO_PROFILE))

### Toolchain

CARGO ?= cargo

####################################
######## Internal Variables ########
####################################

### Environment Variables

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  export LIBCLANG_PATH = $(shell brew --prefix llvm)/lib
endif

### Local Variables

CARGO_PACKAGE = libmobilecoin
ARCHS_IOS = aarch64-apple-ios-sim aarch64-apple-ios-macabi aarch64-apple-ios x86_64-apple-ios-macabi x86_64-apple-ios
IOS_LIB = libmobilecoin.a
IOS_C_HEADERS = include/*

RUST_COMMIT = 4e282795d
RUST_COMMIT_NAME = nightly-2021-08-01
SWIFT_VERSION = 5.3.2

### Helper Function

define BINARY_copy
	mkdir -p out/ios/target/$(1)/${CARGO_PROFILE}
	cp $(CARGO_TARGET_DIR)/$(1)/${CARGO_PROFILE}/libmobilecoin.a out/ios/target/$(1)/${CARGO_PROFILE};
endef

# First argument $(1) is a build-target
define TOOLCHAIN_install	
	$(if \
		$(shell rustup toolchain list | \
		   			grep "ios-$(1)-$(RUST_COMMIT_NAME)-swift-$(subst $(DOT),$(DASH),$(SWIFT_VERSION))" | \
	     			wc -l | \
	     			awk '{$$1=$$1;print}' | \
	     			grep '1'), \
	  @echo "toolchain ios-$(1)-$(RUST_COMMIT_NAME)-swift-$(subst $(DOT),$(DASH),$(SWIFT_VERSION)) already installed", \
    @echo "toolchain ios-$(1)-$(RUST_COMMIT_NAME)-swift-$(subst $(DOT),$(DASH),$(SWIFT_VERSION)) not installed"; \
		$(info "Compiling & Installing Rust $(RUST_COMMIT_NAME) toolchain") \
		$(info "with LLVM matching swift version - $(SWIFT_VERSION)") \
		$(info "from `rust` commit - $(RUST_COMMIT)") \
		$(info "for build-target - $(1)") \
		cd rust-bitcode && \
			build-install.sh -t $@ -l $(SWIFT_VERSION) -r $(RUST_COMMIT) -n $(RUST_COMMIT_NAME); \
	)
endef

DOT:= .
DASH:= -

####################################
############## Targets #############
####################################

.PHONY: all
all: setup ios

.PHONY: setup
setup:
	rustup target add x86_64-apple-ios aarch64-apple-ios x86_64-apple-darwin
	rustup component add llvm-tools-preview rust-src
	rustup run --install stable cargo install cargo-binutils

.PHONY: ios
ios: out/ios/$(IOS_LIB)

CARGO_BUILD_FLAGS += --lib -Z avoid-dev-deps
ifeq ($(CARGO_PROFILE),release)
  BUILD_CONFIG_FOLDER = ${CARGO_PROFILE}
  CARGO_BUILD_FLAGS += --release
else ifeq ($(CARGO_PROFILE),debug)
  BUILD_CONFIG_FOLDER = debug
else
  BUILD_CONFIG_FOLDER = ${CARGO_PROFILE}
  CARGO_BUILD_FLAGS += -Z unstable-options --profile ${CARGO_PROFILE}
endif

.PHONY: $(ARCHS_IOS)
x86_64-apple-ios aarch64-apple-ios: CARGO_ENV_FLAGS += CFLAGS="-DPB_NO_PACKED_STRUCTS=1"
x86_64-apple-ios aarch64-apple-ios: CARGO_ENV_FLAGS += CXXFLAGS="-DPB_NO_PACKED_STRUCTS=1"

x86_64-apple-ios x86_64-apple-ios-macabi x86_64-apple-darwin: LD_ARCH = x86_64
aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-ios-macabi: LD_ARCH = arm64

$(ARCHS_IOS):
	$(call TOOLCHAIN_install,$@)
	$(CARGO_ENV_FLAGS) $(CARGO) +ios-$@-$(RUST_COMMIT_NAME)-swift-$(subst $(DOT),$(DASH),$(SWIFT_VERSION)) build --package $(CARGO_PACKAGE) --target $@ $(CARGO_BUILD_FLAGS)


.PHONY: out/ios/$(IOS_LIB)
out/ios/$(IOS_LIB): $(ARCHS_IOS)
	mkdir -p out/ios
	$(foreach arch,$^,$(call BINARY_copy,$(arch)))

	mkdir -p out/ios/include
	cp $(IOS_C_HEADERS) out/ios/include

.PHONY: clean
clean:
	@rm -r out 2>/dev/null || true

####################################
############# Commands #############
####################################

.PHONY: setup-dev
setup-dev:
	cargo install cbindgen

.PHONY: cbindgen
cbindgen:
	cbindgen --crate libmobilecoin -o libmobilecoin_cbindgen.h
