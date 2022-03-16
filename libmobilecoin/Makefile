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

### Local Variables

DOT:= .
DASH:= -

CARGO_PACKAGE = libmobilecoin
ARCHS_IOS = aarch64-apple-ios-sim aarch64-apple-ios-macabi aarch64-apple-ios x86_64-apple-ios-macabi x86_64-apple-ios x86_64-apple-darwin
TARGET_TOOLCHAINS = toolchain_aarch64-apple-ios-sim toolchain_aarch64-apple-ios-macabi toolchain_aarch64-apple-ios toolchain_x86_64-apple-ios-macabi toolchain_x86_64-apple-ios toolchain_x86_64-apple-darwin

# add l_ prefix to build-targets that use the legacy build-process
ALL_LEGACY_ARCHS_IOS = l_aarch64-apple-ios-sim l_aarch64-apple-ios-macabi l_aarch64-apple-ios l_x86_64-apple-ios-macabi l_x86_64-apple-ios l_x86_64-apple-darwin

IOS_LIB = libmobilecoin.a
IOS_LIB_STRIPPED = libmobilecoin_stripped.a
IOS_C_HEADERS = include/*

RUST_BITCODE_COMMIT = $(shell source toolchain-config.env; echo $$RUST_BITCODE_COMMIT)
RUST_COMMIT = $(shell source toolchain-config.env; echo $$RUST_COMMIT)
RUST_COMMIT_NAME = $(shell source toolchain-config.env; echo $$RUST_COMMIT_NAME)
SWIFT_VERSION = $(shell source toolchain-config.env; echo $$SWIFT_VERSION)

### Helper Function

# First argument $(1) is a build-target, $(2) is the output directory
define BINARY_copy
	mkdir -p out/ios/$(2)/$(1)/${CARGO_PROFILE}
	cp $(CARGO_TARGET_DIR)/$(1)/${CARGO_PROFILE}/libmobilecoin.a out/ios/$(2)/$(1)/${CARGO_PROFILE};
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
		./build-install.sh -t $(1) -l $(SWIFT_VERSION) -r $(RUST_COMMIT) -n $(RUST_COMMIT_NAME); \
	)
endef

####################################
############## Targets #############
####################################

.PHONY: all
all: setup ios

.PHONY: bitcode
bitcode: setup bitcode-init

.PHONY: bitcode-init
bitcode-init:
	cd rust-bitcode && ./build-install.sh -t $@ -l $(SWIFT_VERSION) -r $(RUST_COMMIT) -n $(RUST_COMMIT_NAME);

.PHONY: setup
setup:
setup:
	$(info "Checking selected Xcode is version 12")
	xcodebuild -version | grep 'Xcode 12'
	mkdir -p rust-bitcode
	cd rust-bitcode && \
	git init && \
	git remote add origin git@github.com:mobilecoinofficial/rust-bitcode; \
	git fetch --depth 1 origin $(RUST_BITCODE_COMMIT); \
	git checkout FETCH_HEAD;

.PHONY: ios
ios: out/ios/target

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

LEGACY_CARGO_BUILD_FLAGS = $(CARGO_BUILD_FLAGS)

.PHONY: $(ARCHS_IOS)
x86_64-apple-ios aarch64-apple-ios: CARGO_ENV_FLAGS += CFLAGS="-DPB_NO_PACKED_STRUCTS=1"
x86_64-apple-ios aarch64-apple-ios: CARGO_ENV_FLAGS += CXXFLAGS="-DPB_NO_PACKED_STRUCTS=1"
$(ARCHS_IOS):
	mkdir -p out/ios
	$(call TOOLCHAIN_install,$@)
	$(CARGO_ENV_FLAGS) $(CARGO) +ios-$@-$(RUST_COMMIT_NAME)-swift-$(subst $(DOT),$(DASH),$(SWIFT_VERSION)) build --package $(CARGO_PACKAGE) --target $@ $(CARGO_BUILD_FLAGS)
	$(call BINARY_copy,$@,target)
	mkdir -p out/ios/include
	cp $(IOS_C_HEADERS) out/ios/include

.PHONY: $(TARGET_TOOLCHAINS)
$(TARGET_TOOLCHAINS):
	$(call TOOLCHAIN_install,$(subst toolchain_,,$@))

.PHONY: out/ios/target
out/ios/target: $(ARCHS_IOS)
	mkdir -p out/ios
	$(foreach arch,$^,$(call BINARY_copy,$(arch),target))

	mkdir -p out/ios/include
	cp $(IOS_C_HEADERS) out/ios/include


# Legacy build process uses standard rustup toolchains for building
# Output is in out/ios/legacy/
.PHONY: legacy
legacy: legacy_setup legacy_ios


.PHONY: legacy_setup
legacy_setup:
	rustup target add x86_64-apple-ios aarch64-apple-ios
	rustup component add llvm-tools-preview rust-src
	rustup run --install stable cargo install cargo-binutils


.PHONY: legacy_ios
legacy_ios: out/ios/legacy


.PHONY: legacy_x86_64-apple-darwin
legacy_x86_64-apple-darwin: out/ios/legacy/x86_64-apple-darwin


.PHONY: $(ALL_LEGACY_ARCHS_IOS)
l_x86_64-apple-ios l_aarch64-apple-ios: CARGO_ENV_FLAGS += CFLAGS="-DPB_NO_PACKED_STRUCTS=1"
l_x86_64-apple-ios l_aarch64-apple-ios: CARGO_ENV_FLAGS += CXXFLAGS="-DPB_NO_PACKED_STRUCTS=1"
l_x86_64-apple-ios l_x86_64-apple-ios-macabi l_x86_64-apple-darwin: LD_ARCH = x86_64
l_aarch64-apple-ios l_aarch64-apple-ios-sim l_aarch64-apple-ios-macabi: LD_ARCH = arm64
l_x86_64-apple-ios-macabi l_aarch64-apple-ios-sim l_aarch64-apple-ios-macabi: LEGACY_CARGO_BUILD_FLAGS += -Zbuild-std
$(ALL_LEGACY_ARCHS_IOS):
	$(CARGO_ENV_FLAGS) $(CARGO) build --package $(CARGO_PACKAGE) --target $(subst l_,,$@) $(LEGACY_CARGO_BUILD_FLAGS)

	@# Extract object files from static archive.
	@cd $(CARGO_TARGET_DIR)/$(subst l_,,$@)/$(BUILD_CONFIG_FOLDER) && \
		rm -rf extracted 2>/dev/null; \
		mkdir -p extracted
	cd $(CARGO_TARGET_DIR)/$(subst l_,,$@)/$(BUILD_CONFIG_FOLDER)/extracted && \
		ar -t ../$(IOS_LIB) \
			| grep '\.o$$' \
			| xargs ar -x ../$(IOS_LIB)

	@# Create list of libmobilecoin symbols.
	cd $(CARGO_TARGET_DIR)/$(subst l_,,$@)/$(BUILD_CONFIG_FOLDER) && \
		rust-nm -jgU extracted/mobilecoin*.mobilecoin.*.o -s __TEXT __text \
			| grep '\<_mc_' \
			> exported-symbols.def

	@# Link extracted object files back into static arch. Removes all symbols not needed
	@# by exported libmobilecoin symbols.
	@cd $(CARGO_TARGET_DIR)/$(subst l_,,$@)/$(BUILD_CONFIG_FOLDER) && \
		rm -f $(IOS_LIB_STRIPPED) || true
	cd $(CARGO_TARGET_DIR)/$(subst l_,,$@)/$(BUILD_CONFIG_FOLDER) && \
		ld -r -arch $(LD_ARCH) -x -keep_private_externs \
			-exported_symbols_list exported-symbols.def \
			-o $(IOS_LIB_STRIPPED) \
			extracted/*.o


.PHONY: out/ios/legacy
out/ios/legacy: $(ALL_LEGACY_ARCHS_IOS)
	mkdir -p out/ios/legacy
	$(foreach arch,$^,$(call BINARY_copy,$(subst l_,,$(arch)),legacy))

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
