#!/bin/bash
# Build Chatterbox for iOS and generate Swift bindings.
#
# Usage:
#   ./scripts/build_ios.sh                  # device + simulator + XCFramework
#   ./scripts/build_ios.sh --device-only    # only aarch64-apple-ios
#   ./scripts/build_ios.sh --sim-only       # only aarch64-apple-ios-sim
#   ./scripts/build_ios.sh --release        # optimised (default is debug)
#
# Output:
#   ios/Chatterbox.xcframework/   <- link this in Xcode
#   ios/Sources/ChatterboxFFI/    <- add these Swift/header files to your Xcode project

set -euo pipefail

TOOLCHAIN="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin"
CARGO="$TOOLCHAIN/bin/cargo"
export RUSTC="$TOOLCHAIN/bin/rustc"

if [[ ! -x "$CARGO" ]]; then
  echo "error: stable rustup toolchain not found. Run:"
  echo "  rustup toolchain install stable-aarch64-apple-darwin"
  echo "  rustup target add aarch64-apple-ios aarch64-apple-ios-sim --toolchain stable-aarch64-apple-darwin"
  exit 1
fi

PROFILE="debug"
BUILD_DEVICE=true
BUILD_SIM=true

for arg in "$@"; do
  case "$arg" in
    --release)      PROFILE="release" ;;
    --device-only)  BUILD_SIM=false ;;
    --sim-only)     BUILD_DEVICE=false ;;
  esac
done

PROFILE_FLAG=$([[ "$PROFILE" == "release" ]] && echo "--release" || echo "")
CARGO_ARGS="--lib $PROFILE_FLAG --no-default-features --features ffi"

build_target() {
  local target="$1"
  echo "==> Building for $target ($PROFILE)..."
  "$CARGO" build $CARGO_ARGS --target "$target"
  echo "    -> target/$target/$PROFILE/libchatterbox.a ($(du -sh "target/$target/$PROFILE/libchatterbox.a" | cut -f1))"
}

[[ "$BUILD_DEVICE" == true ]] && build_target aarch64-apple-ios
[[ "$BUILD_SIM"    == true ]] && build_target aarch64-apple-ios-sim

# Generate Swift bindings from whichever lib we just built
if [[ "$BUILD_SIM" == true ]]; then
  BINDGEN_LIB="target/aarch64-apple-ios-sim/$PROFILE/libchatterbox.a"
else
  BINDGEN_LIB="target/aarch64-apple-ios/$PROFILE/libchatterbox.a"
fi

BINDINGS_DIR="ios/Sources/ChatterboxFFI"
mkdir -p "$BINDINGS_DIR"
echo "==> Generating Swift bindings -> $BINDINGS_DIR"
"$CARGO" run --features ffi --bin uniffi-bindgen -- \
  generate --library "$BINDGEN_LIB" --language swift --out-dir "$BINDINGS_DIR"

# Build XCFramework (bundles device + simulator so Xcode picks the right slice)
if [[ "$BUILD_DEVICE" == true && "$BUILD_SIM" == true ]]; then
  XCFW="ios/Chatterbox.xcframework"
  rm -rf "$XCFW"
  echo "==> Creating $XCFW"
  # XCFramework headers must only contain .h/.modulemap — NOT chatterbox.swift
  # (Swift source files are added directly to the Xcode app target instead)
  HEADERS_ONLY_DIR="$(mktemp -d)"
  cp "$BINDINGS_DIR"/chatterboxFFI.h "$HEADERS_ONLY_DIR/"
  cp "$BINDINGS_DIR"/chatterboxFFI.modulemap "$HEADERS_ONLY_DIR/"
  xcodebuild -create-xcframework \
    -library "target/aarch64-apple-ios/$PROFILE/libchatterbox.a" \
    -headers "$HEADERS_ONLY_DIR" \
    -library "target/aarch64-apple-ios-sim/$PROFILE/libchatterbox.a" \
    -headers "$HEADERS_ONLY_DIR" \
    -output "$XCFW"
  rm -rf "$HEADERS_ONLY_DIR"
  echo "==> Done!"
  echo ""
  echo "In Xcode:"
  echo "  1. Drag ios/Chatterbox.xcframework into your project (check 'Copy if needed')"
  echo "  2. Add the .swift files from $BINDINGS_DIR to your app target"
  echo "  3. Add \$(SRCROOT)/ios/Sources/ChatterboxFFI to Swift Compiler -> Import Paths"
fi
