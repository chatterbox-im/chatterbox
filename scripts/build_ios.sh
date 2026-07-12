#!/bin/bash
# Build Chatterbox for iOS and generate Swift bindings.
#
# Usage:
#   ./scripts/build_ios.sh                        # device + simulator + XCFramework
#   ./scripts/build_ios.sh --device-only          # only aarch64-apple-ios
#   ./scripts/build_ios.sh --sim-only             # only aarch64-apple-ios-sim
#   ./scripts/build_ios.sh --release              # optimised (default is debug)
#   ./scripts/build_ios.sh --output-dir /path     # write XCFramework + bindings to /path
#                                                 # (used by chatterbox-ios/bootstrap.sh)
#
# Default output (no --output-dir):
#   ios/Chatterbox.xcframework/
#   ios/Sources/ChatterboxFFI/

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
OUTPUT_DIR=""

for arg in "$@"; do
  case "$arg" in
    --release)          PROFILE="release" ;;
    --device-only)      BUILD_SIM=false ;;
    --sim-only)         BUILD_DEVICE=false ;;
    --output-dir=*)     OUTPUT_DIR="${arg#*=}" ;;
    --output-dir)       shift; OUTPUT_DIR="$1" ;;
  esac
done

# Resolve output directories
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"   # repo root
if [[ -n "$OUTPUT_DIR" ]]; then
  XCFW_OUT="$OUTPUT_DIR/Chatterbox.xcframework"
  BINDINGS_DIR="$OUTPUT_DIR/ChatterboxFFI"
  XCODE_XCFW="$OUTPUT_DIR/ChatterboxiOS/Chatterbox.xcframework"
  XCODE_SWIFT="$OUTPUT_DIR/ChatterboxiOS/ChatterboxiOS/chatterbox.swift"
else
  XCFW_OUT="$SCRIPT_DIR/ios/Chatterbox.xcframework"
  BINDINGS_DIR="$SCRIPT_DIR/ios/Sources/ChatterboxFFI"
  XCODE_XCFW="$SCRIPT_DIR/ios/ChatterboxiOS/Chatterbox.xcframework"
  XCODE_SWIFT="$SCRIPT_DIR/ios/ChatterboxiOS/ChatterboxiOS/chatterbox.swift"
fi

cd "$SCRIPT_DIR"

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

# Generate Swift bindings
if [[ "$BUILD_SIM" == true ]]; then
  BINDGEN_LIB="target/aarch64-apple-ios-sim/$PROFILE/libchatterbox.a"
else
  BINDGEN_LIB="target/aarch64-apple-ios/$PROFILE/libchatterbox.a"
fi

mkdir -p "$BINDINGS_DIR"
echo "==> Generating Swift bindings -> $BINDINGS_DIR"
"$CARGO" run --features ffi --bin uniffi-bindgen -- \
  generate --library "$BINDGEN_LIB" --language swift --out-dir "$BINDINGS_DIR"

# Build XCFramework
if [[ "$BUILD_DEVICE" == true && "$BUILD_SIM" == true ]]; then
  rm -rf "$XCFW_OUT"
  echo "==> Creating $XCFW_OUT"
  HEADERS_ONLY_DIR="$(mktemp -d)"
  cp "$BINDINGS_DIR"/chatterboxFFI.h "$HEADERS_ONLY_DIR/"
  cp "$BINDINGS_DIR"/chatterboxFFI.modulemap "$HEADERS_ONLY_DIR/"
  xcodebuild -create-xcframework \
    -library "target/aarch64-apple-ios/$PROFILE/libchatterbox.a" \
    -headers "$HEADERS_ONLY_DIR" \
    -library "target/aarch64-apple-ios-sim/$PROFILE/libchatterbox.a" \
    -headers "$HEADERS_ONLY_DIR" \
    -output "$XCFW_OUT"
  rm -rf "$HEADERS_ONLY_DIR"

  # Copy into the Xcode project folder (so Xcode finds it at its relative path)
  if [[ -d "$(dirname "$XCODE_XCFW")" ]]; then
    rm -rf "$XCODE_XCFW"
    cp -R "$XCFW_OUT" "$XCODE_XCFW"
    echo "==> Copied XCFramework -> $XCODE_XCFW"
  fi

  # Update chatterbox.swift in the app sources
  if [[ -f "$(dirname "$XCODE_SWIFT")/chatterbox.swift" || -d "$(dirname "$XCODE_SWIFT")" ]]; then
    cp "$BINDINGS_DIR/chatterbox.swift" "$XCODE_SWIFT"
    echo "==> Updated chatterbox.swift -> $XCODE_SWIFT"
  fi

  echo "==> Done!"
fi
