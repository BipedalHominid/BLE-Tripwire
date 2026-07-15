#!/usr/bin/env bash
#
# fetch-libnode.sh — download the prebuilt nodejs-mobile Android library and
# install libnode.so into app/src/main/jniLibs/<abi>/. Run once from the project
# root before building. The .so files are ~60 MB each and are intentionally NOT
# committed to the repo. The version here MUST match the headers vendored under
# app/src/main/cpp/libnode/include/node/ (they were taken from this same release).
#
# Usage:
#   scripts/fetch-libnode.sh
#
set -euo pipefail

NODEJS_MOBILE_VERSION="v18.20.4"
ASSET="nodejs-mobile-${NODEJS_MOBILE_VERSION}-android.zip"
URL="https://github.com/nodejs-mobile/nodejs-mobile/releases/download/${NODEJS_MOBILE_VERSION}/${ASSET}"

# Resolve project root as the parent of this script's dir.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
JNILIBS="${ROOT}/app/src/main/jniLibs"
HEADERS_DST="${ROOT}/app/src/main/cpp/libnode/include/node"

# Which ABIs to install. arm64-v8a covers essentially every phone made in the
# last several years. x86_64 is only for the Android emulator and roughly
# doubles the APK size, so it is OFF by default. Set WANT_X86_64=1 to include it
# (e.g. if you develop against an emulator):
#   WANT_X86_64=1 scripts/fetch-libnode.sh
# (armeabi-v7a also exists in the release if you need very old 32-bit devices.)
ABIS=("arm64-v8a")
if [[ "${WANT_X86_64:-0}" == "1" ]]; then
    ABIS+=("x86_64")
fi

echo ">> nodejs-mobile ${NODEJS_MOBILE_VERSION}"
echo ">> project root: ${ROOT}"

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

echo ">> downloading ${ASSET} (~57 MB)..."
if command -v curl >/dev/null 2>&1; then
    curl -fL --progress-bar "${URL}" -o "${TMP}/${ASSET}"
elif command -v wget >/dev/null 2>&1; then
    wget -q --show-progress "${URL}" -O "${TMP}/${ASSET}"
else
    echo "ERROR: need curl or wget on PATH." >&2
    exit 1
fi

echo ">> unzipping..."
unzip -q "${TMP}/${ASSET}" -d "${TMP}/nm"

echo ">> installing libnode.so per ABI..."
for abi in "${ABIS[@]}"; do
    src="${TMP}/nm/bin/${abi}/libnode.so"
    if [[ ! -f "${src}" ]]; then
        echo "   !! ${abi}: not found in release, skipping"
        continue
    fi
    mkdir -p "${JNILIBS}/${abi}"
    cp "${src}" "${JNILIBS}/${abi}/libnode.so"
    echo "   -> ${JNILIBS}/${abi}/libnode.so ($(du -h "${JNILIBS}/${abi}/libnode.so" | cut -f1))"
done

echo ">> refreshing vendored headers (keeps them in sync with the .so)..."
mkdir -p "${HEADERS_DST}"
rm -rf "${HEADERS_DST:?}/"*
cp -R "${TMP}/nm/include/node/." "${HEADERS_DST}/"
echo "   -> ${HEADERS_DST} ($(find "${HEADERS_DST}" -name '*.h' | wc -l | tr -d ' ') headers)"

echo ">> done. You can now build in Android Studio or with ./gradlew assembleDebug"
