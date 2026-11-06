#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
sdk="${WLOC_SDK:-../ios-sdks/iPhoneOS15.6.sdk}"
clang="${WLOC_CLANG:-clang-18}"
linker="${WLOC_LD:-ld64.lld-18}"
if [[ ! -f "$sdk/SDKSettings.plist" ]]; then
    printf 'iOS SDK not found at %s. Set WLOC_SDK to the SDK directory.\n' "$sdk" >&2
    exit 1
fi
bundle=package/Payload/WLOCRules.app
mkdir -p "$bundle"
flags=(-target arm64-apple-ios15.0 -isysroot "$sdk" -Os -Wall -Wextra -Werror)
"$clang" "${flags[@]}" -fobjc-arc -fblocks -c main.m -o package/main.o
"$clang" "${flags[@]}" -c rules.c -o package/rules.o
"$linker" -arch arm64 -platform_version ios 15.0 15.6 \
    -syslibroot "$sdk" -o "$bundle/WLOCRules" package/main.o package/rules.o \
    -framework UIKit -framework Foundation -framework Security -framework CoreFoundation \
    -lsqlite3 -lSystem -lobjc
cp Info.plist "$bundle/Info.plist"
file "$bundle/WLOCRules"
