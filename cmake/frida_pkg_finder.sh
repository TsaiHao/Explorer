#!/bin/bash

# frida_pkg_config.sh
# Usage: ./frida_pkg_config.sh <FRIDA_LOCAL_PATH> <LIB_NAME> <OPERATION_NAME>
# Example: ./frida_pkg_config.sh /path/to/frida gum libs

if [ $# -ne 3 ]; then
    echo "Usage: $0 <FRIDA_LOCAL_PATH> <LIB_NAME> <OPERATION_NAME>" >&2
    exit 1
fi

FRIDA_LOCAL_PATH="$1"
LIB_NAME="$2"
OPERATION_NAME="$3"

# Validate paths exist
if [ ! -d "$FRIDA_LOCAL_PATH/deps/sdk-android-arm/lib/pkgconfig" ]; then
    echo "Error: SDK pkg-config path does not exist: $FRIDA_LOCAL_PATH/deps/sdk-android-arm/lib/pkgconfig" >&2
    exit 1
fi

if [ ! -d "$FRIDA_LOCAL_PATH/android-server/install/lib/pkgconfig" ]; then
    echo "Error: Android server pkg-config path does not exist: $FRIDA_LOCAL_PATH/android-server/install/lib/pkgconfig" >&2
    exit 1
fi

# Set PKG_CONFIG_PATH and execute pkg-config
PKG_CONFIG_PATH="$FRIDA_LOCAL_PATH/deps/sdk-android-arm/lib/pkgconfig:$FRIDA_LOCAL_PATH/android-server/install/lib/pkgconfig" \
pkg-config --${OPERATION_NAME} ${LIB_NAME} --define-variable=frida_sdk_prefix="$FRIDA_LOCAL_PATH/deps/sdk-android-arm"