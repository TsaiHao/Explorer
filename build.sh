#!/bin/bash

# Immediately exit if any command fails (-e) and print each command before execution (-x)
set -ex

# --- Script Configuration ---
# Define the Frida version to download. Update this as needed.
readonly FRIDA_VERSION="17.0.6"
# Define the base directory for third-party dependencies
readonly BASE_DEPS_DIR="third_party/frida"
# NDK Path (Update if necessary for your environment)
readonly NDK_PATH='/Users/zaijun/Library/Android/sdk/ndk/29.0.13113456'


# --- Helper function to show usage instructions ---
usage() {
  echo "Usage: $0 [-a | -d]"
  echo "  -a: Build for Android"
  echo "  -d: Build for Desktop (macOS arm64 for Frida)"
  exit 1 # Exit the script with an error code
}

# --- Function to parse command line options ---
# Sets the global variable BUILD_TYPE
parse_command_line_options() {
  echo "--- Parsing Command Line Options ---"
  BUILD_TYPE="" # Ensure it's reset or use 'local' if passed back
  while getopts "ad" opt "$@"; do
    case ${opt} in
      a )
        BUILD_TYPE="android"
        ;;
      d )
        BUILD_TYPE="desktop"
        ;;
      \? )
        echo "Error: Invalid option: -$OPTARG" 1>&2
        usage
        ;;
    esac
  done

  if [ -z "${BUILD_TYPE}" ]; then
    echo "Error: No build type selected. Please use -a for Android or -d for Desktop."
    usage
  fi
  echo "Build type selected: ${BUILD_TYPE}"
}

install_extracted_files() {
  local source_dir="$1"
  local target_base_dir="$2"
  local current_project_dir
  current_project_dir=$(pwd)/..

  local target_lib_dir="${current_project_dir}/${target_base_dir}/lib"
  local target_include_dir="${current_project_dir}/${target_base_dir}/include"
  local target_lib_file="libfrida-core.a"
  local target_header_file="frida-core.h"

  echo "Ensuring final destination directories exist:"
  echo "  Lib dir: ${target_lib_dir}"
  echo "  Include dir: ${target_include_dir}"
  mkdir -p "${target_lib_dir}"
  mkdir -p "${target_include_dir}"

  echo "Installing ${target_header_file} to ${target_include_dir}/${target_header_file}..."
  mv "${source_dir}/${target_header_file}" "${target_include_dir}/${target_header_file}"

  echo "Installing ${target_lib_file} to ${target_lib_dir}/${target_lib_file}..."
  mv "${source_dir}/${target_lib_file}" "${target_lib_dir}/${target_lib_file}"

  echo "Frida files installation complete."
}

download_and_extract_frida() {
  echo "--- Downloading and Extracting Frida Dependencies ---"
  local archive_name=""
  local frida_url=""

  if [ "${BUILD_TYPE}" = "android" ]; then
    archive_name="frida-core-devkit-${FRIDA_VERSION}-android-arm.tar.xz"
    frida_url="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${archive_name}"
  elif [ "${BUILD_TYPE}" = "desktop" ]; then
    archive_name="frida-core-devkit-${FRIDA_VERSION}-macos-arm64.tar.xz"
    frida_url="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${archive_name}"
  else
    echo "Error: Frida dependencies not configured for BUILD_TYPE='${BUILD_TYPE}'"
    exit 1
  fi

  echo "Frida version: ${FRIDA_VERSION}"
  echo "Target archive: ${archive_name}"
  echo "Download URL: ${frida_url}"

  local temp_extract_dir="frida_temp_extract_dir"
  echo "Creating temporary directory for download and extraction: ${temp_extract_dir}"
  rm -rf "${temp_extract_dir}" # Clean up if it exists from a failed previous run
  mkdir -p "${temp_extract_dir}"

  local original_dir
  original_dir=$(pwd)
  cd "${temp_extract_dir}" # Change into temp dir for cleaner operations

  echo "Downloading ${archive_name}..."
  curl -L --fail --output "${archive_name}" "${frida_url}"
  if [ $? -ne 0 ]; then
    echo "Error: Failed to download Frida devkit."
    cd "${original_dir}" # Return to original directory
    rm -rf "${temp_extract_dir}" # Clean up
    exit 1
  fi
  echo "Download complete."

  echo "Extracting frida-core.h from ${archive_name}..."
  tar -xJf "${archive_name}" frida-core.h
  if [ $? -ne 0 ]; then
    echo "Error: Failed to extract frida-core.h."
    cd "${original_dir}"
    rm -rf "${temp_extract_dir}"
    exit 1
  fi

  echo "Extracting libfrida-core.a from ${archive_name}..."
  tar -xJf "${archive_name}" libfrida-core.a
  if [ $? -ne 0 ]; then
    echo "Error: Failed to extract libfrida-core.a."
    cd "${original_dir}"
    rm -rf "${temp_extract_dir}"
    exit 1
  fi
  echo "Extraction complete."

  install_extracted_files "$(pwd)" "${BASE_DEPS_DIR}" # $(pwd) is absolute path to temp_extract_dir

  cd "${original_dir}"
  echo "Removing temporary download and extraction directory: ${temp_extract_dir}"
  #rm -rf "${temp_extract_dir}"

  echo "--- Frida Dependencies Setup Complete ---"
}

prepare_build_env() {
  echo "--- Preparing Build Environment ---"
  echo "Removing previous main build directory (if any)..."
  rm -rf build || true
  echo "Creating new main build directory..."
  mkdir build
}

configure_and_generate_build_system() {
  echo "--- Configuring CMake Build System ---"
  local common_cmake_args=(
    -S .
    -B build
    -G Ninja
    -DENABLE_DEBUG=ON
  )

  if [ "${BUILD_TYPE}" = "android" ]; then
    echo "Configuring for Android build..."
    # NDK path is exported to be available for the CMake toolchain file
    export NDK="${NDK_PATH}"

    cmake "${common_cmake_args[@]}" \
      -DCMAKE_TOOLCHAIN_FILE=${NDK}/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI=armeabi-v7a \
      -DANDROID_PLATFORM=android-31 \
      -DTARGET_ANDROID=ON
  elif [ "${BUILD_TYPE}" = "desktop" ]; then
    echo "Configuring for Desktop build..."
    cmake "${common_cmake_args[@]}" \
      -DTARGET_ANDROID=OFF
  else
    echo "Error: Unknown build type in CMake configuration. This should not happen."
    usage
  fi
  echo "CMake configuration complete."
}

# --- Function to execute the build ---
execute_build() {
  echo "--- Executing Build ---"
  cmake --build build
  echo "Build process finished."
}

# --- Main Script Execution ---
main() {
  echo "Starting build process..."

  parse_command_line_options "$@"
  download_and_extract_frida # Depends on BUILD_TYPE being set
  prepare_build_env
  configure_and_generate_build_system # Depends on BUILD_TYPE being set
  execute_build

  echo "Build completed successfully for ${BUILD_TYPE}."
}

# Call the main function to start the script
main "$@"

