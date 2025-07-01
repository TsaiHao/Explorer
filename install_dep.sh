#!/bin/bash

set -ex

readonly FRIDA_VERSION="17.0.6"
readonly BASE_DEPS_DIR="third_party/frida"
readonly NDK_PATH='/Users/zaijun/Library/Android/sdk/ndk/29.0.13113456'

usage() {
  echo "Usage: $0"
  echo "Build for Android platform"
  exit 1 
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
  if [ -f "${BASE_DEPS_DIR}/lib/libfrida-core.a" ]
  then
    echo "Frida dependencies already exist. Skipping download and extraction."
    return
  fi
  
  local archive_name="frida-core-devkit-${FRIDA_VERSION}-android-arm.tar.xz"
  local frida_url="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${archive_name}"

  echo "Frida version: ${FRIDA_VERSION}"
  echo "Target archive: ${archive_name}"
  echo "Download URL: ${frida_url}"

  local temp_extract_dir="frida_temp_extract_dir"
  echo "Creating temporary directory for download and extraction: ${temp_extract_dir}"
  rm -rf "${temp_extract_dir}" # Clean up if it exists from a failed previous run
  mkdir -p "${temp_extract_dir}"

  local original_dir
  original_dir=$(pwd)
  cd "${temp_extract_dir}" 

  echo "Downloading ${archive_name}..."
  curl -L --fail --output "${archive_name}" "${frida_url}"
  if [ $? -ne 0 ]; then
    echo "Error: Failed to download Frida devkit."
    cd "${original_dir}" 
    rm -rf "${temp_extract_dir}"
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

  install_extracted_files "$(pwd)" "${BASE_DEPS_DIR}"

  cd "${original_dir}"
  echo "Removing temporary download and extraction directory: ${temp_extract_dir}"

  rm -rf "${temp_extract_dir}"
  echo "--- Frida Dependencies Setup Complete ---"
}

install_sqlite_source() {
  local sqlite_version="3500100"
  local sqlite_file_name="sqlite-amalgamation-${sqlite_version}"
  local sqlite_zip_name="${sqlite_file_name}.zip"
  local sqlite_url="https://sqlite.org/2025/${sqlite_zip_name}"
  local sqlite_dir="third_party/sqlite"
  local sqlite_include_dir="${sqlite_dir}/include"
  local sqlite_src_dir="${sqlite_dir}/src"
  local temp_extract_dir="sqlite_temp_extract_dir"

  echo "Creating temporary directory for SQLite extraction: ${temp_extract_dir}"
  rm -rf "${temp_extract_dir}" 
  mkdir -p "${temp_extract_dir}"

  echo "Downloading SQLite source code from ${sqlite_url}..."
  curl -L --fail --output "${temp_extract_dir}/${sqlite_zip_name}" "${sqlite_url}"
  if [ $? -ne 0 ]; then
    echo "Error: Failed to download SQLite source code."
    exit 1
  fi

  unzip "${temp_extract_dir}/${sqlite_zip_name}" -d "${temp_extract_dir}"
  if [ $? -ne 0 ]; then
    echo "Error: Failed to extract SQLite source code."
    rm -rf "${temp_extract_dir}"
    exit 1
  fi

  if [ ! -f "${temp_extract_dir}/${sqlite_file_name}/sqlite3.c" ]; then
    echo "Error: SQLite source code not found in the expected location."
    rm -rf "${temp_extract_dir}"
    exit 1
  fi

  echo "Installing SQLite source code to ${sqlite_src_dir}..."
  mkdir -p "${sqlite_include_dir}"
  mkdir -p "${sqlite_src_dir}"
  mv "${temp_extract_dir}/${sqlite_file_name}/sqlite3.c" "${sqlite_src_dir}/sqlite3.c"
  mv "${temp_extract_dir}/${sqlite_file_name}/sqlite3.h" "${sqlite_include_dir}/sqlite3.h"
  mv "${temp_extract_dir}/${sqlite_file_name}/sqlite3ext.h" "${sqlite_include_dir}/sqlite3ext.h"
  echo "SQLite source code installation complete."
  rm -rf "${temp_extract_dir}"
}

main() {
  download_and_extract_frida

  install_sqlite_source
}

main "$@"

