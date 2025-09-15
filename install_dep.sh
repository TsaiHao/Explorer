#!/bin/bash

set -ex

readonly FRIDA_VERSION="17.0.6"
readonly BASE_DEPS_DIR="third_party/frida"
readonly NDK_PATH='/Users/zaijun/Library/Android/sdk/ndk/29.0.13113456'
readonly SQLITE_VERSION='3500100'
readonly SPDLOG_VERSION='1.15.3'
readonly LIBCURL_VERSION='8.16.0'

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
  if [ -f "third_party/sqlite/src/sqlite3.c" ] && [ -f "third_party/sqlite/include/sqlite3.h" ]; then
    echo "SQLite source code already exists. Skipping download and extraction."
    return
  fi

  local sqlite_file_name="sqlite-amalgamation-${SQLITE_VERSION}"
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

install_spdlog() {
  local spdlog_target_dir="third_party/spdlog"
  
  if [ -d "${spdlog_target_dir}" ] && [ -f "${spdlog_target_dir}/spdlog.h" ]; then
    echo "spdlog already exists. Skipping download and extraction."
    return
  fi
  
  local SPDLOG_ARCHEVE_URL="https://github.com/gabime/spdlog/archive/refs/tags/v${SPDLOG_VERSION}.tar.gz"
  local archive_name="spdlog-${SPDLOG_VERSION}.tar.gz"
  local temp_extract_dir="spdlog_temp_extract_dir"
  local extracted_dir_name="spdlog-${SPDLOG_VERSION}"
  
  echo "spdlog version: ${SPDLOG_VERSION}"
  echo "Download URL: ${SPDLOG_ARCHEVE_URL}"
  
  echo "Creating temporary directory for download and extraction: ${temp_extract_dir}"
  rm -rf "${temp_extract_dir}" # Clean up if it exists from a failed previous run
  mkdir -p "${temp_extract_dir}"
  
  local original_dir
  original_dir=$(pwd)
  cd "${temp_extract_dir}"
  
  echo "Downloading ${archive_name}..."
  curl -L --fail --output "${archive_name}" "${SPDLOG_ARCHEVE_URL}"
  if [ $? -ne 0 ]; then
    echo "Error: Failed to download spdlog archive."
    cd "${original_dir}"
    rm -rf "${temp_extract_dir}"
    exit 1
  fi
  echo "Download complete."
  
  echo "Extracting ${archive_name}..."
  tar -xzf "${archive_name}"
  if [ $? -ne 0 ]; then
    echo "Error: Failed to extract spdlog archive."
    cd "${original_dir}"
    rm -rf "${temp_extract_dir}"
    exit 1
  fi
  echo "Extraction complete."
  
  if [ ! -d "${extracted_dir_name}" ]; then
    echo "Error: Expected directory ${extracted_dir_name} not found after extraction."
    cd "${original_dir}"
    rm -rf "${temp_extract_dir}"
    exit 1
  fi
  
  if [ ! -d "${extracted_dir_name}/include/spdlog" ]; then
    echo "Error: include/spdlog directory not found in extracted archive."
    cd "${original_dir}"
    rm -rf "${temp_extract_dir}"
    exit 1
  fi
  
  cd "${original_dir}"
  
  echo "Installing spdlog headers to ${spdlog_target_dir}..."
  mkdir -p "third_party"
  
  rm -rf "${spdlog_target_dir}"
  
  cp -r "${temp_extract_dir}/${extracted_dir_name}/include/spdlog" "${spdlog_target_dir}"
  if [ $? -ne 0 ]; then
    echo "Error: Failed to copy spdlog headers."
    rm -rf "${temp_extract_dir}"
    exit 1
  fi
  
  echo "spdlog headers installation complete."
  
  echo "Removing temporary download and extraction directory: ${temp_extract_dir}"
  rm -rf "${temp_extract_dir}"
  
  echo "--- spdlog Dependencies Setup Complete ---"
}

install_libcurl() {
  if [ -d "third_party/libcurl/curl" ] && [ -f "third_party/libcurl/curl/configure" ]; then
    echo "libcurl source code already exists. Skipping download and extraction."
    return
  fi
  local libcurl_archive_name="curl-${LIBCURL_VERSION}.tar.gz"
  local libcurl_url="https://curl.se/download/${libcurl_archive_name}"
  local libcurl_dir="third_party/libcurl"
  local temp_extract_dir="libcurl_temp_extract_dir"

  echo "Creating temporary directory for libcurl extraction: ${temp_extract_dir}"
  rm -rf "${temp_extract_dir}"
  mkdir -p "${temp_extract_dir}"

  echo "Downloading libcurl source code from ${libcurl_url}..."
  curl -L --fail --output "${temp_extract_dir}/${libcurl_archive_name}" "${libcurl_url}"
  if [ $? -ne 0 ]; then
    echo "Error: Failed to download libcurl source code."
    exit 1
  fi

  tar -xzf "${temp_extract_dir}/${libcurl_archive_name}" -C "${temp_extract_dir}"
  if [ $? -ne 0 ]; then
    echo "Error: Failed to extract libcurl source code."
    rm -rf "${temp_extract_dir}"
    exit 1
  fi

  mv "${temp_extract_dir}/curl-${LIBCURL_VERSION}" "${libcurl_dir}"/curl

  echo "libcurl source code installation complete."
  rm -rf "${temp_extract_dir}"
}

main() {
  download_and_extract_frida

  install_sqlite_source
  
  install_spdlog

  install_libcurl
}

main "$@"
