# Dependencies.cmake
#
# Defines third-party dependency versions and provides
# install_dependencies() to fetch them at configure time.

# ---------------------------------------------------------------------------
# Version definitions (single source of truth)
# ---------------------------------------------------------------------------
set(DEP_FRIDA_VERSION  "17.0.6")
set(DEP_SQLITE_VERSION "3500100")
set(DEP_SQLITE_YEAR    "2025")
set(DEP_SPDLOG_VERSION "1.15.3")
set(DEP_POCO_VERSION   "1.14.2")

# ---------------------------------------------------------------------------
# Map ANDROID_ABI to Frida platform string.
# When not cross-compiling for Android, fall back to a host-based guess.
# ---------------------------------------------------------------------------
function(_resolve_frida_platform out_var)
    if(DEFINED ANDROID_ABI)
        if(ANDROID_ABI STREQUAL "armeabi-v7a")
            set(${out_var} "android-arm" PARENT_SCOPE)
        elseif(ANDROID_ABI STREQUAL "arm64-v8a")
            set(${out_var} "android-arm64" PARENT_SCOPE)
        elseif(ANDROID_ABI STREQUAL "x86")
            set(${out_var} "android-x86" PARENT_SCOPE)
        elseif(ANDROID_ABI STREQUAL "x86_64")
            set(${out_var} "android-x86_64" PARENT_SCOPE)
        else()
            message(FATAL_ERROR "Unsupported ANDROID_ABI: ${ANDROID_ABI}")
        endif()
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        set(${out_var} "macos-arm64" PARENT_SCOPE)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(${out_var} "linux-x86_64" PARENT_SCOPE)
    else()
        message(FATAL_ERROR "Cannot determine Frida platform. "
                "Set ANDROID_ABI (cross-compile) or build on a supported host.")
    endif()
endfunction()

# ---------------------------------------------------------------------------
# install_dependencies()
#
# Runs install_dep.py at configure time, passing all version strings and the
# resolved platform so the Python script needs no hardcoded values.
# ---------------------------------------------------------------------------
function(install_dependencies)
    _resolve_frida_platform(FRIDA_PLATFORM)

    find_package(Python3 COMPONENTS Interpreter REQUIRED)

    set(_script "${CMAKE_SOURCE_DIR}/install_dep.py")

    message(STATUS "Installing dependencies (frida=${DEP_FRIDA_VERSION}/${FRIDA_PLATFORM}, "
            "sqlite=${DEP_SQLITE_VERSION}, spdlog=${DEP_SPDLOG_VERSION}, poco=${DEP_POCO_VERSION})")

    execute_process(
        COMMAND ${Python3_EXECUTABLE} ${_script}
            --frida-version   ${DEP_FRIDA_VERSION}
            --frida-platform  ${FRIDA_PLATFORM}
            --sqlite-version  ${DEP_SQLITE_VERSION}
            --sqlite-year     ${DEP_SQLITE_YEAR}
            --spdlog-version  ${DEP_SPDLOG_VERSION}
            --poco-version    ${DEP_POCO_VERSION}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        RESULT_VARIABLE _dep_result
    )

    if(NOT _dep_result EQUAL 0)
        message(FATAL_ERROR "install_dep.py failed (exit code ${_dep_result})")
    endif()
endfunction()
