set(FRIDA_FINDER "${LOCAL_CMAKE_MODULE_PATH}/frida_pkg_finder.sh")

function(link_frida_library TARGET_NAME FRIDA_LIB_NAME)
    if(NOT DEFINED FRIDA_LOCAL_PATH)
        message(FATAL_ERROR "FRIDA_LOCAL_PATH must be defined before calling link_frida_library")
    endif()

    if(NOT EXISTS "${FRIDA_FINDER}")
        message(FATAL_ERROR "frida_pkg_config.sh script not found in ${CMAKE_CURRENT_SOURCE_DIR}")
    endif()

    # Helper function to recursively collect all static dependencies
    function(_collect_static_dependencies LIB_NAME COLLECTED_LIBS_VAR)
        # Get private requires for this library
        execute_process(
            COMMAND ${FRIDA_FINDER} 
                    "${FRIDA_LOCAL_PATH}" 
                    "${LIB_NAME}" 
                    "print-requires-private"
            OUTPUT_VARIABLE PRIVATE_REQUIRES_OUTPUT
            ERROR_VARIABLE PRIVATE_REQUIRES_ERROR
            RESULT_VARIABLE PRIVATE_REQUIRES_RESULT
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )

        if(NOT PRIVATE_REQUIRES_RESULT EQUAL 0)
            # It's ok if there are no private requires
            message(STATUS "No private requires found for ${LIB_NAME} (or error occurred)")
            return()
        endif()

        # Process line by line
        string(REPLACE "\n" ";" PRIVATE_DEPS_LIST "${PRIVATE_REQUIRES_OUTPUT}")
        
        foreach(private_dep ${PRIVATE_DEPS_LIST})
            # Skip empty lines
            string(STRIP "${private_dep}" private_dep)
            if(NOT private_dep STREQUAL "")
                # Add to collected list if not already present
                list(FIND ${COLLECTED_LIBS_VAR} "${private_dep}" dep_index)
                if(dep_index EQUAL -1)
                    list(APPEND ${COLLECTED_LIBS_VAR} "${private_dep}")
                    # Recursively collect dependencies of this private dependency
                    _collect_static_dependencies("${private_dep}" ${COLLECTED_LIBS_VAR})
                endif()
            endif()
        endforeach()
        
        # Propagate the updated list back to parent scope
        set(${COLLECTED_LIBS_VAR} "${${COLLECTED_LIBS_VAR}}" PARENT_SCOPE)
    endfunction()

    # Get library flags (--libs)
    execute_process(
        COMMAND ${FRIDA_FINDER} 
                "${FRIDA_LOCAL_PATH}" 
                "${FRIDA_LIB_NAME}" 
                "libs"
        OUTPUT_VARIABLE FRIDA_LIBS_OUTPUT
        ERROR_VARIABLE FRIDA_LIBS_ERROR
        RESULT_VARIABLE FRIDA_LIBS_RESULT
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if(NOT FRIDA_LIBS_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to get libs for ${FRIDA_LIB_NAME}: ${FRIDA_LIBS_ERROR}")
    endif()

    # Get compiler flags (--cflags)
    execute_process(
        COMMAND ${FRIDA_FINDER} 
                "${FRIDA_LOCAL_PATH}" 
                "${FRIDA_LIB_NAME}" 
                "cflags"
        OUTPUT_VARIABLE FRIDA_CFLAGS_OUTPUT
        ERROR_VARIABLE FRIDA_CFLAGS_ERROR
        RESULT_VARIABLE FRIDA_CFLAGS_RESULT
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if(NOT FRIDA_CFLAGS_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to get cflags for ${FRIDA_LIB_NAME}: ${FRIDA_CFLAGS_ERROR}")
    endif()

    # Collect all static dependencies recursively
    set(ALL_STATIC_DEPS "")
    _collect_static_dependencies("${FRIDA_LIB_NAME}" ALL_STATIC_DEPS)

    # Get libs for all static dependencies
    set(ALL_STATIC_LIBS "")
    foreach(static_dep ${ALL_STATIC_DEPS})
        execute_process(
            COMMAND ${FRIDA_FINDER} 
                    "${FRIDA_LOCAL_PATH}" 
                    "${static_dep}" 
                    "libs"
            OUTPUT_VARIABLE STATIC_DEP_LIBS
            ERROR_VARIABLE STATIC_DEP_ERROR
            RESULT_VARIABLE STATIC_DEP_RESULT
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        
        if(STATIC_DEP_RESULT EQUAL 0)
            set(ALL_STATIC_LIBS "${ALL_STATIC_LIBS} ${STATIC_DEP_LIBS}")
            message(STATUS "Added static dependency libs for ${static_dep}: ${STATIC_DEP_LIBS}")
        else()
            message(WARNING "Failed to get libs for static dependency ${static_dep}: ${STATIC_DEP_ERROR}")
        endif()
    endforeach()

    # Combine main libs with static dependency libs
    set(COMBINED_LIBS_OUTPUT "${FRIDA_LIBS_OUTPUT} ${ALL_STATIC_LIBS}")

    # Parse the combined outputs
    separate_arguments(FRIDA_LIBS_LIST UNIX_COMMAND "${COMBINED_LIBS_OUTPUT}")
    separate_arguments(FRIDA_CFLAGS_LIST UNIX_COMMAND "${FRIDA_CFLAGS_OUTPUT}")

    # Separate libraries, library directories, and compile flags
    set(LIBRARIES "")
    set(LIBRARY_DIRS "")
    set(INCLUDE_DIRS "")
    set(COMPILE_OPTIONS "")
    set(LINK_OPTIONS "")

    # Process libs output
    foreach(flag ${FRIDA_LIBS_LIST})
        string(STRIP "${flag}" flag)
        if(NOT flag STREQUAL "")
            if(flag MATCHES "^-l(.+)")
                # Remove duplicates
                list(FIND LIBRARIES ${CMAKE_MATCH_1} lib_index)
                if(lib_index EQUAL -1)
                    list(APPEND LIBRARIES ${CMAKE_MATCH_1})
                endif()
            elseif(flag MATCHES "^-L(.+)")
                # Remove duplicates
                list(FIND LIBRARY_DIRS ${CMAKE_MATCH_1} dir_index)
                if(dir_index EQUAL -1)
                    list(APPEND LIBRARY_DIRS ${CMAKE_MATCH_1})
                endif()
            elseif(flag STREQUAL "-Wl,--export-dynamic")
                # Only add export-dynamic on ELF platforms
                if(ANDROID OR CMAKE_SYSTEM_NAME STREQUAL "Linux")
                    list(APPEND LINK_OPTIONS ${flag})
                endif()
            else()
                list(APPEND LINK_OPTIONS ${flag})
            endif()
        endif()
    endforeach()

    # Process cflags output
    foreach(flag ${FRIDA_CFLAGS_LIST})
        string(STRIP "${flag}" flag)
        if(NOT flag STREQUAL "")
            if(flag MATCHES "^-I(.+)")
                # Remove duplicates
                list(FIND INCLUDE_DIRS ${CMAKE_MATCH_1} inc_index)
                if(inc_index EQUAL -1)
                    list(APPEND INCLUDE_DIRS ${CMAKE_MATCH_1})
                endif()
            elseif(flag MATCHES "^-D(.+)" OR flag MATCHES "^-f(.+)" OR flag MATCHES "^-m(.+)")
                list(APPEND COMPILE_OPTIONS ${flag})
            endif()
        endif()
    endforeach()

    # Create an interface library for this Frida component
    set(INTERFACE_TARGET "frida::${FRIDA_LIB_NAME}")
    
    # Check if the interface target already exists
    if(NOT TARGET ${INTERFACE_TARGET})
        add_library(${INTERFACE_TARGET} INTERFACE IMPORTED)
        
        # Set properties on the interface library
        if(LIBRARIES)
            set_target_properties(${INTERFACE_TARGET} PROPERTIES
                INTERFACE_LINK_LIBRARIES "${LIBRARIES}"
            )
        endif()
        
        if(LIBRARY_DIRS)
            set_target_properties(${INTERFACE_TARGET} PROPERTIES
                INTERFACE_LINK_DIRECTORIES "${LIBRARY_DIRS}"
            )
        endif()
        
        if(INCLUDE_DIRS)
            set_target_properties(${INTERFACE_TARGET} PROPERTIES
                INTERFACE_INCLUDE_DIRECTORIES "${INCLUDE_DIRS}"
            )
        endif()
        
        if(COMPILE_OPTIONS)
            set_target_properties(${INTERFACE_TARGET} PROPERTIES
                INTERFACE_COMPILE_OPTIONS "${COMPILE_OPTIONS}"
            )
        endif()

        if(LINK_OPTIONS)
            set_target_properties(${INTERFACE_TARGET} PROPERTIES
                INTERFACE_LINK_OPTIONS "${LINK_OPTIONS}"
            )
        endif()
    endif()

    # Link the interface library to the target
    target_link_libraries(${TARGET_NAME} INTERFACE ${INTERFACE_TARGET})
    
    # Enhanced logging for debugging
    message(STATUS "Linked Frida library '${FRIDA_LIB_NAME}' to target '${TARGET_NAME}' (static mode)")
    message(STATUS "  Static dependencies found: ${ALL_STATIC_DEPS}")
    message(STATUS "  Libraries: ${LIBRARIES}")
    message(STATUS "  Library dirs: ${LIBRARY_DIRS}")
    message(STATUS "  Include dirs: ${INCLUDE_DIRS}")
    message(STATUS "  Compile options: ${COMPILE_OPTIONS}")
    message(STATUS "  Link options: ${LINK_OPTIONS}")
endfunction()