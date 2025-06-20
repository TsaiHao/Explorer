function(embed_js_file)
    cmake_parse_arguments(
            ARGS
            ""
            "TARGET;TARGET_SOURCE;JS_FILE;OUTPUT_NAME;VARIABLE_NAME"
            ""
            ${ARGN}
    )

    if (NOT ARGS_JS_FILE)
        message(FATAL_ERROR "embed_js_file requires JS_FILE argument.")
    endif ()

    if (NOT EXISTS ${ARGS_JS_FILE})
        message(FATAL_ERROR "JavaScript file ${ARGS_JS_FILE} does not exist.")
    endif ()

    if (NOT IS_ABSOLUTE ${ARGS_JS_FILE})
        set(JS_FILE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/${ARGS_JS_FILE})
    else ()
        set(JS_FILE_PATH ${ARGS_JS_FILE})
    endif ()
    if (NOT ARGS_VARIABLE_NAME)
        set(VARIABLE_NAME "kScriptSource")
    else ()
        set(VARIABLE_NAME ${ARGS_VARIABLE_NAME})
    endif ()

    get_filename_component(JS_FILE_NAME ${JS_FILE_PATH} NAME)
    if (NOT ARGS_OUTPUT_NAME)
        set(OUTPUT_NAME ${JS_FILE_NAME}.h)
    else ()
        set(OUTPUT_NAME ${ARGS_OUTPUT_NAME})
    endif ()
    set(OUTPUT_PATH ${CMAKE_BINARY_DIR}/generated/${OUTPUT_NAME})

    add_custom_command(
            OUTPUT ${OUTPUT_PATH}
            COMMAND python3 ${LOCAL_CMAKE_MODULE_PATH}/generate_js_header.py -i ${JS_FILE_PATH} -o ${OUTPUT_PATH} -v ${VARIABLE_NAME}
            DEPENDS ${JS_FILE_PATH} ${LOCAL_CMAKE_MODULE_PATH}/generate_js_header.py
            COMMENT "Embedding JavaScript file ${JS_FILE_NAME} into C++ header ${OUTPUT_NAME}"
            VERBATIM
    )

    if (ARGS_TARGET)
        target_sources(${ARGS_TARGET} PRIVATE ${OUTPUT_PATH})
    endif()

    target_include_directories(${ARGS_TARGET} PRIVATE ${CMAKE_BINARY_DIR}/generated)

    message(STATUS "Embedded JavaScript file ${JS_FILE_NAME} into C++ header ${OUTPUT_NAME} for target ${ARGS_TARGET}.")
endfunction()

function(exp_add_library lib_name)
    add_library(${lib_name} STATIC)

    if(TARGET COMMON_SETTINGS)
        target_link_libraries(${lib_name} PUBLIC COMMON_SETTINGS DEPS)
    else()
        message(STATUS "Warning: COMMON_SETTINGS target not found. Cannot link ${lib_name} to it.")
    endif()
endfunction()