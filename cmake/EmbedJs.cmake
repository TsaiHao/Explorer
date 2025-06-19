function(embed_js_file)
    cmake_parse_arguments(
            ARGS
            ""
            "TARGET_SOURCE;JS_FILE;OUTPUT_NAME;VARIABLE_NAME"
            ""
            ${ARGN}
    )

    if (NOT ARGS_TARGET_SOURCE OR NOT ARGS_JS_FILE)
        message(FATAL_ERROR "embed_js_file requires TARGET, JS_FILE arguments.")
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

    get_filename_component(JS_FILE_BASE_NAME ${JS_FILE_NAME} NAME_WE)
    add_custom_target(embed_js_${JS_FILE_BASE_NAME} ALL DEPENDS ${OUTPUT_PATH})

    target_include_directories(COMMON_SETTINGS INTERFACE ${CMAKE_BINARY_DIR}/generated)
    set_property(TARGET embed_js_${JS_FILE_BASE_NAME} PROPERTY FOLDER "Generated")

    message(STATUS "Embedded JavaScript file ${JS_FILE_NAME} into C++ header ${OUTPUT_NAME} for target ${CMAKE_CURRENT_SOURCE_DIR}/${ARGS_TARGET_SOURCE}.")
endfunction()
