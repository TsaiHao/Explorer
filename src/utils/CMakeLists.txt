set(LIB_NAME ${PROJECT_NAME}_utils)
add_library(${LIB_NAME} STATIC)

target_sources(${LIB_NAME} PRIVATE
        Log.h
        Log.cpp
        Macros.h
        SmallMap.h
        Status.h
        Status.cpp
        Subprocess.h
        Subprocess.cpp
        System.h
        System.cpp
        Util.h
        Util.cpp
)

target_link_libraries(${LIB_NAME} PUBLIC COMMON_SETTINGS)

target_link_libraries(${PROJECT_NAME} PRIVATE ${LIB_NAME})