# sqlite3.c and the header files are fetched by the install_deps.sh script

add_library(sqlite3 STATIC src/sqlite3.c)

target_include_directories(sqlite3 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(DEPS INTERFACE sqlite3)