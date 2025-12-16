exp_add_library(exp_utils)

target_sources(exp_utils PRIVATE
        Log.h
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

if (ENABLE_NETWORKING)
    target_sources(exp_utils PRIVATE
        HttpDownloader.h
        HttpDownloader.cpp
    )

    target_link_libraries(exp_utils PRIVATE
        DEPS
        libcurl
    )
endif ()

if (ENABLE_SQLITE)
    target_sources(exp_utils PRIVATE
        SqliteDB.h
        SqliteDB.cpp
    )

    target_link_libraries(exp_utils PRIVATE
        DEPS
        sqlite3
    )
endif ()