exp_add_library(exp_utils)

target_sources(exp_utils PRIVATE
        Log.h
        Macros.h
        MessageCache.h
        SmallMap.h
        Status.h
        Status.cpp
        StateManager.h
        StateManager.cpp
        ErrorHandling.h
        ErrorHandling.cpp
        Subprocess.h
        Subprocess.cpp
        System.h
        System.cpp
        Util.h
        Util.cpp
)

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