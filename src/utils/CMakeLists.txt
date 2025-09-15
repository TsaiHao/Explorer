exp_add_library(exp_utils)

target_sources(exp_utils PRIVATE
        DB.h
        DB.cpp
        HttpDownloader.h
        HttpDownloader.cpp
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

target_link_libraries(exp_utils PRIVATE
        DEPS
        libcurl
)