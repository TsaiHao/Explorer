exp_add_library(exp_utils)

target_sources(exp_utils PRIVATE
        DB.h
        DB.cpp
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