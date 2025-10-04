cmake_minimum_required(VERSION 3.20)
project(Kerbecs)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

add_library(Kerbecs SHARED 
    src/Private/Kerbecs.cpp src/Public/Kerbecs.h
    src/Private/Memory.cpp src/Public/Memory.h
    src/Private/ShadowMemory.cpp src/Public/ShadowMemory.h
    src/Private/MemoryZone.cpp src/Public/MemoryZone.h
)

target_include_directories(Kerbecs PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Public)

set_target_properties(Kerbecs PROPERTIES FOLDER "Base")
target_precompile_headers(Kerbecs PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/Public/Kerbecs.h)


add_compile_definitions(ENABLE_EVENT_EMITTERS_KERBECS=1)
add_compile_definitions(SHADOWZONE_SIZE=1500) # In Gigabytes
add_compile_definitions(GLOBALZONE_SIZE=500) # In Gigabytes
