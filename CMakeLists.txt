cmake_minimum_required(VERSION 3.20)
project(Kerbecs LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

file(GLOB_RECURSE Kerbecs_HEADERS  CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/Public/*.h")
file(GLOB_RECURSE Kerbecs_SOURCES  CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/Private/*.cpp")

add_library(Kerbecs SHARED
    ${Kerbecs_HEADERS}
    ${Kerbecs_SOURCES}
)

set(KERBECS_QUARANTINE_CAPACITY 4096 CACHE STRING "Quarantine ring buffer slot count (must be power of two)")

target_compile_definitions(Kerbecs PUBLIC
    SHADOWZONE_SIZE=1500
    GLOBALZONE_SIZE=500
    STATICZONE_SIZE=500
    REGISTRY_CAPACITY=4096
    QUARANTINE_CAPACITY=${KERBECS_QUARANTINE_CAPACITY}
    KERBECS_SHARED
    KERBECS_BUILDING_RUNTIME
)

target_include_directories(Kerbecs PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Public
)

target_precompile_headers(Kerbecs PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/Public/Kerbecs.h)

target_compile_options(Kerbecs PRIVATE
    $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CXX_COMPILER_ID:MSVC>>:/arch:AVX2 /W4 /permissive->
    $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<NOT:$<CXX_COMPILER_ID:MSVC>>>:-mavx2 -Wall -Wextra -Wpedantic>
)