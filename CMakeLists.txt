cmake_minimum_required(VERSION 3.20)

# No vcpkg dependencies; opt out of a user-wide `vcpkg integrate install` (its post-build step needs pwsh).
if(NOT DEFINED CMAKE_VS_GLOBALS)
    set(CMAKE_VS_GLOBALS "VcpkgEnabled=false")
endif()
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

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES
    ${Kerbecs_HEADERS}
    ${Kerbecs_SOURCES}
)

set(KERBECS_QUARANTINE_CAPACITY 4096 CACHE STRING "Quarantine ring buffer slot count (must be power of two)")
set(KERBECS_REGION_TABLE_CAPACITY 1024 CACHE STRING "Region-lookup table slot count for wild-pointer-to-Region resolution (v0.2 SS5.2)")

target_compile_definitions(Kerbecs PUBLIC
    SHADOWZONE_SIZE=1500
    GLOBALZONE_SIZE=500
    STATICZONE_SIZE=500
    METADATAZONE_SIZE=500
    REGISTRY_CAPACITY=4096
    QUARANTINE_CAPACITY=${KERBECS_QUARANTINE_CAPACITY}
    REGION_TABLE_CAPACITY=${KERBECS_REGION_TABLE_CAPACITY}
    KERBECS_SHARED
    KERBECS_BUILDING_RUNTIME
)

# AUTO follows _DEBUG (set by the debug CRT); ON/OFF pin it. Kerbecs-scoped, so it never collides with a host's DEBUG.
set(KERBECS_ENABLE_DEBUG_CHECKS AUTO CACHE STRING "Kerbecs asserts: AUTO (follow _DEBUG), ON or OFF")
set_property(CACHE KERBECS_ENABLE_DEBUG_CHECKS PROPERTY STRINGS AUTO ON OFF)
if (KERBECS_ENABLE_DEBUG_CHECKS STREQUAL "ON")
    target_compile_definitions(Kerbecs PUBLIC KERBECS_DEBUG_CHECKS=1)
elseif (KERBECS_ENABLE_DEBUG_CHECKS STREQUAL "OFF")
    target_compile_definitions(Kerbecs PUBLIC KERBECS_DEBUG_CHECKS=0)
endif()

target_include_directories(Kerbecs PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Public
)

target_precompile_headers(Kerbecs PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/Public/Kerbecs.h)

target_compile_options(Kerbecs PRIVATE
    $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>:/arch:AVX2 /W4 /permissive->
    $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<NOT:$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>>:-mavx2 -Wall -Wextra -Wpedantic>
)