cmake_minimum_required(VERSION 3.20)
project(Kerbecs)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

add_library(Kerbecs SHARED 
    src/Private/Kerbecs.cpp src/Public/Kerbecs.h
)

target_include_directories(Kerbecs PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Public)

set_target_properties(Kerbecs PROPERTIES FOLDER "Base")
