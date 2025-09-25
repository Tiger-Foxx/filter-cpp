cmake_minimum_required(VERSION 3.16)
project(TigerFoxCpp VERSION 1.0.0 LANGUAGES CXX)

# Configuration C++
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Optimisations de performance
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -fsanitize=address")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Dépendances système
find_package(PkgConfig REQUIRED)
pkg_check_modules(NETFILTER_QUEUE REQUIRED libnetfilter_queue)
find_package(nlohmann_json 3.2.0 REQUIRED)
find_package(Threads REQUIRED)

# Recherche PCRE2 pour regex haute performance
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCRE2 REQUIRED libpcre2-8)

# Sources du projet
file(GLOB_RECURSE SOURCES src/*.cpp)

# Headers
include_directories(src)

# Exécutable principal
add_executable(tiger-fox ${SOURCES})

# Liaison des bibliothèques
target_link_libraries(tiger-fox 
    ${NETFILTER_QUEUE_LIBRARIES}
    nlohmann_json::nlohmann_json
    ${PCRE2_LIBRARIES}
    Threads::Threads
    pthread
)

# Include directories
target_include_directories(tiger-fox PRIVATE 
    ${NETFILTER_QUEUE_INCLUDE_DIRS}
    ${PCRE2_INCLUDE_DIRS}
)

# Définitions du compilateur
target_compile_definitions(tiger-fox PRIVATE 
    ${NETFILTER_QUEUE_CFLAGS_OTHER}
    ${PCRE2_CFLAGS_OTHER}
)

# Messages informatifs
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler flags: ${CMAKE_CXX_FLAGS}")
message(STATUS "NetFilter Queue found: ${NETFILTER_QUEUE_FOUND}")
message(STATUS "nlohmann/json found: ${nlohmann_json_FOUND}")
message(STATUS "PCRE2 found: ${PCRE2_FOUND}")
