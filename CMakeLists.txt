cmake_minimum_required(VERSION 3.16)
project(TigerFoxCpp VERSION 2.0.0 LANGUAGES CXX)

# Configuration C++
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Optimisations de performance
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags optimisés pour performance réseau
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -mtune=native -DNDEBUG -flto")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g3 -ggdb -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer")

# Options de compilation supplémentaires pour la performance
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(
        -ffast-math
        -funroll-loops
        -fprefetch-loop-arrays
        -fno-stack-protector
    )
endif()

# Recherche des dépendances système
find_package(PkgConfig REQUIRED)

# NetFilter Queue pour NFQUEUE
pkg_check_modules(NETFILTER_QUEUE REQUIRED libnetfilter_queue)
if(NOT NETFILTER_QUEUE_FOUND)
    message(FATAL_ERROR "libnetfilter_queue not found. Install with: sudo apt install libnetfilter-queue-dev")
endif()

# nlohmann JSON
find_package(nlohmann_json 3.2.0 QUIET)
if(NOT nlohmann_json_FOUND)
    # Fallback pour systèmes sans package nlohmann-json
    find_path(NLOHMANN_JSON_INCLUDE_DIR
        NAMES nlohmann/json.hpp
        PATHS /usr/include /usr/local/include
    )
    if(NOT NLOHMANN_JSON_INCLUDE_DIR)
        message(FATAL_ERROR "nlohmann/json not found. Install with: sudo apt install nlohmann-json3-dev")
    endif()
endif()

# Threads
find_package(Threads REQUIRED)

# PCRE2 pour regex haute performance
pkg_check_modules(PCRE2 REQUIRED libpcre2-8)
if(NOT PCRE2_FOUND)
    message(FATAL_ERROR "libpcre2 not found. Install with: sudo apt install libpcre2-dev")
endif()

# Collecte des fichiers source
file(GLOB_RECURSE SOURCES 
    src/*.cpp
    src/engine/*.cpp
    src/handlers/*.cpp
    src/loaders/*.cpp
)

# Headers
include_directories(src)

# Exécutable principal
add_executable(tiger-fox ${SOURCES})

# Définitions du préprocesseur
target_compile_definitions(tiger-fox PRIVATE
    TIGER_FOX_VERSION_MAJOR=2
    TIGER_FOX_VERSION_MINOR=0
    TIGER_FOX_VERSION_PATCH=0
    $<$<CONFIG:Debug>:TIGER_FOX_DEBUG>
    $<$<CONFIG:Release>:TIGER_FOX_RELEASE>
)

# Liaison des bibliothèques
target_link_libraries(tiger-fox 
    ${NETFILTER_QUEUE_LIBRARIES}
    ${PCRE2_LIBRARIES}
    Threads::Threads
    pthread
)

# nlohmann-json linking
if(nlohmann_json_FOUND)
    target_link_libraries(tiger-fox nlohmann_json::nlohmann_json)
else()
    target_include_directories(tiger-fox PRIVATE ${NLOHMANN_JSON_INCLUDE_DIR})
endif()

# Include directories pour les dépendances
target_include_directories(tiger-fox PRIVATE 
    ${NETFILTER_QUEUE_INCLUDE_DIRS}
    ${PCRE2_INCLUDE_DIRS}
)

# Flags de compilation pour les dépendances
target_compile_options(tiger-fox PRIVATE
    ${NETFILTER_QUEUE_CFLAGS_OTHER}
    ${PCRE2_CFLAGS_OTHER}
)

# Options de l'éditeur de liens pour la performance
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_link_options(tiger-fox PRIVATE
        -flto
        -Wl,--gc-sections
        -Wl,--strip-all
    )
endif()

# Installation
install(TARGETS tiger-fox
    DESTINATION bin
)

install(FILES config.json
    DESTINATION etc/tiger-fox
)

install(DIRECTORY rules/
    DESTINATION share/tiger-fox/rules
)

# Messages informatifs
message(STATUS "==================================================")
message(STATUS "Tiger-Fox C++ Network Filtering System")
message(STATUS "==================================================")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Compiler flags: ${CMAKE_CXX_FLAGS}")

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    message(STATUS "Release flags: ${CMAKE_CXX_FLAGS_RELEASE}")
else()
    message(STATUS "Debug flags: ${CMAKE_CXX_FLAGS_DEBUG}")
endif()

message(STATUS "")
message(STATUS "Dependencies:")
message(STATUS "  NetFilter Queue: ${NETFILTER_QUEUE_VERSION}")
message(STATUS "  PCRE2: ${PCRE2_VERSION}")
message(STATUS "  nlohmann-json: ${nlohmann_json_FOUND}")
message(STATUS "  Threads: Available")
message(STATUS "")
message(STATUS "Features:")
message(STATUS "  Multi-worker architecture: YES")
message(STATUS "  TCP reassembly: YES") 
message(STATUS "  High-resolution timing: YES")
message(STATUS "  CPU affinity: YES")
message(STATUS "  Performance optimizations: YES")
message(STATUS "==================================================")