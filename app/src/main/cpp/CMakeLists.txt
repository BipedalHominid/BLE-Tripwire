cmake_minimum_required(VERSION 3.22.1)
project(bluesentinel)

# ---------------------------------------------------------------------------
# Import the prebuilt nodejs-mobile shared library (libnode.so) for the ABI
# currently being built. The .so files are NOT committed to the repo (they are
# ~60 MB each); run scripts/fetch-libnode.sh once to download the pinned
# nodejs-mobile release and drop them into app/src/main/jniLibs/<abi>/.
# ---------------------------------------------------------------------------
set(LIBNODE_INCLUDE "${CMAKE_SOURCE_DIR}/libnode/include/node")
set(LIBNODE_SO "${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libnode.so")

if(NOT EXISTS "${LIBNODE_SO}")
    message(FATAL_ERROR
        "libnode.so not found for ABI '${ANDROID_ABI}' at:\n  ${LIBNODE_SO}\n"
        "Run scripts/fetch-libnode.sh from the project root first "
        "(it downloads the pinned nodejs-mobile v18.20.4 Android library).")
endif()

add_library(node SHARED IMPORTED)
set_target_properties(node PROPERTIES IMPORTED_LOCATION "${LIBNODE_SO}")

# ---------------------------------------------------------------------------
# Our JNI bridge.
# ---------------------------------------------------------------------------
add_library(native-lib SHARED native-lib.cpp)

target_include_directories(native-lib PRIVATE "${LIBNODE_INCLUDE}")

find_library(log-lib log)

target_link_libraries(native-lib
    node
    ${log-lib})
