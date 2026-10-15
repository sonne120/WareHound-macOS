cmake_minimum_required(VERSION 3.16)
project(libsniffer CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(APPLE AND NOT DEFINED CMAKE_OSX_DEPLOYMENT_TARGET)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "14.0" CACHE STRING "Minimum macOS deployment target" FORCE)
endif()

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# ---- Warnings & per-compiler tuning ----
if(MSVC)
    add_compile_options(/W4 /permissive- /Zc:__cplusplus)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)
endif()

# ---- Find libpcap / Npcap ----
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PCAP IMPORTED_TARGET libpcap)
endif()

if(WIN32)
    if(NOT DEFINED NPCAP_SDK AND DEFINED ENV{NPCAP_SDK})
        set(NPCAP_SDK $ENV{NPCAP_SDK})
    endif()
    # Fallback: use the bundled WpdPack in the repo
    set(_WPDPACK_FALLBACK "${CMAKE_CURRENT_SOURCE_DIR}/../header/WpdPack/WpdPack")
    if(NOT NPCAP_SDK AND EXISTS "${_WPDPACK_FALLBACK}/Include")
        message(STATUS "NPCAP_SDK not set — using bundled WpdPack at ${_WPDPACK_FALLBACK}")
        set(PCAP_INCLUDE_DIRS "${_WPDPACK_FALLBACK}/Include")
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(PCAP_LIBRARY "${_WPDPACK_FALLBACK}/Lib/x64/wpcap.lib")
        else()
            set(PCAP_LIBRARY "${_WPDPACK_FALLBACK}/Lib/wpcap.lib")
        endif()
    elseif(NPCAP_SDK)
        set(PCAP_INCLUDE_DIRS "${NPCAP_SDK}/Include")
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(PCAP_LIBRARY "${NPCAP_SDK}/Lib/x64/wpcap.lib")
        else()
            set(PCAP_LIBRARY "${NPCAP_SDK}/Lib/wpcap.lib")
        endif()
    else()
        message(WARNING
            "NPCAP_SDK not set and bundled WpdPack not found. "
            "Pass -DNPCAP_SDK=<path> to cmake.")
    endif()
    set(WS2_32 ws2_32.lib)
else()
    if(NOT PCAP_FOUND)
        find_path(PCAP_INCLUDE_DIR NAMES pcap/pcap.h pcap.h PATHS /usr/local/include /opt/homebrew/include)
        find_library(PCAP_LIBRARY NAMES pcap PATHS /usr/local/lib /opt/homebrew/lib)
        if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
            set(PCAP_FOUND TRUE)
            set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
        endif()
    endif()
    if(NOT PCAP_FOUND AND NOT PCAP_INCLUDE_DIRS)
        message(FATAL_ERROR
            "libpcap not found. Install libpcap-dev (Debian/Ubuntu) "
            "or libpcap-devel (Fedora) or 'brew install libpcap' (macOS).")
    endif()
endif()

# ---- The library ----
add_library(sniffer SHARED
    src/capture/device_scanner.cpp
    src/pcap_source.cpp
    src/api/ipc_pipe.cpp
    src/api/ipc.cpp
    src/api/statistic_exports.cpp
    src/api/capture_source.cpp
    src/api/l7_stats.cpp
    src/api/reassembly.cpp
    src/api/tls_decrypt.cpp
    src/api/quic_decrypt.cpp
)

if(APPLE)
    set_target_properties(sniffer PROPERTIES
        OUTPUT_NAME "sniffer"
        PREFIX "lib"
        SUFFIX ".dylib"
    )
elseif(UNIX)
    set_target_properties(sniffer PROPERTIES
        OUTPUT_NAME "sniffer"
        PREFIX "lib"
        SUFFIX ".so"
    )
elseif(WIN32)
    set_target_properties(sniffer PROPERTIES
        OUTPUT_NAME "sniffer"
        SUFFIX ".dll"
    )
endif()

target_include_directories(sniffer
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

if(WIN32)
    if(PCAP_INCLUDE_DIRS)
        target_include_directories(sniffer PRIVATE ${PCAP_INCLUDE_DIRS})
    endif()
    if(PCAP_LIBRARY)
        target_link_libraries(sniffer PUBLIC ${PCAP_LIBRARY} ${WS2_32})
    endif()
    target_compile_definitions(sniffer PUBLIC WPCAP HAVE_REMOTE)

    # Export all symbols on Windows
    set_target_properties(sniffer PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
    target_compile_definitions(sniffer PRIVATE
        _WINDOWS
        _USRDLL
        WAREHOUND_SNIFFER_EXPORTS
    )
else()
    if(TARGET PkgConfig::PCAP)
        target_link_libraries(sniffer PUBLIC PkgConfig::PCAP)
    else()
        target_include_directories(sniffer PRIVATE ${PCAP_INCLUDE_DIRS})
        target_link_libraries(sniffer PUBLIC ${PCAP_LIBRARY})
    endif()
endif()

find_package(Threads REQUIRED)
target_link_libraries(sniffer PUBLIC Threads::Threads)

# ---- OpenSSL libcrypto (TLS key-log decryption) -------------------------
# Static-link libcrypto so the app bundle needs no extra dylib. Prefer a
# Homebrew openssl@3 archive; fall back to find_package(OpenSSL).
find_path(CRYPTO_INCLUDE_DIR openssl/evp.h
    PATHS /opt/homebrew/opt/openssl@3/include /usr/local/opt/openssl@3/include
          /opt/homebrew/include /usr/local/include)
find_library(CRYPTO_STATIC NAMES libcrypto.a
    PATHS /opt/homebrew/opt/openssl@3/lib /usr/local/opt/openssl@3/lib
          /opt/homebrew/lib /usr/local/lib)
if(CRYPTO_INCLUDE_DIR AND CRYPTO_STATIC)
    target_include_directories(sniffer PRIVATE ${CRYPTO_INCLUDE_DIR})
    target_link_libraries(sniffer PRIVATE ${CRYPTO_STATIC})
    message(STATUS "libsniffer: TLS decryption via static libcrypto (${CRYPTO_STATIC})")
else()
    find_package(OpenSSL REQUIRED)
    target_link_libraries(sniffer PRIVATE OpenSSL::Crypto)
    message(STATUS "libsniffer: TLS decryption via OpenSSL::Crypto (shared)")
endif()

# ---- nghttp2 (HPACK for HTTP/2 + gRPC header decode) --------------------
# Prefer a static archive so the bundle needs no extra dylib; fall back to the
# shared Homebrew lib.
find_path(NGHTTP2_INCLUDE_DIR nghttp2/nghttp2.h
    PATHS /opt/homebrew/opt/libnghttp2/include /usr/local/opt/libnghttp2/include
          /opt/homebrew/include /usr/local/include)
find_library(NGHTTP2_STATIC NAMES libnghttp2.a
    PATHS /opt/homebrew/opt/libnghttp2/lib /usr/local/opt/libnghttp2/lib
          /opt/homebrew/lib /usr/local/lib)
find_library(NGHTTP2_SHARED NAMES nghttp2
    PATHS /opt/homebrew/opt/libnghttp2/lib /usr/local/opt/libnghttp2/lib
          /opt/homebrew/lib /usr/local/lib)
if(NGHTTP2_INCLUDE_DIR AND (NGHTTP2_STATIC OR NGHTTP2_SHARED))
    target_include_directories(sniffer PRIVATE ${NGHTTP2_INCLUDE_DIR})
    if(NGHTTP2_STATIC)
        target_link_libraries(sniffer PRIVATE ${NGHTTP2_STATIC})
        message(STATUS "libsniffer: HTTP/2 HPACK via static libnghttp2 (${NGHTTP2_STATIC})")
    else()
        target_link_libraries(sniffer PRIVATE ${NGHTTP2_SHARED})
        message(STATUS "libsniffer: HTTP/2 HPACK via shared nghttp2 (${NGHTTP2_SHARED})")
    endif()
else()
    message(FATAL_ERROR "nghttp2 not found. Install with: brew install nghttp2")
endif()

# ---- Optional: tunnel mode (Rust smoltcp core) --------------------------
# Off by default so the existing libpcap build is unchanged. Enable with:
#   cmake -B build -DWAREHOUND_ENABLE_TUNNEL=ON
# Requires a Rust toolchain; pulls the `snet` staticlib in via Corrosion.
option(WAREHOUND_ENABLE_TUNNEL "Build the Rust smoltcp tunnel core" OFF)

if(WAREHOUND_ENABLE_TUNNEL)
    include(FetchContent)
    FetchContent_Declare(
        Corrosion
        GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
        GIT_TAG v0.5
    )
    FetchContent_MakeAvailable(Corrosion)

    corrosion_import_crate(MANIFEST_PATH rust/snet/Cargo.toml)

    target_compile_definitions(sniffer PRIVATE WAREHOUND_ENABLE_TUNNEL)
    target_link_libraries(sniffer PRIVATE snet)
    message(STATUS "libsniffer: tunnel mode ENABLED (Rust snet + smoltcp)")
else()
    message(STATUS "libsniffer: tunnel mode disabled (pcap-only build)")
endif()

# ---- Example ----
add_executable(simple_sniff examples/simple_sniff.cpp)
target_link_libraries(simple_sniff PRIVATE sniffer)
set_target_properties(simple_sniff PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

# ---- Tests (optional; only if GTest is available) ----
option(SNIFFER_BUILD_TESTS "Build the GoogleTest suite" ON)
if(SNIFFER_BUILD_TESTS)
    find_package(GTest QUIET)
    if(GTest_FOUND)
        enable_testing()
        add_executable(pipeline_gtest tests/pipeline_gtest.cpp)
        target_link_libraries(pipeline_gtest PRIVATE sniffer GTest::gtest GTest::gtest_main)
        set_target_properties(pipeline_gtest PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
        add_test(NAME pipeline_gtest COMMAND pipeline_gtest)
    else()
        message(STATUS "libsniffer: GTest not found — skipping tests")
    endif()
endif()
