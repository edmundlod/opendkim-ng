# --- Package Version Logic ---
set(VERSION_RELEASE 3)
set(VERSION_MAJOR_REV 0)
set(VERSION_MINOR_REV 0)
set(VERSION_PATCH 0)

# Define the human-readable version string
set(PACKAGE_VERSION "${VERSION_RELEASE}.${VERSION_MAJOR_REV}.${VERSION_MINOR_REV}")

# --- Library Version Logic (Libtool equivalent) ---
set(LIBVERSION_CURRENT 13)
set(LIBVERSION_REVISION 0)
set(LIBVERSION_AGE 0)

# LIBOPENDKIM_VERSION_INFO (simple concatenation)
set(LIBOPENDKIM_VERSION_INFO "${LIBVERSION_CURRENT}:${LIBVERSION_REVISION}:${LIBVERSION_AGE}")

# --- Hexadecimal Version Logic for the library (for dkim.h) ---

# 1. Perform the bitwise math
# Formula: ((RELEASE << 8 | MAJOR) << 8 | MINOR) << 8 | PATCH
math(EXPR HEX_VAL "(((${LIBVERSION_CURRENT} << 8) | ${LIBVERSION_REVISION}) << 8 | ${LIBVERSION_AGE}) << 8")

# 2. Convert to Hexadecimal string (requires CMake 3.13+)
math(EXPR RAW_HEX "${HEX_VAL}" OUTPUT_FORMAT HEXADECIMAL)

# 3. Handle Padding (0x08x)
# math() returns "0x..." but doesn't guarantee 8 digits of padding.
string(SUBSTRING "${RAW_HEX}" 2 -1 HEX_BODY) # Strip "0x"
string(LENGTH "${HEX_BODY}" HEX_LEN)

while(HEX_LEN LESS 8)
    string(PREPEND HEX_BODY "0")
    string(LENGTH "${HEX_BODY}" HEX_LEN)
endwhile()

set(HEX_VERSION "0x${HEX_BODY}")

# --- Output for Verification ---
message(STATUS "Package Version: ${PACKAGE_VERSION}")
message(STATUS "Libtool Version: ${LIBOPENDKIM_VERSION_INFO}")
message(STATUS "Hex Version:     ${HEX_VERSION}")

# ── Required modules ──────────────────────────────────────────────────────────

include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckSymbolExists)
include(GNUInstallDirs)
include(CheckIncludeFiles)

check_include_files("sys/param.h" HAVE_SYS_PARAM_H)
check_include_files("sys/file.h" HAVE_SYS_FILE_H)
check_include_files("paths.h" HAVE_PATHS_H)
check_include_files("sys/vfs.h" HAVE_SYS_VFS_H)
check_include_files("sys/statfs.h" HAVE_SYS_STATFS_H)

# ── OpenSSL 3 (required) ──────────────────────────────────────────────────────

find_package(OpenSSL 3.0 REQUIRED)

# ── LMDB (required) ───────────────────────────────────────────────────────────

find_package(PkgConfig QUIET)

set(LMDB_TARGET "")

if(PKG_CONFIG_FOUND)
    pkg_check_modules(LMDB IMPORTED_TARGET lmdb)
    if(LMDB_FOUND)
        set(LMDB_TARGET PkgConfig::LMDB)
    endif()
endif()

if(NOT LMDB_FOUND)
    find_library(LMDB_LIBRARY NAMES lmdb)
    find_path(LMDB_INCLUDE_DIR NAMES lmdb.h)
    if(LMDB_LIBRARY AND LMDB_INCLUDE_DIR)
        set(LMDB_FOUND TRUE)
        add_library(lmdb_imported UNKNOWN IMPORTED)
        set_target_properties(lmdb_imported PROPERTIES
            IMPORTED_LOCATION "${LMDB_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${LMDB_INCLUDE_DIR}"
        )
        set(LMDB_TARGET lmdb_imported)
    else()
        message(FATAL_ERROR "LMDB not found. Install liblmdb-dev / lmdb-devel.")
    endif()
endif()

# ── Lua 5.4 (optional, default OFF) ──────────────────────────────────────────

option(WITH_LUA "Build with Lua 5.4 scripting support" OFF)

if(WITH_LUA)
    find_package(Lua 5.4 EXACT REQUIRED)
endif()

# ── pthreads (required) ───────────────────────────────────────────────────────

find_package(Threads REQUIRED)

# ── libresolv ─────────────────────────────────────────────────────────────────
# On glibc 2.26+, FreeBSD, and OpenBSD the resolver lives in libc.
# On older glibc it needs -lresolv.  Use the library if found; it is harmless
# to link it even when the symbols are already in libc.

find_library(RESOLV_LIBRARY NAMES resolv)

include(CheckFunctionExists)
include(CheckLibraryExists)

# Logic to find where DNS functions reside
check_function_exists(res_query HAVE_RES_QUERY_LIBC)

if(NOT HAVE_RES_QUERY_LIBC)
    check_library_exists(resolv res_query "" HAVE_LIBRESOLV)
    if(HAVE_LIBRESOLV)
        set(DNS_LIB resolv)
    else()
        check_library_exists(nsl res_query "" HAVE_LIBNSL)
        if(HAVE_LIBNSL)
            set(DNS_LIB nsl)
        endif()
    endif()
endif()

# Check for networking conversion functions
check_function_exists(inet_pton HAVE_INET_PTON)
check_function_exists(inet_ntop HAVE_INET_NTOP)
check_function_exists(getaddrinfo HAVE_GETADDRINFO)

# ── libunbound (optional DNSSEC async resolver) ──────────────────────────────
option(WITH_UNBOUND "Enable libunbound DNSSEC async resolver support" ON)

if(WITH_UNBOUND)
    pkg_check_modules(UNBOUND IMPORTED_TARGET libunbound)

    if(NOT UNBOUND_FOUND)
        # Fallback for systems without pkg-config (BSD/macOS)
        find_path(UNBOUND_INCLUDE_DIR NAMES unbound.h)
        find_library(UNBOUND_LIBRARY NAMES unbound)
        if(UNBOUND_INCLUDE_DIR AND UNBOUND_LIBRARY)
            set(UNBOUND_FOUND TRUE)
            add_library(PkgConfig::UNBOUND UNKNOWN IMPORTED)
            set_target_properties(PkgConfig::UNBOUND PROPERTIES
                IMPORTED_LOCATION "${UNBOUND_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${UNBOUND_INCLUDE_DIR}"
            )
        endif()
    endif()

    if(UNBOUND_FOUND)
        message(STATUS "libunbound found: enabling DNSSEC support")
        # Ensure build-config.h gets these
        set(USE_UNBOUND 1)
        set(HAVE_UNBOUND_H 1)
    else()
        message(WARNING "libunbound not found: DNSSEC disabled")
    endif()
endif()

# ── strlcpy / strlcat detection ───────────────────────────────────────────────
# Detection order per SCOPE.md:
#   1. system libc (glibc 2.38+, FreeBSD, OpenBSD) → no extra library needed
#   2. libbsd                                       → link -lbsd, USE_BSD_H
#   3. neither                                      → compile compat/strl.c

check_function_exists(strlcpy HAVE_STRLCPY_IN_LIBC)
check_function_exists(strlcat HAVE_STRLCAT_IN_LIBC)

set(STRL_SOURCES "")
set(STRL_LIBRARY "")
set(USE_BSD_H FALSE)
set(USE_STRL_H FALSE)

if(NOT (HAVE_STRLCPY_IN_LIBC AND HAVE_STRLCAT_IN_LIBC))
    find_library(BSD_LIBRARY NAMES bsd)
    if(BSD_LIBRARY)
        check_include_file("bsd/string.h" HAVE_BSD_STRING_H)
        if(HAVE_BSD_STRING_H)
            set(STRL_LIBRARY "${BSD_LIBRARY}")
            set(USE_BSD_H TRUE)
        endif()
    endif()

    if(NOT STRL_LIBRARY)
        # Fall back to bundled compat implementation
        set(STRL_SOURCES "${CMAKE_SOURCE_DIR}/compat/strl.c")
        if(NOT EXISTS "${STRL_SOURCES}")
            message(FATAL_ERROR
                "strlcpy/strlcat not found in libc or libbsd, and "
                "compat/strl.c does not exist. Create it or install libbsd-dev.")
        endif()
    endif()
endif()

# ── DNS feature checks ────────────────────────────────────────────────────────

set(CMAKE_REQUIRED_LIBRARIES ${RESOLV_LIBRARY})
check_symbol_exists(res_ninit "resolv.h" HAVE_RES_NINIT)
check_symbol_exists(res_setservers "resolv.h" HAVE_RES_SETSERVERS)
unset(CMAKE_REQUIRED_LIBRARIES)

# ── Standard header checks ────────────────────────────────────────────────────

check_include_file(limits.h   HAVE_LIMITS_H)
check_include_file(stdbool.h  HAVE_STDBOOL_H)


# ── Daemon-specific configuration ────────────────────────────────────────────
# Package version
set(SENDMAIL_PATH "/usr/sbin/sendmail" CACHE STRING "Path to sendmail binary")
set(CONFIG_BASE "/etc/opendkim" CACHE STRING "Base path for config files")

# Check for smfi_version (milter version reporting)
# 1. Dynamically find the header and library paths
find_path(MILTER_INCLUDE_DIR NAMES libmilter/mfapi.h mfapi.h)
find_library(MILTER_LIBRARY NAMES milter)

if(MILTER_INCLUDE_DIR AND MILTER_LIBRARY)
    # 2. Use the discovered paths for the functional check
    set(CMAKE_REQUIRED_INCLUDES "${MILTER_INCLUDE_DIR}")
    set(CMAKE_REQUIRED_LIBRARIES "${MILTER_LIBRARY}")

    include(CheckSymbolExists)

    # Use a unique internal variable to avoid CMake's "sticky" cache issue
    check_symbol_exists(smfi_version "libmilter/mfapi.h" HAVE_SMFI_VERSION_INTERNAL)
    check_symbol_exists(smfi_insheader  "libmilter/mfapi.h" HAVE_SMFI_INSHEADER)
    check_symbol_exists(smfi_opensocket "libmilter/mfapi.h" HAVE_SMFI_OPENSOCKET)
    check_symbol_exists(smfi_progress   "libmilter/mfapi.h" HAVE_SMFI_PROGRESS)
    check_symbol_exists(smfi_setsymlist "libmilter/mfapi.h" HAVE_SMFI_SETSYMLIST)

    if(NOT HAVE_SMFI_VERSION_INTERNAL)
        # Fallback for systems where it's just <mfapi.h> without the libmilter/ prefix
        check_symbol_exists(smfi_version "mfapi.h" HAVE_SMFI_VERSION_INTERNAL)
        check_symbol_exists(smfi_insheader  "mfapi.h" HAVE_SMFI_INSHEADER)
        check_symbol_exists(smfi_opensocket "mfapi.h" HAVE_SMFI_OPENSOCKET)
        check_symbol_exists(smfi_progress   "mfapi.h" HAVE_SMFI_PROGRESS)
        check_symbol_exists(smfi_setsymlist "mfapi.h" HAVE_SMFI_SETSYMLIST)
    endif()

    # 3. Finalize the variable for your config.h
    set(HAVE_SMFI_VERSION ${HAVE_SMFI_VERSION_INTERNAL} CACHE INTERNAL "smfi_version availability")

    unset(CMAKE_REQUIRED_INCLUDES)
    unset(CMAKE_REQUIRED_LIBRARIES)
endif()

# Check for BSD socket structure member checks
include(CheckStructHasMember)
check_struct_has_member("struct stat" "st_node" "sys/stat.h" HAVE_ST_NODE)
check_struct_has_member("struct sockaddr_un"  sun_len  "sys/un.h"     HAVE_SUN_LEN)
check_struct_has_member("struct sockaddr_in"  sin_len  "netinet/in.h" HAVE_SIN_LEN)
check_struct_has_member("struct sockaddr_in6" sin6_len "netinet/in.h" HAVE_SIN6_LEN)

# ── Generate build-config.h ───────────────────────────────────────────────────
configure_file(
    build-config.h.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/build-config.h
    @ONLY
)

# ── Process dkim.h to inject the hex version ──────────────────────────────────
configure_file(
    dkim.h
    ${CMAKE_CURRENT_BINARY_DIR}/opendkim/dkim.h
    @ONLY
)

# ── Library sources ───────────────────────────────────────────────────────────
# Source list derived from libopendkim/Makefile.am.

set(LIBOPENDKIM_SOURCES
    base64.c
    dkim-cache.c
    dkim-canon.c
    dkim-dns.c
    dkim-keys.c
    dkim-mailparse.c
    dkim-report.c
    dkim-tables.c
    dkim-test.c
    dkim-util.c
    dkim.c
    util.c
    ${STRL_SOURCES}
)

# ── Shared library ────────────────────────────────────────────────────────────

add_library(opendkim SHARED ${LIBOPENDKIM_SOURCES})

set_target_properties(opendkim PROPERTIES
    OUTPUT_NAME   opendkim
    VERSION       13.0.0
    SOVERSION     13
)

# ── Static library ────────────────────────────────────────────────────────────

add_library(opendkim_static STATIC ${LIBOPENDKIM_SOURCES})

set_target_properties(opendkim_static PROPERTIES
    OUTPUT_NAME opendkim
)

# ── Common configuration helper ───────────────────────────────────────────────

function(configure_opendkim_target tgt)
    target_include_directories(${tgt}
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/opendkim>
        PRIVATE
            ${CMAKE_CURRENT_BINARY_DIR}   # build-config.h lives here
    )

    # Inject the version hex directly into the source code
    target_compile_definitions(${tgt} PUBLIC
        OPENDKIM_LIB_VERSION=${HEX_VERSION}
    )

    # Always-on compile definitions for this modern build
    target_compile_definitions(${tgt} PRIVATE
        HAVE_SHA256=1
        USE_MDB=1
        _FFR_RESIGN=1
        _FFR_IDENTITY_HEADER=1
        _FFR_SENDER_MACRO=1
    )

    if(HAVE_RES_NINIT)
        target_compile_definitions(${tgt} PRIVATE HAVE_RES_NINIT=1)
    endif()
    if(HAVE_RES_SETSERVERS)
        target_compile_definitions(${tgt} PRIVATE HAVE_RES_SETSERVERS=1)
    endif()
    if(HAVE_LIMITS_H)
        target_compile_definitions(${tgt} PRIVATE HAVE_LIMITS_H=1)
    endif()
    if(HAVE_STDBOOL_H)
        target_compile_definitions(${tgt} PRIVATE HAVE_STDBOOL_H=1)
    endif()
    if(USE_BSD_H)
        target_compile_definitions(${tgt} PRIVATE USE_BSD_H=1)
    endif()

    target_link_libraries(${tgt}
        PUBLIC  OpenSSL::Crypto
        PRIVATE Threads::Threads ${LMDB_TARGET}
    )

    if(UNBOUND_FOUND)
        target_include_directories(${tgt} PRIVATE ${UNBOUND_INCLUDE_DIRS})
        target_link_libraries(${tgt} PRIVATE PkgConfig::UNBOUND)

        target_compile_definitions(${tgt} PRIVATE
            USE_UNBOUND=1
            HAVE_UNBOUND_H=1
        )
    endif()

    if(RESOLV_LIBRARY)
        target_link_libraries(${tgt} PRIVATE ${RESOLV_LIBRARY})
    endif()

    if(STRL_LIBRARY)
        target_link_libraries(${tgt} PRIVATE ${STRL_LIBRARY})
    endif()

    if(WITH_LUA)
        target_link_libraries(${tgt} PRIVATE ${LUA_LIBRARIES})
        target_include_directories(${tgt} PRIVATE ${LUA_INCLUDE_DIR})
        target_compile_definitions(${tgt} PRIVATE USE_LUA=1)
    endif()
endfunction()

configure_opendkim_target(opendkim)
configure_opendkim_target(opendkim_static)

# ── Public header install ─────────────────────────────────────────────────────

install(FILES dkim.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/opendkim
)

install(TARGETS opendkim opendkim_static
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# ── pkg-config .pc file ───────────────────────────────────────────────────────

set(OPENDKIM_PC_REQUIRES_PRIVATE "")
set(OPENDKIM_PC_PRIVATE_LIBS "")

if(UNBOUND_FOUND)
    string(APPEND OPENDKIM_PC_REQUIRES_PRIVATE " libunbound")
endif()

if(LMDB_FOUND AND PKG_CONFIG_FOUND)
    string(APPEND OPENDKIM_PC_REQUIRES_PRIVATE " lmdb")
else()
    string(APPEND OPENDKIM_PC_PRIVATE_LIBS " -llmdb")
endif()

if(RESOLV_LIBRARY)
    string(APPEND OPENDKIM_PC_PRIVATE_LIBS " -lresolv")
endif()

if(STRL_LIBRARY)
    string(APPEND OPENDKIM_PC_PRIVATE_LIBS " -lbsd")
endif()

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/opendkim.pc.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/opendkim.pc
    @ONLY
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/opendkim.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

# ── Tests ─────────────────────────────────────────────────────────────────────

add_subdirectory(tests)
