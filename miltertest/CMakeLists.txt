# Copyright (c) 2026 OpenDKIM contributors
#   All rights reserved.

include(GNUInstallDirs)

if(NOT WITH_LUA)
    return()
endif()

find_package(Lua 5.4 EXACT REQUIRED)

add_executable(miltertest miltertest.c)

target_include_directories(miltertest PRIVATE
    ${CMAKE_SOURCE_DIR}/libopendkim
    ${CMAKE_BINARY_DIR}/libopendkim
    ${LUA_INCLUDE_DIR}
)

target_link_libraries(miltertest PRIVATE
    opendkim
    ${LUA_LIBRARIES}
)

if(BSD_LIBRARY)
    target_link_libraries(miltertest PRIVATE ${BSD_LIBRARY})
endif()

install(TARGETS miltertest DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES miltertest.8 DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)
