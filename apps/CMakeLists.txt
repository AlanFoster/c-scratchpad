# New in cmake version 3.12: If the CONFIGURE_DEPENDS flag is specified,
# CMake will add logic to the main build system check target to rerun the
# flagged GLOB commands at build time. If any of the outputs change, CMake
# will regenerate the build system.
file(GLOB SRC_FILES CONFIGURE_DEPENDS "../src/*.c" "../src/*.cpp")
file(GLOB HEADER_FILES CONFIGURE_DEPENDS "../include/*.h")

add_executable(scratchpad scratchpad.c ${SRC_FILES} ${HEADER_FILES})
target_include_directories(scratchpad PUBLIC ../include)
