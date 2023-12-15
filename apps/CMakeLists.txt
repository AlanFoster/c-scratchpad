# New in cmake version 3.12: If the CONFIGURE_DEPENDS flag is specified,
# CMake will add logic to the main build system check target to rerun the
# flagged GLOB commands at build time. If any of the outputs change, CMake
# will regenerate the build system.
# Scratchpad - include everything
add_executable(
    # target
    scratchpad
    # files
    scratchpad.c
    "../include/calculator.h"
    "../src/calculator.c"
)
target_include_directories(scratchpad PUBLIC ../include)

# VirtualAllocExShellCode
add_executable(
    # target
    inject
    # Files
    inject.c
    "../include/VirtualAllocExShellCode.h"
    "../src/VirtualAllocExShellCode.c"
)
target_include_directories(inject PUBLIC ../include)
