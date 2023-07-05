cmake_minimum_required(VERSION 3.1)
project(TestApp)

file(GLOB SRC_FILES "src/*.c")
add_executable(scratchpad ${SRC_FILES})
