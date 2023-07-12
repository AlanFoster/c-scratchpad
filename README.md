## Scratchpad

A scratchpad for C/C++ code

## Building

Generate build directory, i.e. Visual Studio configuration etc.

```
cmake -S . -B build
```

Compile:

```
# Debug
cmake --build build

# Production
cmake --build build --config Release
```

Run:

```
# Debug
.\build\apps\Debug\scratchpad.exe

# Release
.\build\apps\Release\scratchpad.exe
```

### Editing

If using Visual Studio, ensure the `build` directory is created - then open the `build/Scratchpad.sln` file in Visual Studio.

### Running tests

After building successfully:

```
.\build\test\Debug\tests.exe
```

Or with ctests:

```
ctest --test-dir build
```

In visual studio:
- install CMake Tools extension
- ctrl+shift+p - `Cmake: Configure`
- In the new CMake tab, right click `tests.exe` then select `Build`, and then `Run in Terminal`

### What's present?

- [CMake](https://cmake.org/) setup, with [catch2](https://github.com/catchorg/Catch2) for unit tests
- Simple VirtualAllocEx shellcode injection technique, will inject into either the given pid or will attempt to search and inject into a running notepad process

### Resources

- https://cliutils.gitlab.io/modern-cmake/
- https://drmemory.org/ - System call tracer and memory/handle leak detection
