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
.\build\scratchpad\src\Debug\scratchpad.exe

# Release
.\build\scratchpad\src\Release\scratchpad.exe
```

### Editing

If using Visual Studio, ensure the `build` directory is created - then open the `build/Scratchpad.sln` file in Visual Studio.

### Resources

- https://cliutils.gitlab.io/modern-cmake/
