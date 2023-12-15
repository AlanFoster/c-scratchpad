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

### Debugging

#### Mac

Add breakpoint in C:

```c
# If Intel x86/x64
asm("int3");

# If AArch64
asm("brk #0x1");
```

Breakpoint in payload:

```
# If Intel x86/x64
\xcc

# If AArch64
\x40\x00\x20\xD4
```

Compile target and run with lldb

```
cmake --build build --target scratchpad && lldb --file ./build/apps/scratchpad
```

lldb commands:

- `run` - Run the program
- `bt` - show backtrace
- `register read` - Show registers
- Printing 14 bytes of memory that the `x1` register points to
```
(lldb) memory read -s1 -c 14 $x1
0x100004000: 68 65 6c 6c 6f 20 77 6f 72 6c 64 0a 00 2f        hello world../
```
- Memory reading from the stack with an expression:
`````
(lldb) memory read -s1 -c 14 `$sp - 16`
`````
- https://lldb.llvm.org/use/map.html

### What's present?

- [CMake](https://cmake.org/) setup, with [catch2](https://github.com/catchorg/Catch2) for unit tests
- Simple VirtualAllocEx shellcode injection technique, will inject into either the given pid or will attempt to search and inject into a running notepad process

### Resources

- https://cliutils.gitlab.io/modern-cmake/
- https://drmemory.org/ - System call tracer and memory/handle leak detection
