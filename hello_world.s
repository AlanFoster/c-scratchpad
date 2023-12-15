# as -arch arm64 ./hello_world.s
# clang -g -arch arm64 ./hello_world.s
.equ SYS_EXIT,   0x2000001
.equ SYS_WRITE,  0x2000004
.equ SYS_EXECVE, 0x200003b

.data

message: .asciz "hello world\n\0"
message_end:
.set message_size, message_end - message
// program: .asciz "/bin/bash"

.text

.global _main
_main:
    //
    // Print hello world from page
    //
    ldr x16, =SYS_WRITE         // The system call number
    mov x0, 0                   // Arg 0: stdout file descriptor
    adrp x1, message@PAGE       // Arg 1: Pointer to string to print.
    add	x1, x1, message@PAGEOFF //        Start off with page pointer, then add the page offset
    mov x2, #message_size       // Arg 2: The size of the message in bytes
    svc #0                      // Supervisor call - i.e. the system call

    //
    // Print hello world from the stack
    //
    ldr x16, =SYS_WRITE         // The system call number
    mov x0, 0                   // Arg 0: stdout file descriptor

    mov x5, #0x6568 // Temporarily store parts of the string in a register, before storing into the stack with 'str'. /bin/bash
    movk x5, #0x6c6c, lsl #16
    movk x5, #0x206f, lsl #32
    movk x5, #0x6f77, lsl #48
    str x5, [sp, #-16]

    mov x5, #0x6c72 // Temporarily store parts of the string in a register, before storing into the stack with 'str'. /bin/bash
    movk x5, #0x2164, lsl #16
    movk x5, #0x5c00, lsl #32
    movk x5, #0x0000, lsl #48
    str x5, [sp, #-8]

    mov x1, sp       // Arg1: Pointer to the start of the string
    sub x1, x1, #16
    mov x2, 12       // Arg 2: The size of the message in bytes
    svc #0                      // Supervisor call - i.e. the system call

    // Execve /bin/bash using the data section
    // ldr x16, =SYS_EXECVE        // The system call number
    // adrp x0, program@PAGE       // Arg 1: Pointer to the program name to run
    // add	x0, x0, program@PAGEOFF //        Start off with page pointer, then add the page offset
    // mov x1, xzr                 // Arg 1: Arguments, NULL for now
    // mov x2, xzr                 // Arg 2: Environment variables, NULL for now
    // svc #0                      // Supervisor call - i.e. the system call

    // Exit 0
    ldr x16, =SYS_EXIT // The system call number
    mov x0, 11         // Arg 0: result code
    svc #0             // Supervisor call - i.e. the system call

