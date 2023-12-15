mov x5, #0x552f
movk x5, #0x6573, lsl #16
movk x5, #0x7372, lsl #32
movk x5, #0x6a2f, lsl #48
str x5, [sp, #-48]

mov x5, #0x6e65
movk x5, #0x696b, lsl #16
movk x5, #0x736e, lsl #32
movk x5, #0x742f, lsl #48
str x5, [sp, #-40]

mov x5, #0x7365
movk x5, #0x6974, lsl #16
movk x5, #0x676e, lsl #32
movk x5, #0x742f, lsl #48
str x5, [sp, #-32]

mov x5, #0x7365
movk x5, #0x0074, lsl #16
movk x5, #0x0000, lsl #32
movk x5, #0x0000, lsl #48
str x5, [sp, #-24]

mov x5, sp
sub x5, x5, #48
stp x5, xzr, [sp, #-16]

ldr x16, =0x200003b  // Load sys number for SYS_EXECVE
mov x0, sp           // Arg0: char* path - Pointer to the current stack position
sub x0, x0, 48  // subtract to the base of the program name

mov x1, sp          // Arg1: char *const argv[] - program name pointer for now
sub x1, x1, 16
mov x2, xzr         // Arg2: char *const envp[] - NULL for now

svc #0              // Supervisor call - i.e. the system call

