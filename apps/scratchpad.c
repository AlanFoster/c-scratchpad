#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>

// /*
//  * osx/x64/exec - 59 bytes
//  * https://metasploit.com/
//  * VERBOSE=true, CMD=/usr/bin/say 'hello world'
//  */
// unsigned char buf[] =
// "\xcc\x48\x31\xd2\xe8\x19\x00\x00\x00\x2f\x75\x73\x72\x2f\x62"
// "\x69\x6e\x2f\x73\x61\x79\x00\x68\x65\x6c\x6c\x6f\x20\x77"
// "\x6f\x72\x6c\x64\x00\x5f\x48\x89\xf9\x52\x48\x81\xc1\x0d"
// "\x00\x00\x00\x51\x57\x48\x89\xe6\x48\xc7\xc0\x3b\x00\x00"
// "\x02\x0f\x05";

/*
 * osx/x64/exec - 33 bytes
 * https://metasploit.com/
 * VERBOSE=true, CMD=/bin/bash
 */
char buf[] =
    "\x48\x31\xd2\xe8\x0a\x00\x00\x00\x2f\x62\x69\x6e\x2f\x62"
    "\x61\x73\x68\x00\x5f\x52\x57\x48\x89\xe6\x48\xc7\xc0\x3b"
    "\x00\x00\x02\x0f\x05";

// char buf[] = "\x40\x00\x20\xD4";

int main() {
    // char foo[2048] = { 0 };
    // memcpy(foo, buf, sizeof(buf));

    size_t mmap_len = sizeof(buf);

    printf("connect: %x\n", MSG_WAITALL);

    // // 1) mmap writable memory
    int mmap_flags = MAP_PRIVATE | MAP_ANON;
    int mmap_prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    printf("mmap_flags: %x\n", mmap_flags);
    printf("mmap_prot: %x %d\n", mmap_prot, mmap_prot);
    void* mem = mmap(
        // void *addr - If addr is zero, an address will be selected by the system
        0,
        // size_t len
        mmap_len,
        // int prot
        mmap_prot,
        // int flags
        mmap_flags,
        // int fildes,
        -1,
        // off_t offset
        0
    );
    printf("Checking against MAP_FAILED (%p == %p)\n", MAP_FAILED, mem);
    if (mem == MAP_FAILED) {
        printf("failed to mmap memory\n");
        printf("Error: %s (%d)", strerror(errno), errno);
        return 1;
    }
IPPROTO_TC
    printf("mmap'd address: %p\n", mem);

    // 2) Write the memory
    memcpy(mem, buf, sizeof(buf));
    printf("memory written\n");

    // 3) Flip mmap'd region to executable
    int mprotect_flags = PROT_READ | PROT_EXEC;
    printf("mprotect_flags=%x\n", mprotect_flags);
    int mprotect_result = mprotect(
        // void *addr
        mem,
        // size_t len
        mmap_len,
        // int prot
        mprotect_flags
    );

    printf("mprotect result %d\n", mprotect_result);
    if (mprotect_result != 0) {
        printf("failed to mprotect memory\n");
        printf("Error: %s (%d)", strerror(errno), errno);
        return 1;
    }

    // 4) Exec the shellcode
    ((void (*)()) mem)();

    // char path[] = "/bin/bash";
    // char *argv[] = { NULL };
    // char *env[] = { NULL };

    // execve(
    //     path,
    //     argv,
    //     env
    // );

    // char hello_world[] = "hello world\n";

    // FILE* file = fopen("file.txt", "wb+");
    // fwrite(hello_world, 1, sizeof(hello_world), file);
    // fclose(file);

    return 0;
}
