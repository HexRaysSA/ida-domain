/*
 * Minimal dynamically-linked ELF64 test binary for imports testing.
 *
 * Purpose: Generate import entries from libc to test the IDA Domain Imports API.
 *
 * Compilation:
 *   gcc -O0 -no-pie -fno-stack-protector tiny_imports.c -o tiny_imports.bin
 *
 * Expected imports (from libc.so.6 or similar):
 *   - printf (named import)
 *   - malloc (named import)
 *   - free (named import)
 *   - puts (named import)
 *   - exit (named import)
 */

#include <stdio.h>
#include <stdlib.h>

/* Global to prevent optimizer from eliminating calls */
volatile void *global_ptr;

int main(int argc, char *argv[]) {
    /* Use printf - common string formatting import */
    printf("IDA Domain Imports Test\n");

    /* Use malloc/free - memory management imports */
    void *ptr = malloc(64);
    if (ptr) {
        global_ptr = ptr;
        free(ptr);
    }

    /* Use puts - simple string output import */
    puts("Testing complete");

    /* Use exit - process termination import */
    exit(0);

    return 0; /* Never reached, but keeps compiler happy */
}
