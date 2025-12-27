/**
 * Test binary for Imports entity.
 * Calls various libc functions to generate import table entries.
 *
 * Compile: zig cc -target x86_64-linux-gnu -O0 -o test_imports.bin test_imports.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

// Use volatile to prevent optimization
volatile int sink;

void use_stdio(void) {
    printf("Hello from stdio\n");
    fprintf(stderr, "Error message\n");

    char buf[64];
    snprintf(buf, sizeof(buf), "Formatted: %d", 42);
    puts(buf);
}

void use_memory(void) {
    void *p = malloc(1024);
    if (p) {
        memset(p, 0, 1024);
        memcpy(p, "test", 4);
        sink = memcmp(p, "test", 4);
        free(p);
    }

    void *c = calloc(10, sizeof(int));
    if (c) {
        c = realloc(c, 20 * sizeof(int));
        free(c);
    }
}

void use_string(void) {
    const char *s = "Hello, World!";
    sink = strlen(s);

    char buf[64];
    strcpy(buf, s);
    strcat(buf, " Extra");

    sink = strcmp(buf, s);
    sink = strncmp(buf, s, 5);

    char *found = strstr(buf, "World");
    if (found) sink = *found;

    found = strchr(buf, 'W');
    if (found) sink = *found;
}

void use_file(void) {
    int fd = open("/dev/null", O_RDONLY);
    if (fd >= 0) {
        char buf[16];
        read(fd, buf, sizeof(buf));
        close(fd);
    }

    struct stat st;
    stat("/tmp", &st);
}

void use_env(void) {
    char *home = getenv("HOME");
    if (home) sink = home[0];

    sink = getpid();
    sink = getuid();
}

int main(int argc, char **argv) {
    use_stdio();
    use_memory();
    use_string();
    use_file();
    use_env();

    if (argc > 1) {
        sink = atoi(argv[1]);
    }

    return 0;
}
