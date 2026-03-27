/*
 * Minimal COFF x86-64 test binary for pseudocode/ctree testing.
 *
 * Purpose: Generate a variety of ctree node types to test the IDA Domain
 *          Pseudocode API (if/else, for, while, do-while, goto, switch,
 *          struct access, function calls, assignments, casts, etc.).
 *
 * Compilation (MinGW, produces COFF object):
 *   gcc -O0 -c -o tiny_pseudocode.bin tiny_pseudocode.c
 *
 * Expected functions and ctree features:
 *   - classify     : ternary (optimized from if/else)
 *   - nested_if    : nested if/else, SLE comparisons, NEG, SUB, ADD, 3 returns
 *   - use_switch   : if-chain + GOTO (compiler converts switch to if-chain at -O0)
 *   - use_for      : FOR loop with PREINC step, BREAK, SGE comparison
 *   - use_while    : WHILE loop with POSTDEC, SGT comparison
 *   - use_string   : CALL to strlen
 *   - use_struct   : PTR dereference, IDX (array index) for struct field access
 *   - main         : 8 CALL expressions with various argument counts
 */

#include <string.h>

volatile int sink;
const char *msg = "hello";

struct Point { int x; int y; };

void classify(int x) {
    if (x > 10)
        sink = 1;
    else
        sink = 0;
}

void nested_if(int a, int b) {
    if (a > 0) {
        if (b > 0)
            sink = a + b;
        else
            sink = a - b;
    } else {
        sink = -a;
    }
}

void use_switch(int v) {
    switch (v) {
        case 1: sink = 10; break;
        case 2: sink = 20; break;
        case 3: sink = 30; break;
        default: sink = 0; break;
    }
}

void use_for(int n) {
    for (int i = 0; i < n; i++)
        sink = i;
}

void use_while(int n) {
    while (n > 0) {
        sink = n;
        n--;
    }
}

int use_string(void) {
    return strlen(msg);
}

void use_struct(struct Point *p) {
    sink = p->x + p->y;
}

int main(int argc, char **argv) {
    struct Point pt = {1, 2};
    classify(argc);
    nested_if(argc, argc + 1);
    use_switch(argc);
    use_for(argc);
    use_while(argc);
    sink = use_string();
    use_struct(&pt);
    return 0;
}
