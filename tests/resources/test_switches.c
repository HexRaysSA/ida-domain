/**
 * Test binary for Switches entity.
 * Contains various switch statement patterns that generate jump tables.
 *
 * Compile: zig cc -target x86_64-linux-gnu -O1 -o test_switches.bin test_switches.c
 * Note: -O1 is needed to generate actual jump tables instead of if-else chains.
 */

#include <stdint.h>

volatile int sink;

// Dense switch: consecutive cases generate a compact jump table
int dense_switch(int x) {
    switch (x) {
        case 0: return 100;
        case 1: return 101;
        case 2: return 102;
        case 3: return 103;
        case 4: return 104;
        case 5: return 105;
        case 6: return 106;
        case 7: return 107;
        default: return -1;
    }
}

// Dense switch with offset: starts at non-zero value
int dense_switch_offset(int x) {
    switch (x) {
        case 10: return 200;
        case 11: return 201;
        case 12: return 202;
        case 13: return 203;
        case 14: return 204;
        case 15: return 205;
        default: return -1;
    }
}

// Sparse switch: non-consecutive cases may generate value table
int sparse_switch(int x) {
    switch (x) {
        case 1:   return 300;
        case 5:   return 301;
        case 10:  return 302;
        case 50:  return 303;
        case 100: return 304;
        case 500: return 305;
        default:  return -1;
    }
}

// Switch with fall-through cases
int fallthrough_switch(int x) {
    int result = 0;
    switch (x) {
        case 0:
        case 1:
        case 2:
            result = 400;
            break;
        case 3:
        case 4:
            result = 401;
            break;
        case 5:
            result = 402;
            // fall through
        case 6:
            result += 10;
            break;
        default:
            result = -1;
    }
    return result;
}

// Switch without default case
int no_default_switch(int x) {
    int result = 0;
    switch (x) {
        case 0: result = 500; break;
        case 1: result = 501; break;
        case 2: result = 502; break;
        case 3: result = 503; break;
    }
    return result;
}

// Nested switches
int nested_switch(int x, int y) {
    switch (x) {
        case 0:
            switch (y) {
                case 0: return 600;
                case 1: return 601;
                case 2: return 602;
                default: return 609;
            }
        case 1:
            switch (y) {
                case 0: return 610;
                case 1: return 611;
                case 2: return 612;
                default: return 619;
            }
        default:
            return -1;
    }
}

// Switch on char (8-bit values)
int char_switch(char c) {
    switch (c) {
        case 'a': return 700;
        case 'b': return 701;
        case 'c': return 702;
        case 'd': return 703;
        case 'e': return 704;
        case 'f': return 705;
        default:  return -1;
    }
}

// Switch with negative cases
int negative_switch(int x) {
    switch (x) {
        case -3: return 800;
        case -2: return 801;
        case -1: return 802;
        case 0:  return 803;
        case 1:  return 804;
        case 2:  return 805;
        default: return -1;
    }
}

// Large switch to ensure jump table generation
int large_switch(int x) {
    switch (x) {
        case 0:  return 900;
        case 1:  return 901;
        case 2:  return 902;
        case 3:  return 903;
        case 4:  return 904;
        case 5:  return 905;
        case 6:  return 906;
        case 7:  return 907;
        case 8:  return 908;
        case 9:  return 909;
        case 10: return 910;
        case 11: return 911;
        case 12: return 912;
        case 13: return 913;
        case 14: return 914;
        case 15: return 915;
        case 16: return 916;
        case 17: return 917;
        case 18: return 918;
        case 19: return 919;
        default: return -1;
    }
}

int main(int argc, char **argv) {
    sink = dense_switch(argc);
    sink = dense_switch_offset(argc + 10);
    sink = sparse_switch(argc * 10);
    sink = fallthrough_switch(argc);
    sink = no_default_switch(argc);
    sink = nested_switch(argc, argc + 1);
    sink = char_switch((char)argc);
    sink = negative_switch(argc - 2);
    sink = large_switch(argc);

    return 0;
}
