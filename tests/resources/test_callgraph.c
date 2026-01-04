/**
 * test_callgraph.c - Test binary for CallGraph API validation
 *
 * This file creates a structured call graph for testing:
 *
 *                    main
 *                   /    \
 *              level1_a  level1_b
 *             /    \        |
 *        level2_a  level2_b |
 *             \    /    \   |
 *              leaf_a   leaf_b  (leaf_b called by level1_b and level2_b)
 *
 * Test scenarios:
 * - callers_of(leaf_a) with depth=1 -> {level2_a, level2_b}
 * - callers_of(leaf_a) with depth=2 -> {level2_a, level2_b, level1_a}
 * - callers_of(leaf_b) with depth=1 -> {level2_b, level1_b}
 * - callees_of(level1_a) with depth=1 -> {level2_a, level2_b}
 * - callees_of(level1_a) with depth=2 -> {level2_a, level2_b, leaf_a, leaf_b}
 * - paths_between(main, leaf_a) -> multiple paths exist
 * - reachable_from(main) -> all functions
 * - reaches(leaf_a) -> {level2_a, level2_b, level1_a, main}
 *
 * Compile with:
 *   gcc -O0 -fno-pie -fno-inline -c test_callgraph.c -o test_callgraph.bin
 */

#include <stdint.h>

/* Volatile sink to prevent optimization */
volatile uint64_t sink;

/* Leaf functions - bottom of call graph */
__attribute__((noinline))
void leaf_a(uint64_t val) {
    sink = val * 2;
}

__attribute__((noinline))
void leaf_b(uint64_t val) {
    sink = val * 3;
}

/* Level 2 functions - call leaf functions */
__attribute__((noinline))
void level2_a(uint64_t val) {
    leaf_a(val + 1);
}

__attribute__((noinline))
void level2_b(uint64_t val) {
    leaf_a(val + 2);
    leaf_b(val + 3);
}

/* Level 1 functions - call level 2 functions */
__attribute__((noinline))
void level1_a(uint64_t val) {
    level2_a(val * 10);
    level2_b(val * 20);
}

__attribute__((noinline))
void level1_b(uint64_t val) {
    /* Directly calls leaf_b, bypassing level2 */
    leaf_b(val * 100);
}

/* Entry point - calls level 1 functions */
__attribute__((noinline))
void entry_point(uint64_t val) {
    level1_a(val);
    level1_b(val);
}

/* Isolated function - not connected to main call graph */
__attribute__((noinline))
void isolated_func(uint64_t val) {
    sink = val;
}

/* Recursive function for cycle testing */
__attribute__((noinline))
void recursive_func(uint64_t n) {
    if (n > 0) {
        sink = n;
        recursive_func(n - 1);
    }
}

/* Mutually recursive functions for cycle testing */
__attribute__((noinline)) void mutual_b(uint64_t n);

__attribute__((noinline))
void mutual_a(uint64_t n) {
    if (n > 0) {
        sink = n;
        mutual_b(n - 1);
    }
}

__attribute__((noinline))
void mutual_b(uint64_t n) {
    if (n > 0) {
        sink = n * 2;
        mutual_a(n - 1);
    }
}
