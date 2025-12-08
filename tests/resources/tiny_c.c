#include <stdint.h>

typedef union {
    uint32_t full;
    struct { uint16_t lo; uint16_t hi; } parts;
} SplitWord;

volatile uint64_t sink;

__attribute__((noinline)) void use_val(uint64_t v) {
    sink = v;
}

void complex_assignments(uint16_t hi_val, uint16_t lo_val, uint32_t q1, uint32_t q2, uint64_t bytes_val) {
    volatile SplitWord val;
    val.parts.hi = hi_val;
    val.parts.lo = lo_val;
    use_val(val.full);

    volatile uint64_t qval;
    *((volatile uint32_t*)&qval) = q1;
    *(((volatile uint32_t*)&qval) + 1) = q2;
    use_val(qval);

    volatile uint8_t bytes[8];
    *((volatile uint64_t*)bytes) = bytes_val;
    use_val(*((volatile uint64_t*)bytes));
}
