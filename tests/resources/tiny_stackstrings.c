/*
 * tiny_stackstrings.c -- COFF x86-64 object used by the string tests.
 *
 * emit_marker() places the marker text "ida-domain" into a stack buffer as
 * little-endian 16-bit units, filled from the terminator backwards. The
 * object file therefore has no string literal; IDA 9.4+ reconstructs the
 * text with the decompiler and lists it as a decompiler (STRTYPE_DECOMP)
 * string.
 *
 * Build (MinGW):  gcc -O0 -c -o tiny_stackstrings.bin tiny_stackstrings.c
 */

#include <stdint.h>

extern void write_marker(const char *marker, unsigned size);

void emit_marker(void)
{
    uint16_t units[6];

    units[5] = 0x0000; /* terminator */
    units[4] = 0x6e69; /* "in" */
    units[3] = 0x616d; /* "ma" */
    units[2] = 0x6f64; /* "do" */
    units[1] = 0x2d61; /* "a-" */
    units[0] = 0x6469; /* "id" */

    write_marker((const char *)units, sizeof units);
}
