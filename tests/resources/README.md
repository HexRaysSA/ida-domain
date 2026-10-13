
# Unit Testing Input Binaries

The project includes minimal binaries used for unit testing.

---

## Assembly Test Binary (tiny_asm)

The `tiny_asm.asm` file is a minimal assembly binary used for basic unit testing.

To rebuild:
```bash
nasm -f elf64 tiny_asm.asm -o tiny_asm.bin
```

After rebuilding, replace `tiny_asm.bin` in this folder and update any tests as needed.

---

## C Test Binary (tiny_c)

The `tiny_c.c` file contains patterns that generate complex variable access
patterns in IDA's decompiler output (HIWORD, LOWORD, pointer casts).

To rebuild:
```bash
gcc -O0 -fno-pie -c tiny_c.c -o tiny_c.bin
```

After rebuilding, replace `tiny_c.bin` in this folder and update any tests as needed.

---

## Imports Test Binary (tiny_imports)

The `tiny_imports.c` file is a minimal dynamically-linked binary used for
testing the Imports API with actual import data.

To rebuild:
```bash
gcc -O0 -no-pie -fno-stack-protector tiny_imports.c -o tiny_imports.bin
```

This binary links against libc and imports:
- `malloc` / `free` - memory allocation
- `puts` - simple output
- `exit` - process termination

After rebuilding, replace `tiny_imports.bin` in this folder and update any tests as needed.

---

## Struct Test Binary (tiny_struct)

The `tiny_struct.c` file contains real structure and enum usage: a global
`struct Packet` accessed by member (directly and through a pointer) and an
`enum PacketStatus` constant used as an immediate.

To rebuild:
```bash
gcc -O0 -c tiny_struct.c -o tiny_struct.bin
```

The tests use instruction addresses from this object. After rebuilding, replace
`tiny_struct.bin` and update those addresses if the generated code changed.

---

## Stack String Test Binary (tiny_stackstrings)

The `tiny_stackstrings.c` file stores a marker text on the stack as 16-bit
integer units, so no string literal exists in the object; only the decompiler
reconstructs it. Used to test decompiler strings (`StringType.DECOMP`, IDA 9.4+).

To rebuild:
```bash
gcc -O0 -c -o tiny_stackstrings.bin tiny_stackstrings.c
```

After rebuilding, replace `tiny_stackstrings.bin` in this folder and update any tests as needed.

---

## Switch Test Binaries (tiny_switch_x64, tiny_switch_thumb)

The `tiny_switch.c` file contains switches that compile to jump tables: a dense
switch with gaps and a shared target, one without a default, and one whose cases
straddle zero. Each case calls its own function, so tests can tell where a value
goes from the name of the function its target calls.

The same source is built for x86-64 (8-byte table entries) and for Thumb, where
the switches use `TBB` (1-byte entries).

The checked-in binaries were built with GCC 13.2.0 (x86-64) and GCC 14.2.0
(arm-none-eabi). The tests depend on the generated code, so other versions may
need test updates. To rebuild (on x86-64 Linux, `gcc` works in place of
`x86_64-linux-gnu-gcc`):
```bash
x86_64-linux-gnu-gcc -O2 -c tiny_switch.c -o tiny_switch_x64.bin
arm-none-eabi-gcc -mthumb -mcpu=cortex-m3 -O2 -c tiny_switch.c -o tiny_switch_thumb.bin
```

After rebuilding, replace both binaries in this folder and check that the tests
still find one switch per function.
