
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

## ARM Thumb Test Binary (tiny_thumb)

`tiny_thumb.bin` is a synthetic 516-byte 32-bit ARM ELF (no source, the bytes
were assembled by a small generator script). It stores Thumb function pointers
with bit 0 set, so IDA creates the offset xrefs at `func+1` instead of `func`.
Used to test `Xrefs.to_item()`.

- `sub_10120` (2-byte head `PUSH {R4,LR}`): BL from `0x10102`; offset xrefs to
  `0x10121` from `0x1010a` (`LDR R1, =(sub_10120+1)`), `0x10138`, `0x10150`
  and `0x20000` (`DCD sub_10120+1`).
- `sub_10128` (4-byte head `PUSH.W {R4,LR}`): BL from `0x10106`; offset xrefs
  to `0x10129` from `0x1010c` (`LDR`), `0x1013c` and `0x10154` (`DCD`).
