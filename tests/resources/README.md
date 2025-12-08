
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
