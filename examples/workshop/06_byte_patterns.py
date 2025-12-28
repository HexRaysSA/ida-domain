"""
Example 6: Extracting Byte Patterns

This script searches for interesting byte patterns
like XOR constants and magic values.
"""

from ida_domain import Database


def hexdump(data, start_addr, bytes_per_line=16):
    """Format bytes as a hex dump."""
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i : i + bytes_per_line]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"0x{start_addr + i:08x}: {hex_str:<48} {ascii_str}")
    return "\n".join(lines)


def main():
    with Database() as db:
        print("Searching for interesting byte patterns...")
        print("=" * 60)

        # 1. Dump bytes from suspected hash function
        print("\n1. Looking for hash function bytes")
        print("-" * 40)

        # Find functions called by the validation logic
        for func in db.functions:
            func_size = func.end_ea - func.start_ea

            # Small functions are often utility/hash functions
            if 50 < func_size < 200:
                func_bytes = db.bytes.get_bytes(func.start_ea, func_size)
                if func_bytes:
                    print(f"\n{func.name} ({func_size} bytes):")
                    print(hexdump(func_bytes, func.start_ea))

        # 2. Search for XOR patterns
        print("\n\n2. Searching for XOR instructions with immediate values")
        print("-" * 40)

        # Common XOR patterns in x86-64:
        # 35 XX XX XX XX     - XOR EAX, imm32
        # 81 F0 XX XX XX XX  - XOR EAX, imm32 (alternate encoding)
        # 48 35 XX XX XX XX  - XOR RAX, imm32 (with REX prefix)

        xor_patterns = [
            ("35", "XOR EAX, imm32"),
            ("81 f0", "XOR EAX, imm32 (alt)"),
            ("48 35", "XOR RAX, imm32"),
        ]

        for pattern, description in xor_patterns:
            print(f"\nPattern: {pattern} ({description})")

            # Search through code segments
            current_ea = db.minimum_ea
            found = False

            while current_ea < db.maximum_ea:
                # Simple linear search through bytes
                try:
                    byte_val = db.bytes.get_byte(current_ea)
                    if byte_val is not None:
                        # Check if this might be our pattern
                        pattern_bytes = bytes.fromhex(pattern.replace(" ", ""))
                        match_bytes = db.bytes.get_bytes(current_ea, len(pattern_bytes))

                        if match_bytes == pattern_bytes:
                            # Get the immediate value
                            imm_bytes = db.bytes.get_bytes(
                                current_ea + len(pattern_bytes), 4
                            )
                            if imm_bytes:
                                imm_value = int.from_bytes(imm_bytes, "little")
                                func = db.functions.get_at(current_ea)
                                func_name = func.name if func else "(not in function)"

                                print(
                                    f"  0x{current_ea:08x}: immediate = 0x{imm_value:08x} [{func_name}]"
                                )
                                found = True
                except Exception:
                    pass

                current_ea += 1

            if not found:
                print("  (none found)")

        # 3. Look for known magic values
        print("\n\n3. Searching for magic values")
        print("-" * 40)

        magic_values = [
            (0xDEADBEEF, "Common debug/XOR constant"),
            (0x12345678, "Sequential test value"),
            (0xCAFEBABE, "Java class file / debug marker"),
            (0x8BADF00D, "Apple watchdog marker"),
        ]

        for magic, description in magic_values:
            magic_bytes = magic.to_bytes(4, "little")

            print(f"\nSearching for 0x{magic:08X} ({description})...")

            # Search for this 4-byte sequence
            current_ea = db.minimum_ea
            while current_ea < db.maximum_ea - 4:
                try:
                    found_bytes = db.bytes.get_bytes(current_ea, 4)
                    if found_bytes == magic_bytes:
                        func = db.functions.get_at(current_ea)
                        context = func.name if func else "data section"
                        print(f"  Found at 0x{current_ea:08x} [{context}]")
                except Exception:
                    pass
                current_ea += 1


if __name__ == "__main__":
    main()
