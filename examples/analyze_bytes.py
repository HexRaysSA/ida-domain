#!/usr/bin/env python3
"""
Byte analysis example for IDA Domain API.

This example demonstrates how to analyze, search, and manipulate bytes in an IDA database.
It showcases the comprehensive byte manipulation capabilities including data type operations,
patching, flag checking, and search functionality.
"""

import argparse

import ida_domain
from ida_domain import Database
from ida_domain.bytes import ByteFlags, SearchFlags, StringType
from ida_domain.database import IdaCommandOptions


def analyze_bytes(db_path, search_pattern=None, patch_demo=False, max_results=20):
    """Analyze and manipulate bytes in the database."""
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=True)
    with Database.open(path=db_path, args=ida_options, save_on_close=False) as db:
        bytes_handler = db.bytes

        print('=== IDA Domain Bytes Analysis ===\n')

        # 1. Basic byte reading operations
        print('1. Basic Byte Reading Operations:')
        print('-' * 40)

        # Read different data types from entry point
        entry_point = db.minimum_ea
        print(f'Entry point: {hex(entry_point)}')

        byte_val = bytes_handler.get_byte_at(entry_point)
        word_val = bytes_handler.get_word_at(entry_point)
        dword_val = bytes_handler.get_dword_at(entry_point)
        qword_val = bytes_handler.get_qword_at(entry_point)

        print(f'  Byte:  0x{byte_val:02x} ({byte_val})')
        print(f'  Word:  0x{word_val:04x} ({word_val})')
        print(f'  DWord: 0x{dword_val:08x} ({dword_val})')
        print(f'  QWord: 0x{qword_val:016x} ({qword_val})')

        # Get disassembly
        disasm = bytes_handler.get_disassembly_at(entry_point)
        print(f'  Disassembly: {disasm}')

        # 2. Data type analysis using flags
        print('\n2. Data Type Analysis:')
        print('-' * 40)

        # Analyze different addresses
        test_addresses = [entry_point, entry_point + 0x10, entry_point + 0x20]
        for addr in test_addresses:
            if not db.is_valid_ea(addr):
                continue

            flags = bytes_handler.get_flags_at(addr)
            data_size = bytes_handler.get_data_size_at(addr)

            # Use new flag checking methods
            is_code = bytes_handler.check_flags_at(addr, ByteFlags.CODE)
            is_data = bytes_handler.check_flags_at(addr, ByteFlags.DATA)
            has_any_data_flags = bytes_handler.has_any_flags_at(
                addr, ByteFlags.BYTE | ByteFlags.WORD | ByteFlags.DWORD
            )

            print(f'  Address {hex(addr)}:')
            print(f'    Flags: 0x{flags:x}')
            print(f'    Is Code: {is_code}, Is Data: {is_data}')
            print(f'    Has Data Flags: {has_any_data_flags}')
            print(f'    DataSize: {data_size}')

        # 3. Search operations
        print('\n3. Search Operations:')
        print('-' * 40)

        # Search for common patterns
        patterns_to_search = [
            (b'\x48\x89\xe5', 'Function prologue (mov rbp, rsp)'),
            (b'\x55', 'Push rbp'),
            (b'\xc3', 'Return instruction'),
        ]

        for pattern, description in patterns_to_search:
            found_addr = bytes_handler.find_bytes_between(pattern)
            if found_addr:
                print(f'  Found {description} at {hex(found_addr)}')
            else:
                print(f'  {description} not found')

        # Text search with flags
        if search_pattern:
            print(f"\n  Searching for text: '{search_pattern}'")
            # Case-sensitive search
            addr_case = bytes_handler.find_text(
                search_pattern, flags=SearchFlags.DOWN | SearchFlags.CASE
            )
            # Case-insensitive search
            addr_nocase = bytes_handler.find_text_between(search_pattern, flags=SearchFlags.DOWN)

            if addr_case:
                print(f'    Case-sensitive found at: {hex(addr_case)}')
            if addr_nocase and addr_nocase != addr_case:
                print(f'    Case-insensitive found at: {hex(addr_nocase)}')
            if not addr_case and not addr_nocase:
                print(f"    Text '{search_pattern}' not found")

        # Search for immediate values
        immediate_addr = bytes_handler.find_immediate_between(1)
        if immediate_addr is not None:
            print(f'  Found immediate value 1 at {hex(immediate_addr)}')

        # 4. String operations
        print('\n4. String Operations:')
        print('-' * 40)

        # Find and analyze strings
        string_count = 0
        for item in db.strings:
            if string_count >= 3:  # Limit output
                break

            print(f'  String at {hex(item.address)}: {str(item)}')

            # Try different string reading methods
            cstring = bytes_handler.get_cstring_at(item.address)
            if cstring:
                print(f'    C-string: {repr(cstring)}')

            string_count += 1

        # 5. Data type creation
        print('\n5. Data Type Creation:')
        print('-' * 40)

        # Find a suitable data address for demonstration
        data_addr = None
        for addr in range(db.minimum_ea, min(db.minimum_ea + 0x100, db.maximum_ea), 4):
            if bytes_handler.is_data_at(addr) or bytes_handler.is_unknown_at(addr):
                data_addr = addr
                break

        if data_addr:
            print(f'  Working with data at {hex(data_addr)}')

            # Create different data types
            original_flags = bytes_handler.get_flags_at(data_addr)
            print(f'    Original flags: {original_flags}')

            # Make it a byte
            if bytes_handler.make_byte_at(data_addr):
                print(f'    Successfully created byte at {hex(data_addr)}')

            # Make it a word
            if bytes_handler.make_word(data_addr):
                print(f'    Successfully created word at {hex(data_addr)}')

            # Create a string with specific type
            string_addr = data_addr + 8
            if bytes_handler.make_string(string_addr, string_type=StringType.C):
                print(f'    Successfully created C-string at {hex(string_addr)}')

        # 6. Patching demonstration (if requested)
        if patch_demo:
            print('\n6. Patching Demonstration:')
            print('-' * 40)

            # Find a safe address to patch (data section)
            patch_addr = None
            for addr in range(db.minimum_ea, min(db.minimum_ea + 0x200, db.maximum_ea)):
                if bytes_handler.is_data(addr):
                    patch_addr = addr
                    break

            if patch_addr:
                print(f'  Demonstrating patching at {hex(patch_addr)}')

                # Get original values
                orig_byte = bytes_handler.get_byte_at(patch_addr)
                orig_word = bytes_handler.get_word_at(patch_addr)

                print(f'    Original byte: 0x{orig_byte:02x}')
                print(f'    Original word: 0x{orig_word:04x}')

                # Patch byte
                if bytes_handler.patch_byte_at(patch_addr, 0xAB):
                    new_byte = bytes_handler.get_byte_at(patch_addr)
                    print(f'    Patched byte: 0x{new_byte:02x}')

                    # Get original value
                    retrieved_orig = bytes_handler.get_original_byte_at(patch_addr)
                    print(f'    Retrieved original: 0x{retrieved_orig:02x}')

                    # Revert patch
                    if bytes_handler.revert_byte_at(patch_addr):
                        reverted_byte = bytes_handler.get_byte_at(patch_addr)
                        print(f'    Reverted byte: 0x{reverted_byte:02x}')

                # Patch multiple bytes
                test_data = b'\x90\x90\x90\x90'  # NOP instructions
                if bytes_handler.patch_bytes(patch_addr, test_data):
                    print(f'    Patched {len(test_data)} bytes with NOPs')

                    # Get original bytes
                    success, orig_bytes = bytes_handler.get_original_bytes_at(
                        patch_addr, len(test_data)
                    )
                    if success:
                        print(f'    Original bytes: {orig_bytes.hex()}')

        # 7. Navigation helpers
        print('\n7. Navigation Helpers:')
        print('-' * 40)

        test_addr = entry_point + 0x10
        if test_addr <= db.maximum_ea:
            next_head = bytes_handler.get_next_head(test_addr)
            prev_head = bytes_handler.get_previous_head(test_addr)
            next_addr = bytes_handler.get_next_address(test_addr)
            prev_addr = bytes_handler.get_previous_address(test_addr)

            print(f'  From address {hex(test_addr)}:')
            print(
                f'    Next head: {hex(next_head) if next_head != 0xFFFFFFFFFFFFFFFF else "None"}'
            )
            print(
                f'    Prev head: {hex(prev_head) if prev_head != 0xFFFFFFFFFFFFFFFF else "None"}'
            )
            print(f'    Next addr: {hex(next_addr)}')
            print(f'    Prev addr: {hex(prev_addr)}')

        # 8. Summary statistics
        print('\n8. Summary Statistics:')
        print('-' * 40)

        code_count = data_count = unknown_count = 0
        sample_size = db.maximum_ea - db.minimum_ea

        for addr in range(db.minimum_ea, db.minimum_ea + sample_size):
            if not db.is_valid_ea(addr):
                continue
            if bytes_handler.is_code_at(addr):
                code_count += 1
            elif bytes_handler.is_data_at(addr):
                data_count += 1
            elif bytes_handler.is_unknown_at(addr):
                unknown_count += 1

        print(f'  Sample size: {sample_size} bytes')
        print(f'  Code bytes: {code_count} ({code_count / sample_size * 100:.1f}%)')
        print(f'  Data bytes: {data_count} ({data_count / sample_size * 100:.1f}%)')
        print(f'  Unknown bytes: {unknown_count} ({unknown_count / sample_size * 100:.1f}%)')

        print('\n=== Analysis Complete ===')


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(description='Byte analysis example for IDA Domain API')
    parser.add_argument(
        '-f', '--input-file', help='Binary input file to be loaded', type=str, required=True
    )
    parser.add_argument(
        '-s',
        '--search-pattern',
        help='Text pattern to search for in the binary',
        type=str,
        default=None,
    )
    parser.add_argument(
        '-p',
        '--patch-demo',
        action='store_true',
        help='Demonstrate patching operations (modifies database temporarily)',
    )
    parser.add_argument(
        '-m',
        '--max-results',
        type=int,
        default=20,
        help='Maximum number of results to display (default: 20)',
    )

    args = parser.parse_args()
    analyze_bytes(args.input_file, args.search_pattern, args.patch_demo, args.max_results)


if __name__ == '__main__':
    main()
