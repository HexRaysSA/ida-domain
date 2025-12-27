#!/usr/bin/env python3
"""
Pre-analyze test binaries and save as .i64 files.

This script opens each test binary in IDA, runs auto-analysis,
and saves the resulting database. This allows tests to skip
the expensive auto-analysis step and just load pre-analyzed databases.

Usage:
    python create_idbs.py

Requires:
    - ida-domain package installed
    - IDA Pro available
"""

import os
import sys

# Add parent directory to path for ida_domain import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import ida_domain
from ida_domain.database import IdaCommandOptions

RESOURCES_DIR = os.path.dirname(os.path.abspath(__file__))

# Test binaries to pre-analyze
TEST_BINARIES = [
    'test_imports.bin',
    'test_switches.bin',
    'test_try_blocks.bin',
    'test_stack_frames.bin',
    'test_types.bin',
    'tiny_asm.bin',
    'tiny_c.bin',
]


def create_idb(bin_path: str) -> bool:
    """
    Open a binary in IDA, run auto-analysis, and save as .i64.

    Args:
        bin_path: Path to the binary file

    Returns:
        True if successful, False otherwise
    """
    i64_path = bin_path + '.i64'

    print(f'Processing: {os.path.basename(bin_path)}')
    print(f'  Input:  {bin_path}')
    print(f'  Output: {i64_path}')

    # Remove existing .i64 if present
    if os.path.exists(i64_path):
        os.remove(i64_path)
        print(f'  Removed existing: {i64_path}')

    try:
        # Open with new database and auto-analysis
        ida_options = IdaCommandOptions(
            new_database=True,
            auto_analysis=True,
        )

        print('  Opening database and running auto-analysis...')
        db = ida_domain.Database.open(
            path=bin_path,
            args=ida_options,
            save_on_close=True,  # Save the database
        )

        # Print some stats
        func_count = len(list(db.functions.get_all()))
        print(f'  Functions found: {func_count}')
        print(f'  Address range: 0x{db.minimum_ea:x} - 0x{db.maximum_ea:x}')

        # Close and save
        db.close(save=True)
        print(f'  Saved: {i64_path}')

        # Verify the file was created
        if os.path.exists(i64_path):
            size = os.path.getsize(i64_path)
            print(f'  Size: {size / 1024:.1f} KB')
            return True
        else:
            print(f'  ERROR: Output file not created!')
            return False

    except Exception as e:
        print(f'  ERROR: {e}')
        return False


def main():
    print('=' * 60)
    print('Pre-analyzing test binaries for ida-domain tests')
    print('=' * 60)
    print()

    success_count = 0
    fail_count = 0

    for bin_name in TEST_BINARIES:
        bin_path = os.path.join(RESOURCES_DIR, bin_name)

        if not os.path.exists(bin_path):
            print(f'SKIP: {bin_name} (not found)')
            print()
            continue

        if create_idb(bin_path):
            success_count += 1
        else:
            fail_count += 1

        print()

    print('=' * 60)
    print(f'Done: {success_count} succeeded, {fail_count} failed')
    print('=' * 60)

    return 0 if fail_count == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
