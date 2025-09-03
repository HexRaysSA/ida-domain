#!/usr/bin/env python3
"""
Cross-reference analysis example for IDA Domain API.

This example demonstrates how to analyze cross-references in an IDA database.
"""

import argparse

import ida_domain
from ida_domain import Database
from ida_domain.database import IdaCommandOptions


def analyze_xrefs(db_path, target_addr):
    """Analyze cross-references to and from a target address."""
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=True)
    with Database.open(db_path, ida_options) as db:
        print(f'Cross-references to {hex(target_addr)}:')

        # Get references TO the target address
        xref_to_count = 0
        for xref in db.xrefs.to_ea(target_addr):
            xref_type_name = xref.type.name
            print(f'  From {hex(xref.from_ea)} to {hex(xref.to_ea)} (type: {xref_type_name})')
            xref_to_count += 1

        if xref_to_count == 0:
            print('  No cross-references found')
        else:
            print(f'  Total: {xref_to_count} references')

        print(f'\nCross-references from {hex(target_addr)}:')

        # Get references FROM the target address
        xref_from_count = 0
        for xref in db.xrefs.from_ea(target_addr):
            xref_type_name = xref.type.name
            print(f'  From {hex(xref.from_ea)} to {hex(xref.to_ea)} (type: {xref_type_name})')
            xref_from_count += 1

        if xref_from_count == 0:
            print('  No outgoing references found')
        else:
            print(f'  Total: {xref_from_count} outgoing references')

        # Use convenience methods for specific xref types
        call_count = sum(1 for _ in db.xrefs.calls_to_ea(target_addr))
        jump_count = sum(1 for _ in db.xrefs.jumps_to_ea(target_addr))
        read_count = sum(1 for _ in db.xrefs.reads_of_ea(target_addr))
        write_count = sum(1 for _ in db.xrefs.writes_to_ea(target_addr))

        # Summary
        print(f'\nSummary for {hex(target_addr)}:')
        print(f'  Calls to address: {call_count}')
        print(f'  Jumps to address: {jump_count}')
        print(f'  Data reads to address: {read_count}')
        print(f'  Data writes to address: {write_count}')
        print(f'  Incoming references: {xref_to_count}')
        print(f'  Outgoing references: {xref_from_count}')


def parse_address(value):
    """Parse address as either decimal or hexadecimal"""
    try:
        if value.lower().startswith('0x'):
            return int(value, 16)
        else:
            return int(value, 10)
    except ValueError:
        raise argparse.ArgumentTypeError(f'Invalid address format: {value}')


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(description='Database exploration example')
    parser.add_argument(
        '-f', '--input-file', help='Binary input file to be loaded', type=str, required=True
    )
    parser.add_argument(
        '-a',
        '--address',
        help='Address (decimal or hex with 0x prefix)',
        type=parse_address,
        required=True,
    )
    args = parser.parse_args()
    analyze_xrefs(args.input_file, args.address)


if __name__ == '__main__':
    main()
