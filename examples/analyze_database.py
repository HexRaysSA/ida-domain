#!/usr/bin/env python3
"""
Database Traversal Example for IDA Domain API

This example demonstrates how to systematically traverse an IDA database and
examine available entities. It provides a structured approach to exploring
contents of a binary analysis database.
"""

import argparse
from dataclasses import asdict

import ida_domain
import ida_domain.flowchart
from ida_domain.database import IdaCommandOptions


def print_section_header(title: str, char: str = '=') -> None:
    """Print a formatted section header for better output organization."""
    print(f'\n{char * 60}')
    print(f' {title}')
    print(f'{char * 60}')


def print_subsection_header(title: str) -> None:
    """Print a formatted subsection header."""
    print(f'\n--- {title} ---')


def traverse_metadata(db: ida_domain.Database) -> None:
    """
    Traverse and display database metadata.

    Args:
        db: The IDA database instance
    """
    print_section_header('DATABASE METADATA')

    metadata = asdict(db.metadata)
    if metadata:
        for key, value in metadata.items():
            print(f'  {key:15}: {value}')
    else:
        print('  No metadata available')

    # Additional database properties
    print(f'  {"current_ea":15}: 0x{db.current_ea:x}')
    print(f'  {"minimum_ea":15}: 0x{db.minimum_ea:x}')
    print(f'  {"maximum_ea":15}: 0x{db.maximum_ea:x}')


def traverse_segments(db: ida_domain.Database) -> None:
    """
    Traverse and display memory segments.

    Args:
        db: The IDA database instance
    """
    print_section_header('MEMORY SEGMENTS')

    segments = list(db.segments)
    print(f'Total segments: {len(segments)}')

    for i, segment in enumerate(segments, 1):
        print(
            f'  [{i:2d}] {segment.name:20} | '
            f'Start: 0x{segment.start_ea:08x} | '
            f'End: 0x{segment.end_ea:08x} | '
            f'Size: {segment.size} | '
            f'Type: {segment.type}'
        )


def traverse_functions(db: ida_domain.Database) -> None:
    """
    Traverse and display functions.

    Args:
        db: The IDA database instance
    """
    print_section_header('FUNCTIONS')

    functions = list(db.functions)
    print(f'Total functions: {len(functions)}')

    # Show first 20 functions to avoid overwhelming output
    display_count = min(20, len(functions))
    if display_count < len(functions):
        print(f'Displaying first {display_count} functions:')

    for i, func in enumerate(functions[:display_count], 1):
        print(
            f'  [{i:2d}] {func.name:30} | '
            f'Start: 0x{func.start_ea:08x} | '
            f'End: 0x{func.end_ea:08x} | '
            f'Size: {func.size}'
        )

    if display_count < len(functions):
        print(f'  ... and {len(functions) - display_count} more functions')


def traverse_entries(db: ida_domain.Database) -> None:
    """
    Traverse and display program entries.

    Args:
        db: The IDA database instance
    """
    print_section_header('PROGRAM ENTRIES')

    entries = list(db.entries)
    print(f'Total entries: {len(entries)}')

    for i, entry in enumerate(entries, 1):
        print(
            f'  [{i:2d}] {entry.name:30} | '
            f'Address: 0x{entry.address:08x} | '
            f'Ordinal: {entry.ordinal}'
        )


def traverse_heads(db: ida_domain.Database) -> None:
    """
    Traverse and display heads (data and code locations).

    Args:
        db: The IDA database instance
    """
    print_section_header('HEADS (Data/Code Locations)')

    heads = list(db.heads)
    print(f'Total heads: {len(heads)}')

    # Show first 20 heads to avoid overwhelming output
    display_count = min(20, len(heads))
    if display_count < len(heads):
        print(f'Displaying first {display_count} heads:')

    for i, head in enumerate(heads[:display_count], 1):
        print(f'  [{i:2d}] Address: 0x{head:08x}')

    if display_count < len(heads):
        print(f'  ... and {len(heads) - display_count} more heads')


def traverse_strings(db: ida_domain.Database) -> None:
    """
    Traverse and display identified strings.

    Args:
        db: The IDA database instance
    """
    print_section_header('STRINGS')

    strings = list(db.strings)
    print(f'Total strings: {len(strings)}')

    # Show first 15 strings to avoid overwhelming output
    display_count = min(15, len(strings))
    if display_count < len(strings):
        print(f'Displaying first {display_count} strings:')

    for i, item in enumerate(strings[:display_count], 1):
        # Truncate very long strings for display
        display_str = str(item)[:50] + '...' if len(str(item)) > 50 else str(i)
        print(f'  [{i:2d}] 0x{item.address:08x}: "{display_str}"')

    if display_count < len(strings):
        print(f'  ... and {len(strings) - display_count} more strings')


def traverse_names(db: ida_domain.Database) -> None:
    """
    Traverse and display names (symbols and labels).

    Args:
        db: The IDA database instance
    """
    print_section_header('NAMES (Symbols & Labels)')

    names = list(db.names)
    print(f'Total names: {len(names)}')

    # Show first 20 names to avoid overwhelming output
    display_count = min(20, len(names))
    if display_count < len(names):
        print(f'Displaying first {display_count} names:')

    for i, (ea, name) in enumerate(names[:display_count], 1):
        print(f'  [{i:2d}] 0x{ea:08x}: {name}')

    if display_count < len(names):
        print(f'  ... and {len(names) - display_count} more names')


def traverse_types(db: ida_domain.Database) -> None:
    """
    Traverse and display type definitions.

    Args:
        db: The IDA database instance
    """
    print_section_header('TYPE DEFINITIONS')

    types = list(db.types)
    print(f'Total types: {len(types)}')

    # Show first 15 types to avoid overwhelming output
    display_count = min(15, len(types))
    if display_count < len(types):
        print(f'Displaying first {display_count} types:')

    for i, type_def in enumerate(types[:display_count], 1):
        type_name = (
            type_def.get_type_name()
            if type_def.get_type_name()
            else f'<unnamed_{type_def.get_tid()}>'
        )
        print(f'  [{i:2d}] {type_name:30} | TID: {type_def.get_tid()}')

    if display_count < len(types):
        print(f'  ... and {len(types) - display_count} more types')


def traverse_comments(db: ida_domain.Database) -> None:
    """
    Traverse and display comments.

    Args:
        db: The IDA database instance
    """
    print_section_header('COMMENTS')

    # Get all comments (regular and repeatable)
    comments = list(db.comments)
    print(f'Total comments: {len(comments)}')

    # Show first 10 comments to avoid overwhelming output
    display_count = min(10, len(comments))
    if display_count < len(comments):
        print(f'Displaying first {display_count} comments:')

    for i, info in enumerate(comments[:display_count], 1):
        # Truncate very long comments for display
        text = info.comment[:60] + '...' if len(info.comment) > 60 else info.comment
        type = 'REP' if info.repeatable else 'REG'
        print(f'  [{i:2d}] 0x{info.ea:08x} [{type}]: {text}')

    if display_count < len(comments):
        print(f'  ... and {len(comments) - display_count} more comments')


def traverse_basic_blocks(db: ida_domain.Database) -> None:
    """
    Traverse and display basic blocks.

    Args:
        db: The IDA database instance
    """
    print_section_header('BASIC BLOCKS')

    flowchart = ida_domain.flowchart.FlowChart(db, None, (db.minimum_ea, db.maximum_ea))
    basic_blocks = list(flowchart)
    print(f'Total basic blocks: {len(basic_blocks)}')

    # Show first 15 basic blocks to avoid overwhelming output
    display_count = min(15, len(basic_blocks))
    if display_count < len(basic_blocks):
        print(f'Displaying first {display_count} basic blocks:')

    for i, bb in enumerate(basic_blocks[:display_count], 1):
        print(f'  [{i:2d}] Start: 0x{bb.start_ea:08x} | End: 0x{bb.end_ea:08x}')

    if display_count < len(basic_blocks):
        print(f'  ... and {len(basic_blocks) - display_count} more basic blocks')


def traverse_instructions(db: ida_domain.Database) -> None:
    """
    Traverse and display instructions with disassembly.

    Args:
        db: The IDA database instance
    """
    print_section_header('INSTRUCTIONS')

    instructions = list(db.instructions)
    print(f'Total instructions: {len(instructions)}')

    # Show first 20 instructions to avoid overwhelming output
    display_count = min(20, len(instructions))
    if display_count < len(instructions):
        print(f'Displaying first {display_count} instructions:')

    for i, inst in enumerate(instructions[:display_count], 1):
        disasm = db.instructions.get_disassembly(inst)
        if disasm:
            print(f'  [{i:2d}] 0x{inst.ea:08x}: {disasm}')
        else:
            print(f'  [{i:2d}] 0x{inst.ea:08x}: <no disassembly>')

    if display_count < len(instructions):
        print(f'  ... and {len(instructions) - display_count} more instructions')


def traverse_cross_references(db: ida_domain.Database) -> None:
    """
    Traverse and display cross-references.

    Args:
        db: The IDA database instance
    """
    print_section_header('CROSS-REFERENCES')

    # Get a sample of addresses to check for cross-references
    sample_addresses = []

    # Add function start addresses
    functions = list(db.functions)
    sample_addresses.extend([f.start_ea for f in functions[:5]])

    # Add some heads
    heads = list(db.heads)
    sample_addresses.extend(heads[:5])

    xref_count = 0
    print('Sample cross-references:')

    for addr in sample_addresses[:10]:  # Limit to first 10 addresses
        xrefs_to = list(db.xrefs.to_ea(addr))
        xrefs_from = list(db.xrefs.from_ea(addr))

        if xrefs_to or xrefs_from:
            print(f'  Address 0x{addr:08x}:')

            for xref in xrefs_to[:3]:  # Show max 3 xrefs to
                type_name = xref.type.name
                print(f'    <- FROM 0x{xref.from_ea:08x} (type: {type_name})')
                xref_count += 1

            for xref in xrefs_from[:3]:  # Show max 3 xrefs from
                type_name = xref.type.name
                print(f'    -> TO   0x{xref.to_ea:08x} (type: {type_name})')
                xref_count += 1

    print(f'Total cross-references displayed: {xref_count}')


def traverse_database(db_path: str):
    """
    Main function to traverse the entire IDA database and display all entities.

    Args:
        db_path: Path to the binary file to analyze
    """
    print_section_header('IDA DOMAIN DATABASE TRAVERSAL', '=')
    print(f'Analyzing file: {db_path}')

    # Configure IDA options for analysis
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=True)

    # Open database
    with ida_domain.Database.open(db_path, ida_options, False) as db:
        # Traverse all database entities
        traverse_metadata(db)
        traverse_segments(db)
        traverse_functions(db)
        traverse_entries(db)
        traverse_heads(db)
        traverse_strings(db)
        traverse_names(db)
        traverse_types(db)
        traverse_comments(db)
        traverse_basic_blocks(db)
        traverse_instructions(db)
        traverse_cross_references(db)

        print_section_header('TRAVERSAL COMPLETE', '=')


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(description='IDA Database Traversal Example')
    parser.add_argument(
        '-f', '--input-file', help='Binary input file to be loaded', type=str, required=True
    )
    args = parser.parse_args()
    traverse_database(args.input_file)


if __name__ == '__main__':
    main()
