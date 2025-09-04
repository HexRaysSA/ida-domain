#!/usr/bin/env python3
"""
String analysis example for IDA Domain API.

This example demonstrates how to find and analyze strings in an IDA database.
"""

import argparse

import ida_domain
from ida_domain import Database
from ida_domain.database import IdaCommandOptions


def analyze_strings(db_path, min_length=5, max_display=20, show_interesting=True):
    """Find and analyze strings in the database."""
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=True)
    with Database.open(db_path, ida_options) as db:
        print(f'Analyzing strings (minimum length: {min_length}):')

        # Collect all strings
        all_strings = []
        interesting_strings = []

        for item in db.strings:
            if item.length >= min_length:
                all_strings.append((item.address, str(item)))

                # Check for interesting keywords
                if show_interesting:
                    lower_str = str(item).lower()
                    interesting_keywords = [
                        'password',
                        'passwd',
                        'pwd',
                        'key',
                        'secret',
                        'token',
                        'api',
                        'username',
                        'user',
                        'login',
                        'config',
                        'settings',
                        'registry',
                        'file',
                        'path',
                        'directory',
                        'http',
                        'https',
                        'ftp',
                        'url',
                        'sql',
                        'database',
                        'query',
                    ]

                    if any(keyword in lower_str for keyword in interesting_keywords):
                        interesting_strings.append((item.address, str(item)))

        print(f'Total strings: {len(db.strings)}')
        print(f'Strings >= {min_length} chars: {len(all_strings)}')

        # Display regular strings
        print(f'\nFirst {max_display} strings:')
        for i, (addr, string_value) in enumerate(all_strings[:max_display]):
            print(f'{hex(addr)}: {repr(string_value)}')

        if len(all_strings) > max_display:
            print(f'... (showing first {max_display} of {len(all_strings)} strings)')

        # Display interesting strings
        if show_interesting and interesting_strings:
            print(f'\nInteresting strings found ({len(interesting_strings)}):')
            for addr, string_value in interesting_strings[:10]:  # Limit to 10
                print(f'{hex(addr)}: {repr(string_value)}')

            if len(interesting_strings) > 10:
                print(f'... (showing first 10 of {len(interesting_strings)} interesting strings)')


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(description='Database exploration example')
    parser.add_argument(
        '-f', '--input-file', help='Binary input file to be loaded', type=str, required=True
    )
    parser.add_argument(
        '-l', '--min-length', type=int, default=5, help='Minimum string length(default: 5)'
    )
    parser.add_argument(
        '-m', '--max-display', type=int, default=20, help='Maximum displayed strings (default: 20)'
    )
    parser.add_argument(
        '-s',
        '--show-interesting',
        type=bool,
        default=True,
        help='Highlight interesting strings (default True)',
    )
    args = parser.parse_args()
    analyze_strings(args.input_file, args.min_length, args.max_display, args.show_interesting)


if __name__ == '__main__':
    main()
