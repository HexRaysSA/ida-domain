"""
Database exploration example for IDA Domain API.

This example demonstrates how to open an IDA database and explore its basic properties.
"""

import argparse
from dataclasses import asdict

import ida_domain
from ida_domain import Database
from ida_domain.database import IdaCommandOptions


def explore_database(db_path):
    """Explore basic database information."""
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=False)
    with Database.open(db_path, ida_options) as db:
        # Get basic information
        print(f'Address range: {hex(db.minimum_ea)} - {hex(db.maximum_ea)}')

        # Get metadata
        print('Database metadata:')
        metadata_dict = asdict(db.metadata)
        for key, value in metadata_dict.items():
            print(f'  {key}: {value}')

        # Count functions
        function_count = 0
        for _ in db.functions:
            function_count += 1
        print(f'Total functions: {function_count}')


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(description='Database exploration example')
    parser.add_argument(
        '-f', '--input-file', help='Binary input file to be loaded', type=str, required=True
    )
    args = parser.parse_args()
    explore_database(args.input_file)


if __name__ == '__main__':
    main()
