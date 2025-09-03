#!/usr/bin/env python3
"""
Types example for IDA Domain API.

This example demonstrates how to work with IDA's type information libraries.
"""

import argparse
import tempfile
from pathlib import Path

import ida_domain
from ida_domain import Database


def print_section_header(title: str, char: str = '=') -> None:
    """Print a formatted section header for better output organization."""
    print(f'\n{char * 60}')
    print(f' {title}')
    print(f'{char * 60}')


def print_subsection_header(title: str) -> None:
    """Print a formatted subsection header."""
    print(f'\n--- {title} ---')


declarations = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

struct STRUCT_EXAMPLE
{
    char *text;
    unsigned int length;
    uint32_t reserved;
};

"""


def create_types(db: Database, library_path: Path):
    """Create a type library and fill it with types parsed from declaration"""

    til = db.types.create_library(library_path, 'Example type information library')
    db.types.parse_declarations(til, declarations)
    db.types.save_library(til, library_path)
    db.types.unload_library(til)


def import_types(db: Database, library_path: Path):
    """Import all types from external library"""

    til = db.types.load_library(library_path)

    print_subsection_header(f'Type names from external library {library_path}')
    for name in db.types.get_all(library=til):
        print(name)

    print_subsection_header('Type information objects in local library (before import)')
    for item in sorted(list(db.types), key=lambda i: i.get_ordinal()):
        print(f'{item.get_ordinal()}. {item}')

    db.types.import_from_library(til)

    print_subsection_header('Type information objects in local library (after import)')
    for item in sorted(list(db.types), key=lambda i: i.get_ordinal()):
        print(f'{item.get_ordinal()}. {item}')

    db.types.unload_library(til)


def export_types(db: Database, library_path: Path):
    """Export all types from database to external library"""

    til = db.types.create_library(library_path, 'Exported type library')
    db.types.export_to_library(til)
    db.types.save_library(til, library_path)
    db.types.unload_library(til)

    print_subsection_header(f'Types exported to {library_path}')
    til = db.types.load_library(library_path)
    for t in db.types.get_all(library=til):
        print(t)
    db.types.unload_library(til)


def main():
    parser = argparse.ArgumentParser(
        description=f'IDA Domain usage example, version {ida_domain.__version__}'
    )
    parser.add_argument(
        '-f', '--input-file', help='Binary input file to be loaded', type=str, required=True
    )
    args = parser.parse_args()

    library_dir = Path(tempfile.gettempdir()) / 'ida_domain_example'
    library_dir.mkdir(parents=True, exist_ok=True)
    library_create_path = library_dir / 'new.til'
    library_import_path = library_dir / 'new.til'
    library_export_path = library_dir / 'exported.til'

    print_section_header('Working with type information libraries')

    with Database.open(args.input_file) as db:
        create_types(db, library_create_path)
        import_types(db, library_import_path)
        export_types(db, library_export_path)


if __name__ == '__main__':
    main()
