#!/usr/bin/env python3
"""
Using FLIRT signature files example in IDA Domain API.

This example demonstrates how to work with signature files:
  - how to evaluate the matches on your binary
  - how to actually apply a sig file
  - how to generate .sig/.pat from your loaded binary
  - how to use custom signature directories
"""

import argparse
from pathlib import Path

import ida_domain
from ida_domain import Database
from ida_domain.database import IdaCommandOptions
from ida_domain.signature_files import FileInfo


def probe_signature_files(db: ida_domain.Database, min_matches: int, custom_dir: str = None):
    """Probe signature files and collect the ones over the minimum number of matches."""
    print('Probing signature files...')
    directories = [Path(custom_dir)] if custom_dir else None
    files = db.signature_files.get_files(directories=directories)

    good_matches = []
    for sig_file in files:
        results = db.signature_files.apply(sig_file, probe_only=True)
        for result in results:
            if result.matches >= min_matches:
                good_matches.append(result)
                print(f'{sig_file.name}: {result.matches} matches')

    return good_matches


def apply_signature_files(db: ida_domain.Database, matches: list[FileInfo], min_matches: int):
    """Apply signature files over the minimum number of matches."""
    if not matches:
        return

    print('\nApplying signature files...')
    for result in matches:
        if result.matches >= min_matches:
            sig_path = Path(result.path)
            print(f'Applying {sig_path.name}')
            db.signature_files.apply(sig_path, probe_only=False)


def generate_signatures(db: ida_domain.Database):
    """Generate signature files from current database."""
    print('\nGenerating signatures...')
    produced_files = db.signature_files.create()
    if produced_files:
        for file_path in produced_files:
            print(f'Generated: {Path(file_path).name}')


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='FLIRT signature files example')
    parser.add_argument('-f', '--input-file', required=True, help='Binary file to analyze')
    parser.add_argument('-d', '--sig-dir', help='Directory where to look for signature files')
    parser.add_argument('-p', '--min-probe-matches', default=5, type=int)
    parser.add_argument('-a', '--min-apply-matches', default=10, type=int)
    args = parser.parse_args()

    ida_options = IdaCommandOptions(auto_analysis=True, new_database=False)
    with Database.open(args.input_file, ida_options) as db:
        matches = probe_signature_files(db, args.min_probe_matches, args.sig_dir)
        apply_signature_files(db, matches, args.min_apply_matches)
        generate_signatures(db)


if __name__ == '__main__':
    main()
