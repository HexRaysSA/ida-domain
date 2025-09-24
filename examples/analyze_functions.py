#!/usr/bin/env python3
"""
Function analysis example for IDA Domain API.

This example demonstrates how to find and analyze functions in an IDA database.
"""

import argparse

import ida_domain
from ida_domain.database import IdaCommandOptions


def analyze_local_variables(db, func):
    """Analyze local variables in a function."""
    lvars = db.functions.get_local_variables(func)
    if not lvars:
        print('  No local variables found')
        return

    print(f'  Local variables ({len(lvars)} total):')

    for lvar in lvars:
        refs = db.functions.get_local_variable_references(func, lvar)
        ref_count = len(refs)
        var_type = 'arg' if lvar.is_argument else 'ret' if lvar.is_result else 'var'
        type_str = lvar.type_str if lvar.type else 'unknown'

        print(f'    {lvar.name} ({var_type}, {type_str}): {ref_count} refs')


def analyze_functions(db_path, pattern='main', max_results=10, analyze_lvars=True):
    """Find and analyze functions matching a pattern."""
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=True)
    with ida_domain.Database.open(db_path, ida_options, False) as db:
        # Find functions matching a pattern
        matching_functions = []
        for func in db.functions:
            func_name = db.functions.get_name(func)
            if pattern.lower() in func_name.lower():
                matching_functions.append((func, func_name))

        print(f"Found {len(matching_functions)} functions matching '{pattern}':")

        # Limit results if requested
        display_functions = (
            matching_functions[:max_results] if max_results > 0 else matching_functions
        )

        for func, name in display_functions:
            print(f'\nFunction: {name}')
            print(f'\nAddress: {hex(func.start_ea)} - {hex(func.end_ea)}')

            # Get signature
            signature = db.functions.get_signature(func)
            print(f'\nSignature: {signature}')

            # Get basic blocks
            flowchart = db.functions.get_flowchart(func)
            print(f'\nBasic blocks count: {len(flowchart)}')

            # Analyze local variables if requested
            if analyze_lvars:
                print('\nLocal variable analysis:')
                analyze_local_variables(db, func)

            # Show first few lines of disassembly
            disasm = db.functions.get_disassembly(func)
            print('\nDisassembly:')
            for line in disasm:
                print(f'  {line}')

            # Show first few lines of pseudocode
            pseudocode = db.functions.get_pseudocode(func)
            print('\nPseudocode :')
            for line in pseudocode:
                print(f'  {line}')

        if max_results > 0 and len(matching_functions) > max_results:
            print(f'\n... (showing first {max_results} of {len(matching_functions)} matches)')


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(description='Function analysis examples')
    parser.add_argument(
        '-f', '--input-file', help='Binary input file to be loaded', type=str, required=True
    )
    parser.add_argument(
        '-p',
        '--pattern',
        default='main',
        help='Pattern to search for in function names (default: main)',
    )
    parser.add_argument(
        '-m',
        '--max-results',
        type=int,
        default=10,
        help='Maximum number of results to display (0 for all, default: 10)',
    )
    parser.add_argument(
        '-l',
        '--analyze-locals',
        action='store_true',
        help='Analyze local variables in functions',
    )
    args = parser.parse_args()
    analyze_functions(args.input_file, args.pattern, args.max_results, args.analyze_locals)


if __name__ == '__main__':
    main()
