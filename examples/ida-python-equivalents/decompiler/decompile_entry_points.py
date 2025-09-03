"""
This is equivalent of decompile_entry_points.py from IDAPython examples
Original: https://github.com/idapython/src/blob/master/examples/decompiler/decompile_entry_points.py
"""

import argparse

import ida_domain


def main():
    parser = argparse.ArgumentParser(description='Decompile entry points automatically')
    parser.add_argument('-f', '--input-file', required=True, help='Binary input file')
    args = parser.parse_args()

    db = ida_domain.Database.open(args.input_file)
    if db:
        print('Database opened successfully')

        # Get all entry points
        entries = list(db.entries.get_all())

        if entries:
            output_file = args.input_file + '.c'
            with open(output_file, 'w') as outfile:
                print(f"Writing results to '{output_file}'...")

                for entry in entries:
                    print(f'Decompiling at: {entry.address:X}...')

                    # Get the function at this entry point
                    func = db.functions.get_at(entry.address)
                    if func:
                        try:
                            # Get pseudocode for the function
                            pseudocode = db.functions.get_pseudocode(func)
                            if pseudocode:
                                outfile.write(f'\n// Function at 0x{func.start_ea:X}\n')
                                outfile.write('\n'.join(pseudocode) + '\n')
                                print(f'OK')
                            else:
                                outfile.write(
                                    f'// Failed to decompile function at 0x{func.start_ea:X}\n'
                                )
                                print(f'Failed!')
                        except RuntimeError as e:
                            outfile.write(f'// Decompilation error at 0x{func.start_ea:X}: {e}\n')
                            print(f'Failed: {e}')
                    else:
                        outfile.write(f'// No function found at entry point 0x{entry.address:X}\n')
                        print(f'No function at entry point')

                print(f'Results written to {output_file}')
        else:
            print('No known entrypoints. Cannot decompile.')

        db.close()
    else:
        print(f'Failed to open database for {args.input_file}')
        return 1

    return 0


if __name__ == '__main__':
    exit(main())
