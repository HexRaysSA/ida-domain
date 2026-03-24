# my_first_script.py
import argparse

from ida_domain import Database


def explore_database(db_path):
    # Create and open database
    with Database.open(path=db_path, save_on_close=False) as db:
        # Basic database info
        print(f'[+] Opened: {db_path}')
        print(f'  Architecture: {db.architecture}')
        print(f'  Entry point: {hex(db.entries[0].address)}')
        print(f'  Address range: {hex(db.minimum_ea)} - {hex(db.maximum_ea)}')

        # Count functions
        func_count = len(list(db.functions))
        print(f'  Functions: {func_count}')

        # Count strings
        string_count = len(list(db.strings))
        print(f'  Strings: {string_count}')
    print('[+] Database closed')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--input-file', type=str, required=True)
    args = parser.parse_args()
    # Run with your IDA input file
    explore_database(args.input_file)
