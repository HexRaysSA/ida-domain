# ida_console_example.py
# Run this from IDA's IDAPython console or via File → Script command
from ida_domain import Database

# Get handle to currently open database (no path needed)
with Database.open() as db:
    print(f"Current database: {db.path}")
    print(f"Architecture: {db.architecture}")
    print(f"Functions: {len(list(db.functions))}")
