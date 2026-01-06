# IDA Domain Code Patterns

Detailed code examples for common binary analysis tasks.

## Table of Contents

1. [Database Operations](#database-operations)
2. [Function Analysis](#function-analysis)
3. [Cross-Reference Analysis](#cross-reference-analysis)
4. [Call Graph Traversal](#call-graph-traversal)
5. [Local Variable Analysis](#local-variable-analysis)
6. [Instruction & Operand Analysis](#instruction--operand-analysis)
7. [String Analysis](#string-analysis)
8. [Byte Operations](#byte-operations)
9. [Type Operations](#type-operations)
10. [Search Operations](#search-operations)
11. [Switch Statement Analysis](#switch-statement-analysis)
12. [Exception Handling Analysis](#exception-handling-analysis)
13. [Complete Script Template](#complete-script-template)

---

## Database Operations

### Opening a Binary or IDB

```python
from ida_domain import Database
from ida_domain.database import IdaCommandOptions

# Simple open (auto-analysis enabled by default)
with Database.open("path/to/binary") as db:
    pass

# With options
ida_options = IdaCommandOptions(auto_analysis=True, new_database=False)
with Database.open("path/to/file.idb", ida_options) as db:
    pass
```

### Database Properties

```python
with Database.open(path) as db:
    print(f"Address range: {hex(db.minimum_ea)} - {hex(db.maximum_ea)}")
    print(f"Architecture: {db.architecture}")
    print(f"Bitness: {db.bitness}")
    print(f"File format: {db.format}")
    print(f"MD5: {db.md5}")
    print(f"SHA256: {db.sha256}")
```

---

## Function Analysis

### List All Functions

```python
for func in db.functions:
    name = db.functions.get_name(func)
    print(f"{hex(func.start_ea)}: {name}")
```

### Find Function by Name

```python
func = db.functions.get_by_name("main")
if func:
    print(f"Found at {hex(func.start_ea)}")
```

### Get Function at Address

```python
func = db.functions.get_at(0x401000)
if func:
    print(db.functions.get_name(func))
```

### Get Disassembly

```python
func = db.functions.get_by_name("main")
for line in db.functions.get_disassembly(func):
    print(line)
```

### Get Decompiled Pseudocode

```python
func = db.functions.get_by_name("main")
for line in db.functions.get_pseudocode(func):
    print(line)
```

### Analyze Direct Callers/Callees

```python
func = db.functions.get_by_name("main")

# Functions that call this function
callers = db.functions.get_callers(func)
print(f"Called by: {[db.functions.get_name(f) for f in callers]}")

# Functions this function calls
callees = db.functions.get_callees(func)
print(f"Calls: {[db.functions.get_name(f) for f in callees]}")
```

### Get Function Signature

```python
func = db.functions.get_by_name("printf")
sig = db.functions.get_signature(func)
print(sig)  # e.g., "int __cdecl printf(const char *, ...)"
```

### Get Basic Blocks (Flowchart)

```python
func = db.functions.get_by_name("main")
flowchart = db.functions.get_flowchart(func)
print(f"Basic blocks: {len(flowchart)}")
for block in flowchart:
    print(f"  {hex(block.start_ea)} - {hex(block.end_ea)}")
```

### Check Function Flags

```python
from ida_domain.functions import FunctionFlags

func = db.functions.get_by_name("exit")
flags = db.functions.get_flags(func)

if FunctionFlags.NORET in flags:
    print("Function does not return")
if FunctionFlags.THUNK in flags:
    print("Thunk/jump function")
if FunctionFlags.LIB in flags:
    print("Library function")
```

---

## Cross-Reference Analysis

### References TO an Address

```python
target = 0x401000
for xref in db.xrefs.to_ea(target):
    print(f"{hex(xref.from_ea)} -> {hex(xref.to_ea)} ({xref.type.name})")
```

### References FROM an Address

```python
source = 0x401000
for xref in db.xrefs.from_ea(source):
    print(f"{hex(xref.from_ea)} -> {hex(xref.to_ea)}")
```

### Specific Xref Types

```python
addr = 0x401000

# Calls to this address
for ea in db.xrefs.calls_to_ea(addr):
    print(f"Called from {hex(ea)}")

# Jumps to this address
for ea in db.xrefs.jumps_to_ea(addr):
    print(f"Jump from {hex(ea)}")

# Data reads
for ea in db.xrefs.reads_of_ea(addr):
    print(f"Read from {hex(ea)}")

# Data writes
for ea in db.xrefs.writes_to_ea(addr):
    print(f"Written from {hex(ea)}")
```

### Using XrefKind Filter

```python
from ida_domain.xrefs import XrefKind

# Only calls (using enum)
for ea in db.xrefs.get_refs_to(func_ea, XrefKind.CALLS):
    print(f"Call from {hex(ea)}")

# Only code refs (using string)
for ea in db.xrefs.get_refs_to(func_ea, "code"):
    print(f"Code ref from {hex(ea)}")
```

### Check Reference Existence

```python
# Efficient check without iterating
if db.xrefs.has_any_refs_to(addr):
    print("Address is referenced")

if db.xrefs.has_code_refs_to(func_ea):
    print("Function is called")

# Count references
count = db.xrefs.count_refs_to(addr)
print(f"Referenced {count} times")
```

---

## Call Graph Traversal

Multi-hop traversal using `db.callgraph`.

### Find All Callers (Multi-hop)

```python
# Find ALL functions that can reach dangerous_func (up to 5 call hops)
dangerous_func = db.functions.get_by_name("system")
if dangerous_func:
    print(f"Functions that can reach 'system' (5 hops):")
    for caller_ea in db.callgraph.callers_of(dangerous_func.start_ea, max_depth=5):
        name = db.names.get_at(caller_ea) or hex(caller_ea)
        print(f"  {name}")
```

### Find All Callees (Multi-hop)

```python
# Find all functions reachable from main
main_func = db.functions.get_by_name("main")
if main_func:
    print(f"Functions called from 'main' (3 hops):")
    for callee_ea in db.callgraph.callees_of(main_func.start_ea, max_depth=3):
        name = db.names.get_at(callee_ea) or hex(callee_ea)
        print(f"  {name}")
```

### Find Call Paths Between Functions

```python
# Find how main reaches a target function
main_func = db.functions.get_by_name("main")
target_func = db.functions.get_by_name("encrypt")

if main_func and target_func:
    print(f"Call paths from main to encrypt:")
    for path in db.callgraph.paths_between(main_func.start_ea, target_func.start_ea, max_depth=10):
        path_names = []
        for ea in path:
            name = db.names.get_at(ea) or hex(ea)
            path_names.append(name)
        print(f"  {' -> '.join(path_names)}")
```

### Reachability Analysis

```python
# Get set of all reachable functions
func = db.functions.get_by_name("main")
if func:
    # All functions main can call (transitively)
    reachable = db.callgraph.reachable_from(func.start_ea, max_depth=100)
    print(f"Main can reach {len(reachable)} functions")

    # All functions that can reach a target
    reaches = db.callgraph.reaches(target_ea, max_depth=100)
    print(f"{len(reaches)} functions can reach target")
```

---

## Local Variable Analysis

### List Local Variables

```python
func = db.functions.get_by_name("main")
lvars = db.functions.get_local_variables(func)
for lvar in lvars:
    var_type = "arg" if lvar.is_argument else "local"
    print(f"  {lvar.name} ({var_type}): {lvar.type_str}")
```

### Analyze Variable References

```python
from ida_domain.functions import LocalVariableAccessType, LocalVariableContext

func = db.functions.get_by_name("main")
lvars = db.functions.get_local_variables(func)

for lvar in lvars:
    refs = db.functions.get_local_variable_references(func, lvar)
    print(f"\nVariable: {lvar.name}")

    for ref in refs:
        access = ref.access_type.name  # READ, WRITE, ADDRESS
        context = ref.context.value if ref.context else "unknown"
        line = ref.line_number or "?"
        print(f"  Line {line}: {access} ({context})")
        if ref.code_line:
            print(f"    Code: {ref.code_line}")
```

### Find Variables Used as Arguments

```python
func = db.functions.get_by_name("main")
lvars = db.functions.get_local_variables(func)

for lvar in lvars:
    refs = db.functions.get_local_variable_references(func, lvar)
    for ref in refs:
        if ref.context == LocalVariableContext.CALL_ARG:
            print(f"{lvar.name} passed as argument at line {ref.line_number}")
```

### Find Written Variables

```python
func = db.functions.get_by_name("main")
lvars = db.functions.get_local_variables(func)

written_vars = []
for lvar in lvars:
    refs = db.functions.get_local_variable_references(func, lvar)
    for ref in refs:
        if ref.access_type == LocalVariableAccessType.WRITE:
            written_vars.append(lvar.name)
            break

print(f"Variables that are written: {written_vars}")
```

---

## Instruction & Operand Analysis

### Decode Instructions

```python
insn = db.instructions.get_at(0x401000)
if insn:
    mnemonic = db.instructions.get_mnemonic(insn)
    disasm = db.instructions.get_disassembly(insn)
    print(f"{mnemonic}: {disasm}")
```

### Iterate Instructions in Range

```python
func = db.functions.get_by_name("main")
if func:
    for insn in db.instructions.get_between(func.start_ea, func.end_ea):
        mnem = db.instructions.get_mnemonic(insn)
        print(f"{hex(insn.ea)}: {mnem}")
```

### Analyze Operands

```python
from ida_domain.operands import OperandType

insn = db.instructions.get_at(0x401000)
if insn:
    operands = db.instructions.get_operands(insn)
    for i, op in enumerate(operands):
        print(f"Operand {i}: {op.type.name}")

        if op.type == OperandType.REGISTER:
            print(f"  Register: {op.get_register_name()}")
        elif op.type == OperandType.IMMEDIATE:
            print(f"  Value: {hex(op.get_value())}")
        elif op.type == OperandType.MEMORY:
            addr = op.get_address()
            if addr:
                print(f"  Address: {hex(addr)}")

        # Access type
        access = op.get_access_type()
        print(f"  Access: {access.value}")
```

### Find Call Instructions

```python
func = db.functions.get_by_name("main")
if func:
    for insn in db.instructions.get_between(func.start_ea, func.end_ea):
        if db.instructions.is_call_instruction(insn):
            disasm = db.instructions.get_disassembly(insn)
            print(f"{hex(insn.ea)}: {disasm}")
```

### Find Flow-Breaking Instructions

```python
func = db.functions.get_by_name("main")
if func:
    for insn in db.instructions.get_between(func.start_ea, func.end_ea):
        if db.instructions.breaks_sequential_flow(insn):
            mnem = db.instructions.get_mnemonic(insn)
            print(f"{hex(insn.ea)}: {mnem} (breaks flow)")
```

---

## String Analysis

### List All Strings

```python
for s in db.strings:
    print(f"{hex(s.address)}: {s} (len={s.length})")
```

### Filter Strings

```python
# Find strings containing keywords
keywords = ["password", "secret", "key", "token", "api"]
for s in db.strings:
    text = str(s).lower()
    if any(kw in text for kw in keywords):
        print(f"{hex(s.address)}: {s}")
```

### Strings with Minimum Length

```python
min_len = 10
for s in db.strings:
    if s.length >= min_len:
        print(f"{hex(s.address)}: {s}")
```

### Find String References

```python
for s in db.strings:
    # Check if string is referenced
    if db.xrefs.has_any_refs_to(s.address):
        refs = list(db.xrefs.to_ea(s.address))
        print(f"{s}: referenced from {len(refs)} locations")
```

---

## Byte Operations

### Read Bytes

```python
# Single byte
byte = db.bytes.get_byte_at(0x401000)

# Word (2 bytes)
word = db.bytes.get_word_at(0x401000)

# Dword (4 bytes)
dword = db.bytes.get_dword_at(0x401000)

# Qword (8 bytes)
qword = db.bytes.get_qword_at(0x401000)

# Multiple bytes
data = db.bytes.get_bytes_at(0x401000, 16)
```

### Write/Patch Bytes

```python
# Write byte (modifies database)
db.bytes.set_byte_at(0x401000, 0x90)

# Patch byte (tracks original)
db.bytes.patch_byte_at(0x401000, 0x90)

# Revert patch
db.bytes.revert_byte_at(0x401000)

# Get original byte
orig = db.bytes.get_original_byte_at(0x401000)
```

### Check Byte Type

```python
addr = 0x401000
if db.bytes.is_code_at(addr):
    print("Code")
elif db.bytes.is_data_at(addr):
    print("Data")
elif db.bytes.is_unknown_at(addr):
    print("Undefined")
```

### Get Disassembly at Address

```python
disasm = db.bytes.get_disassembly_at(0x401000)
print(disasm)  # e.g., "push    ebp"
```

---

## Type Operations

### Parse Type Declarations

```python
declarations = """
typedef unsigned int uint32_t;
struct MyStruct {
    char *name;
    uint32_t size;
};
"""
til = db.types.get_local_library()
db.types.parse_declarations(til, declarations)
```

### Apply Type to Address

```python
db.types.apply_by_name(0x401000, "MyStruct *")
```

### Get Type by Name

```python
tinfo = db.types.get_by_name("MyStruct")
if tinfo:
    print(db.types.format_type(tinfo))
```

### Work with Type Libraries

```python
from pathlib import Path

# Create library
til = db.types.create_library(Path("/tmp/my.til"), "My types")

# Parse declarations
db.types.parse_declarations(til, declarations)

# Save and unload
db.types.save_library(til, Path("/tmp/my.til"))
db.types.unload_library(til)

# Load existing library
til = db.types.load_library(Path("/tmp/my.til"))
```

---

## Search Operations

### Find Next Address by Type

```python
from ida_domain.search import SearchTarget, SearchDirection

start = db.minimum_ea

# Find next code address
code_ea = db.search.find_next(start, SearchTarget.CODE, SearchDirection.DOWN)

# Find next undefined bytes
undef_ea = db.search.find_next(start, SearchTarget.UNDEFINED, SearchDirection.DOWN)

# Find orphaned code (not in function)
orphan = db.search.find_next(start, SearchTarget.CODE_OUTSIDE_FUNCTION, SearchDirection.DOWN)
```

### Iterate All Addresses of Type

```python
# Find all undefined bytes in range
for ea in db.search.find_all(start_ea, end_ea, SearchTarget.UNDEFINED):
    print(f"Undefined at {hex(ea)}")

# Find all orphaned code
for ea in db.search.all_code_outside_functions():
    print(f"Orphaned code at {hex(ea)}")
    # Optionally create function
    # db.functions.create(ea)
```

### Search for Problems

```python
# Find analysis errors
ea, opnum = db.search.next_error(start_ea)
if ea:
    print(f"Error at {hex(ea)}, operand {opnum}")

# Iterate all errors
for ea, opnum in db.search.all_errors():
    print(f"Error at {hex(ea)}")
```

---

## Switch Statement Analysis

### Find and Analyze Switches

```python
# Check if address has switch
switch_info = db.switches.get_at(addr)
if switch_info:
    cases = db.switches.get_cases(switch_info)
    print(f"Switch at {hex(addr)} with {len(cases)} cases")
    for case in cases:
        print(f"  Case {case.value}: {hex(case.target)}")
```

### Find Switches in Function

```python
func = db.functions.get_by_name("handle_command")
if func:
    for insn in db.instructions.get_between(func.start_ea, func.end_ea):
        switch_info = db.switches.get_at(insn.ea)
        if switch_info:
            print(f"Found switch at {hex(insn.ea)}")
```

---

## Exception Handling Analysis

### Find Try/Catch Blocks

```python
# Get try block at address
try_block = db.try_blocks.get_at(addr)
if try_block:
    print(f"Try block found")

# Get all try blocks in function
func = db.functions.get_by_name("main")
if func:
    try_blocks = db.try_blocks.get_in_function(func)
    for tb in try_blocks:
        print(f"Try block: {hex(tb.start_ea)} - {hex(tb.end_ea)}")
```

---

## Complete Script Template

```python
#!/usr/bin/env python3
"""
IDA Domain script template.

Usage: python script.py -f <binary_or_idb>
"""

import argparse
from ida_domain import Database
from ida_domain.database import IdaCommandOptions


def analyze(db_path: str) -> None:
    """Main analysis function."""
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=False)

    with Database.open(db_path, ida_options) as db:
        # Wait for auto-analysis to complete
        db.analysis.wait_for_completion()

        # Print summary
        func_count = sum(1 for _ in db.functions)
        string_count = len(db.strings)
        print(f"Functions: {func_count}")
        print(f"Strings: {string_count}")
        print(f"Architecture: {db.architecture}")
        print(f"Bitness: {db.bitness}")

        # Find interesting functions
        for func in db.functions:
            name = db.functions.get_name(func)
            if "main" in name.lower():
                print(f"\nFound {name} at {hex(func.start_ea)}")

                # Show pseudocode
                print("Pseudocode:")
                for line in db.functions.get_pseudocode(func):
                    print(f"  {line}")

                # Show callers (multi-hop)
                print("\nCallers (2 hops):")
                for caller_ea in db.callgraph.callers_of(func.start_ea, max_depth=2):
                    caller_name = db.names.get_at(caller_ea) or hex(caller_ea)
                    print(f"  {caller_name}")


def main():
    parser = argparse.ArgumentParser(description="IDA Domain analysis script")
    parser.add_argument(
        "-f", "--input-file",
        type=str,
        required=True,
        help="Binary or IDB file to analyze"
    )
    args = parser.parse_args()
    analyze(args.input_file)


if __name__ == "__main__":
    main()
```
