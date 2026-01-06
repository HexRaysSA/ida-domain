# Changelog

All notable changes to ida-domain are documented in this file.

## [1.0.0] - Fork from upstream ida-domain 0.3.2

This release is a major API overhaul from upstream ida-domain 0.3.2, focusing on API consistency, comprehensive coverage, and LLM-friendly patterns.

### Summary

| Metric | Value |
|--------|-------|
| Total commits since fork | 185 |
| Lines added | +50,049 |
| Lines removed | -507 |
| Files changed | 132 |
| New entity modules | 12 |
| New methods | 300+ |
| mypy strict errors fixed | 218 → 0 |

---

## Breaking Changes

> **Important**: All breaking changes include deprecated aliases that emit warnings. Your existing code will continue to work, but you should migrate to the new API. Run Python with warnings enabled to see deprecation notices:
> ```python
> import warnings
> warnings.filterwarnings('default', category=DeprecationWarning)
> ```

### Method Renames

| Module | Old Name | New Name | Reason |
|--------|----------|----------|--------|
| `Decompiler` | `decompile_at(address)` | `decompile(ea)` | LLM-friendly, consistent `ea` naming |
| `Functions` | `create(ea)` | `create_at(ea)` | Consistent `*_at()` pattern |
| `Heads` | `size(ea)` | `get_size(ea)` | Consistent `get_*()` pattern |
| `Heads` | `bounds(ea)` | `get_bounds(ea)` | Consistent `get_*()` pattern |
| `Imports` | `find_by_name(name)` | `get_by_name(name)` | Consistent `get_*()` pattern |
| `Strings` | `get_at_index(index)` | `get_by_index(index)` | Consistent `get_by_*()` pattern |
| `Entries` | `get_at_index(index)` | `get_by_index(index)` | Consistent `get_by_*()` pattern |
| `Names` | `delete(ea)` | `delete_at(ea)` | Consistent `*_at()` pattern |
| `Fixups` | `delete(ea)` | `delete_at(ea)` | Consistent `*_at()` pattern |
| `Problems` | `remove_at(ea)` | `delete_at(ea)` | Consistent `delete_*()` naming |
| `Switches` | `remove_parent(ea)` | `delete_parent(ea)` | Consistent `delete_*()` naming |
| `TryBlocks` | `remove_in_range(...)` | `delete_in_range(...)` | Consistent `delete_*()` naming |

**Migration example:**
```python
# Before (0.3.2)
lines = db.decompiler.decompile_at(0x401000)
db.functions.create(0x401000)
item_size = db.heads.size(ea)

# After (1.0.0)
lines = db.decompiler.decompile(0x401000)
db.functions.create_at(0x401000)
item_size = db.heads.get_size(ea)
```

### Parameter Signature Changes

| Module | Method | Change | Migration |
|--------|--------|--------|-----------|
| `Types` | `apply_at()` | Parameter order: now `(ea, type_info, flags)` | Swap first two arguments |
| `Types` | `apply_at()` | Default flag: `DEFINITE` (was `GUESSED`) | Pass `GUESSED` explicitly if needed |
| `Functions` | `get_local_variable_by_name()` | Returns `None` instead of `KeyError` | Check `is None` instead of try/except |
| `Strings` | `get_by_index()` | Returns `None` instead of raising | Check for `None` return |
| `Entries` | `get_by_index()` | Returns `None` instead of raising | Check for `None` return |
| `StackFrames` | `delete_variable()` | Raises `LookupError` instead of `False` | Catch `LookupError` |

**Migration example for `Types.apply_at()`:**
```python
# Before (0.3.2) - type first, then address
db.types.apply_at(type_info, ea)

# After (1.0.0) - address first, then type (consistent with other methods)
db.types.apply_at(ea, type_info)
```

### Property to Method Conversions

| Module | Old | New | Migration |
|--------|-----|-----|-----------|
| `Problems` | `count` (property) | `count()` (method) | Add parentheses |

```python
# Before
n = db.problems.count

# After
n = db.problems.count()
```

---

## New Entity Modules

The following new entities are accessible via `Database` properties:

### `db.analysis` - Auto-Analysis Control

Complete control over IDA's automatic analysis engine.

```python
# Wait for analysis to complete (blocking)
db.analysis.wait()

# Analyze a specific range
db.analysis.analyze(start_ea, end_ea)

# Schedule analysis for specific items
db.analysis.schedule(ea, AnalysisType.CODE)      # Schedule code analysis
db.analysis.schedule(ea, AnalysisType.FUNCTION)  # Schedule function creation
db.analysis.schedule(ea, "code")                 # String form also works

# Check analysis state
if db.analysis.is_complete:
    print("Analysis done")

# Cancel pending analysis
db.analysis.cancel()
```

### `db.decompiler` - Hex-Rays Decompiler

Decompilation support for functions.

```python
# Decompile a function
lines = db.decompiler.decompile(func_ea)
for line in lines:
    print(line)

# Check if decompiler is available
if db.decompiler.is_available():
    code = db.decompiler.decompile(ea)
```

### `db.search` - Search Operations

Comprehensive search with 17+ methods.

```python
# Find next occurrence of a target type
ea = db.search.find_next(start_ea, SearchTarget.CODE)      # Find code
ea = db.search.find_next(start_ea, SearchTarget.UNDEFINED) # Find undefined bytes
ea = db.search.find_next(start_ea, "data")                 # String form works too

# Find all occurrences
for ea in db.search.find_all(SearchTarget.CODE_OUTSIDE_FUNCTION):
    print(f"Orphaned code at 0x{ea:x}")

# Text and binary search
ea = db.search.find_text(start_ea, "password")
ea = db.search.find_binary(start_ea, "48 8B 05 ?? ?? ?? ??")  # Wildcards supported
```

### `db.callgraph` - Inter-Procedural Analysis

Multi-hop call graph traversal for security and impact analysis.

```python
# Find all functions that call a target (up to 3 levels deep)
for caller_ea in db.callgraph.callers_of(dangerous_func, max_depth=3):
    print(f"Caller: {db.names.get_at(caller_ea)}")

# Find all functions called by a target
for callee_ea in db.callgraph.callees_of(main_ea, max_depth=5):
    print(f"Calls: 0x{callee_ea:x}")

# Find call paths between two functions
for path in db.callgraph.paths_between(entry_point, target_func):
    print(path)  # CallPath(0x401000 -> 0x401234 -> 0x402000)

# Check reachability
reachable = set(db.callgraph.reachable_from(main_ea))
if vulnerable_func in reachable:
    print("Vulnerable function is reachable from main!")
```

### `db.imports` - Import Table

Import module and entry enumeration.

```python
# Iterate all imports
for module in db.imports.get_modules():
    print(f"Module: {module}")
    for entry in db.imports.get_entries(module):
        print(f"  {entry.name} @ 0x{entry.address:x}")

# Find specific import
entry = db.imports.get_by_name("VirtualAlloc")
if entry:
    print(f"VirtualAlloc at 0x{entry.address:x}")
```

### `db.exporter` - File Export

Export database contents to various formats.

```python
from ida_domain.exporter import ExportFormat

# Export to assembly
db.exporter.export("/path/to/output.asm", format=ExportFormat.ASM)
db.exporter.export("/path/to/output.asm", format="asm")  # String form works

# Export to listing
db.exporter.export("/path/to/output.lst", format=ExportFormat.LST)

# Export raw bytes
db.exporter.export_bytes("/path/to/dump.bin", start_ea, end_ea)
```

### `db.stack_frames` - Stack Frame Analysis

Comprehensive stack frame and variable operations.

```python
# Get stack frame info
frame = db.stack_frames.get_frame(func_ea)
print(f"Frame size: {frame.size}")

# Enumerate variables
for var in db.stack_frames.get_variables(func_ea):
    print(f"{var.name}: offset={var.offset}, size={var.size}")

# Create/delete variables
db.stack_frames.create_variable(func_ea, offset=-0x10, name="local_buf", size=16)
db.stack_frames.delete_variable(func_ea, offset=-0x10)
```

### `db.switches` - Switch Statement Analysis

Switch/case table operations.

```python
switch = db.switches.get_at(insn_ea)
if switch:
    print(f"Default: 0x{switch.default_ea:x}")
    for case_val, target_ea in switch.cases:
        print(f"  case {case_val}: -> 0x{target_ea:x}")
```

### `db.problems` - Problem List

IDA problem/issue tracking.

```python
# List all problems
for problem in db.problems.get_all():
    print(f"{problem.type.name} @ 0x{problem.address:x}")

# Get problem count
print(f"Total problems: {db.problems.count()}")

# Remove a problem
db.problems.delete_at(ea, ProblemType.BOUNDS)
```

### `db.fixups` - Relocation Information

Fixup (relocation) operations.

```python
for fixup in db.fixups.get_all():
    print(f"0x{fixup.address:x}: {fixup.type.name}")

# Check if address has fixup
if db.fixups.exists_at(ea):
    fixup = db.fixups.get_at(ea)
```

### `db.try_blocks` - Exception Handling

Try/catch block analysis (C++ and SEH).

```python
for try_block in db.try_blocks.get_in_range(start_ea, end_ea):
    print(f"try @ 0x{try_block.start_ea:x} - 0x{try_block.end_ea:x}")
    for handler in try_block.handlers:
        print(f"  catch @ 0x{handler.handler_ea:x}")
```

---

## New Features

### Wildcard Pattern Search

IDA-style wildcard byte pattern search.

```python
# Single wildcard byte: ? or ??
ea = db.bytes.find_pattern("48 8B ?? 90")
ea = db.bytes.find_pattern("CC ? ? 90")

# Find all matches in a range
for ea in db.bytes.find_pattern_all("E8 ?? ?? ?? ??", start_ea, end_ea):
    print(f"Call instruction at 0x{ea:x}")
```

### Xref Mutation Methods

Create and delete cross-references programmatically.

```python
from ida_domain.xrefs import XrefType

# Add xrefs
db.xrefs.add_code_xref(from_ea, to_ea, XrefType.CALL_NEAR)
db.xrefs.add_data_xref(insn_ea, data_ea, XrefType.READ)

# Delete xrefs
db.xrefs.delete_xref(from_ea, to_ea)
```

### Pagination Helpers

Process large result sets efficiently.

```python
from ida_domain.base import get_page, get_chunked

# Get page 2 of functions (50 per page)
page = get_page(db.functions.get_all(), page=2, page_size=50)

# Process in chunks
for chunk in get_chunked(db.strings.get_all(), chunk_size=100):
    process_batch(chunk)
```

### LLM-Friendly Unified Methods

Simplified, consistent API patterns.

```python
# Functions - new convenience methods
db.functions.count()              # Total function count
db.functions.exists_at(ea)        # Check if function exists
db.functions.get_in_range(s, e)   # Functions in range
db.functions.delete(ea)           # Delete function

# Types - unified API
type_info = db.types.get(name)           # Get type by name
db.types.apply(ea, type_info)            # Apply type at address
db.types.create(name, declaration)       # Create new type

# Xrefs - unified API
refs = db.xrefs.get_refs_to(ea)          # All refs to address
refs = db.xrefs.get_refs_from(ea)        # All refs from address
db.xrefs.has_refs_to(ea)                 # Check existence
```

### Improved Debug Output

Better `__repr__` methods for debugging.

```python
>>> xref = db.xrefs.get_code_refs_to(func_ea)[0]
>>> print(xref)
XrefInfo(0x401234 -> 0x402000, CALL_NEAR, code)

>>> caller = db.xrefs.get_callers(func_ea)[0]
>>> print(caller)
CallerInfo(0x401234, 'sub_401234', CALL_NEAR, func=0x401200)

>>> path = list(db.callgraph.paths_between(src, dst))[0]
>>> print(path)
CallPath(0x401000 -> 0x401234 -> 0x402000)
```

### String-to-Enum Refactoring

Methods now accept proper enums while maintaining backward compatibility with strings.

**New Enums:**

| Module | Enum | Values |
|--------|------|--------|
| `analysis` | `AnalysisType` | `CODE`, `FUNCTION`, `REANALYSIS` |
| `search` | `SearchTarget` | `UNDEFINED`, `DEFINED`, `CODE`, `DATA`, `CODE_OUTSIDE_FUNCTION` |
| `search` | `SearchDirection` | `UP`, `DOWN` |
| `types` | `TypeLookupMode` | `NAME`, `ORDINAL`, `ADDRESS` |
| `types` | `TypeApplyMode` | `NAME`, `DECL`, `TINFO` |
| `xrefs` | `XrefKind` | `ALL`, `CODE`, `DATA`, `CALLS`, `JUMPS`, `READS`, `WRITES` |
| `exporter` | `ExportFormat` | `ASM`, `LST`, `HTML`, `EXE`, `DIF`, `IDC`, `MAP` |

**Usage - both forms work:**
```python
# Enum form (recommended - IDE autocompletion, type checking)
db.analysis.schedule(ea, AnalysisType.CODE)
db.xrefs.get_refs_to(ea, XrefKind.CALLS)
db.search.find_next(ea, SearchTarget.CODE)
db.exporter.export(path, ExportFormat.ASM)

# String form (backward compatible, case-insensitive)
db.analysis.schedule(ea, "code")
db.xrefs.get_refs_to(ea, "calls")
db.search.find_next(ea, "code")
db.exporter.export(path, "asm")
```

---

## Method Additions by Entity

### Database
| Method | Description |
|--------|-------------|
| `save_as(path, flags)` | Save database to a new path |

### Functions (15+ new methods)
| Method | Description |
|--------|-------------|
| `count()` | Get total function count |
| `exists_at(ea)` | Check if function exists at address |
| `get_in_range(start, end)` | Get functions in address range |
| `delete(ea)` | Delete function at address |
| `get_previous(ea)` | Get previous function |
| `get_index(func)` | Get function index |
| `contains(ea, func)` | Check if address is in function |
| `set_start(func, new_start)` | Change function start |
| `set_end(func, new_end)` | Change function end |
| `update(func, start, end)` | Update function bounds |
| `reanalyze(func)` | Reanalyze function |
| `add_tail(func, start, end)` | Add function tail chunk |
| `remove_tail(func, tail_ea)` | Remove function tail chunk |

### Bytes (20+ new methods)
| Method | Description |
|--------|-------------|
| `find_pattern(pattern)` | Wildcard pattern search |
| `find_pattern_all(pattern)` | Find all pattern matches |
| `is_operand_hex/decimal/char/binary/octal(ea, n)` | Check operand format |
| `set_operand_hex/decimal/char(ea, n)` | Set operand format |
| `set_operand_offset(ea, n, base)` | Make operand an offset |
| `get_next_item(ea)` | Get next item address |
| `get_previous_item(ea)` | Get previous item address |

### Comments (15+ new methods)
| Method | Description |
|--------|-------------|
| `set_at(ea, comment, repeatable)` | Set comment at address |
| `append_at(ea, text, repeatable)` | Append to comment |
| `delete_at(ea, repeatable)` | Delete comment |
| `get/set_function_comment(func)` | Function comments |
| `get/set_anterior_lines(ea)` | Anterior comments |
| `get/set_posterior_lines(ea)` | Posterior comments |

### Segments (18+ new methods)
| Method | Description |
|--------|-------------|
| `create(start, end, name, ...)` | Create new segment |
| `delete(segment)` | Delete segment |
| `rename(segment, name)` | Rename segment |
| `set_type(segment, type)` | Set segment type |
| `set_permissions(segment, r, w, x)` | Set permissions |
| `move(segment, new_start)` | Move segment |
| `resize(segment, new_size)` | Resize segment |
| `split(segment, split_ea)` | Split segment |
| `merge(seg1, seg2)` | Merge segments |

### Names (5+ new methods)
| Method | Description |
|--------|-------------|
| `resolve_value(name)` | Resolve name to address |
| `is_valid_name(name)` | Check if name is valid |
| `make_unique(name)` | Make name unique |
| `demangle(name)` | Demangle C++ name |
| `format(ea, flags)` | Format name with flags |

### Xrefs (10+ new methods)
| Method | Description |
|--------|-------------|
| `has_code_refs_to/from(ea)` | Check for code refs |
| `has_data_refs_to/from(ea)` | Check for data refs |
| `count_code_refs_to(ea)` | Count code refs |
| `count_data_refs_to(ea)` | Count data refs |
| `add_code_xref(from, to, type)` | Create code xref |
| `add_data_xref(from, to, type)` | Create data xref |
| `delete_xref(from, to)` | Delete xref |
| `get_refs_to/from(ea, kind)` | Unified xref query |
| `has_refs_to/from(ea, kind)` | Unified existence check |

### Instructions (21+ new methods)
| Method | Description |
|--------|-------------|
| `is_call/jump/return/nop(ea)` | Instruction type checks |
| `is_conditional_jump(ea)` | Check if conditional |
| `is_unconditional_jump(ea)` | Check if unconditional |
| `get_target(ea)` | Get branch/call target |
| `get_operand_value(ea, n)` | Get operand value |
| `get_operand_type(ea, n)` | Get operand type |
| `patch_byte(ea, value)` | Patch single byte |
| `patch_bytes(ea, bytes)` | Patch multiple bytes |
| `assemble(ea, instruction)` | Assemble instruction |

### Types (15+ new methods)
| Method | Description |
|--------|-------------|
| `get(name, by)` | Get type (with lookup mode) |
| `apply(ea, type_info, by)` | Apply type (with apply mode) |
| `create(name, decl)` | Create new type |
| `delete(name)` | Delete type |
| `rename(old, new)` | Rename type |
| `get_size(type_info)` | Get type size |
| `get_fields(struct_type)` | Get struct fields |
| `add_field(struct, name, ...)` | Add struct field |
| `parse(declaration)` | Parse type declaration |

---

## Bug Fixes

- **Fixed `copy_type()` argument order** in Types entity (was reversed)
- **Fixed `copy_type()` error message** ("exporting" → "copying")
- **Fixed Python 3.11 hooks crash** (#16)
- **Fixed string type retrieval** (#17, #19)
- **Fixed microcode retrieval** for multi-block functions
- **Fixed microcode format** for jcnd/call instructions
- **Fixed `LocalVariableAccessType`** incorrect for instruction (#30, #31)
- **Fixed hook `ev_decorate_name`** delegation and `stkpnts` typo

---

## Internal Improvements

- Full `mypy --strict` compliance (218 errors → 0)
- Comprehensive `ruff` linting compliance
- Added `__all__` exports to all modules
- Consistent type annotations using `ea_t` throughout
- Added deprecation decorator for API migration
- Split `bytes` module into submodules for maintainability
- Added comprehensive test coverage (700+ tests)
- Added dedicated test binaries for reliable testing

---

## Upgrading from 0.3.2

### Quick Migration Checklist

1. **Run with deprecation warnings enabled:**
   ```python
   import warnings
   warnings.filterwarnings('default', category=DeprecationWarning)
   ```

2. **Update renamed methods:**
   ```python
   # Decompiler
   decompile_at(ea)  →  decompile(ea)

   # Functions
   create(ea)  →  create_at(ea)

   # Heads
   size(ea)    →  get_size(ea)
   bounds(ea)  →  get_bounds(ea)

   # Imports
   find_by_name(n)  →  get_by_name(n)

   # Strings/Entries
   get_at_index(i)  →  get_by_index(i)

   # Deletion methods
   delete(ea)     →  delete_at(ea)      # Names, Fixups
   remove_at(ea)  →  delete_at(ea)      # Problems
   remove_*(...)  →  delete_*(...)      # Switches, TryBlocks
   ```

3. **Fix parameter order for `Types.apply_at()`:**
   ```python
   apply_at(type_info, ea)  →  apply_at(ea, type_info)
   ```

4. **Update property to method:**
   ```python
   db.problems.count  →  db.problems.count()
   ```

5. **Handle `None` returns instead of exceptions:**
   ```python
   # Before
   try:
       var = db.functions.get_local_variable_by_name(func, name)
   except KeyError:
       var = None

   # After
   var = db.functions.get_local_variable_by_name(func, name)
   if var is None:
       ...
   ```

### Deprecated Aliases

All deprecated method names continue to work and emit `DeprecationWarning`. They will be removed in version 2.0.0.
