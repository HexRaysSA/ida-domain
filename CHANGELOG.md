# Changelog

All notable changes to ida-domain are documented in this file.

## [1.0.0] - Fork from upstream ida-domain 0.3.2

This release represents a major API overhaul from the upstream ida-domain 0.3.2, focusing on API consistency, comprehensive coverage, and LLM-friendly patterns.

### Summary

| Metric | Value |
|--------|-------|
| Total commits | 175 |
| Lines added | +48,072 |
| Lines removed | -507 |
| Files changed | 127 |
| New entity modules | 11 |
| New methods | 300+ |
| mypy strict errors | 0 (was 218) |

---

## Breaking Changes

> **Migration Guide**: All breaking changes include deprecated aliases that emit warnings. Your existing code will continue to work but you should migrate to the new API.

### Method Renames

The following methods have been renamed for API consistency. Deprecated aliases are provided for backward compatibility.

| Module | Old Name | New Name | Reason |
|--------|----------|----------|--------|
| `Decompiler` | `decompile_at(address)` | `decompile(ea)` | LLM-friendly, consistent `ea` parameter naming |
| `Functions` | `create(ea)` | `create_at(ea)` | Consistent `*_at()` pattern for address-based operations |
| `Heads` | `size(ea)` | `get_size(ea)` | Consistent `get_*()` pattern for retrieval operations |
| `Heads` | `bounds(ea)` | `get_bounds(ea)` | Consistent `get_*()` pattern for retrieval operations |
| `Imports` | `find_by_name(name)` | `get_by_name(name)` | Consistent `get_*()` pattern for retrieval operations |
| `Strings` | `get_at_index(index)` | `get_by_index(index)` | Consistent `get_by_*()` pattern |
| `Entries` | `get_at_index(index)` | `get_by_index(index)` | Consistent `get_by_*()` pattern |
| `Names` | `delete(ea)` | `delete_at(ea)` | Consistent `*_at()` pattern |
| `Fixups` | `delete(ea)` | `delete_at(ea)` | Consistent `*_at()` pattern |
| `Problems` | `remove_at(ea)` | `delete_at(ea)` | Consistent `delete_*()` for deletions |
| `Switches` | `remove_parent(ea)` | `delete_parent(ea)` | Consistent `delete_*()` for deletions |
| `TryBlocks` | `remove_in_range(...)` | `delete_in_range(...)` | Consistent `delete_*()` for deletions |

**Migration example:**

```python
# Before
lines = db.decompiler.decompile_at(0x401000)
db.functions.create(0x401000)
item_size = db.heads.size(ea)

# After
lines = db.decompiler.decompile(0x401000)
db.functions.create_at(0x401000)
item_size = db.heads.get_size(ea)
```

### Parameter Signature Changes

| Module | Method | Change | Migration |
|--------|--------|--------|-----------|
| `Types` | `apply_at()` | Parameter order changed: `(ea, type_info, flags)` - address first | Swap first two arguments |
| `Types` | `apply_at()` | Default flag changed from `GUESSED` to `DEFINITE` | Explicitly pass `GUESSED` if needed |
| `Functions` | `get_local_variable_by_name()` | Returns `None` instead of raising `KeyError` when not found | Check for `None` instead of catching `KeyError` |
| `Strings` | `get_by_index()` | Returns `None` instead of raising on invalid index | Check for `None` return value |
| `Entries` | `get_by_index()` | Returns `None` instead of raising on invalid index | Check for `None` return value |
| `StackFrames` | `delete_variable()` | Raises `LookupError` instead of returning `False` | Catch `LookupError` for non-existent variables |

**Migration example for `Types.apply_at()`:**

```python
# Before (0.3.2)
db.types.apply_at(type_info, ea)

# After (1.0.0)
db.types.apply_at(ea, type_info)
```

### Property to Method Conversions

| Module | Old | New | Migration |
|--------|-----|-----|-----------|
| `Problems` | `count` (property) | `count()` (method) | Add parentheses: `db.problems.count()` |

---

## New Entity Modules

The following new entity modules have been added, accessible via `Database` properties:

### `db.analysis` - Analysis Control
Complete auto-analysis control and queue management.

```python
db.analysis.wait()                    # Wait for analysis to complete
db.analysis.analyze(start_ea, end_ea) # Analyze a range
db.analysis.schedule(ea, "code")      # Schedule code analysis
db.analysis.cancel()                  # Cancel pending analysis
db.analysis.is_complete               # Check if analysis is done
```

### `db.decompiler` - Hex-Rays Decompiler
Decompilation support for functions.

```python
lines = db.decompiler.decompile(func_ea)  # Get pseudocode lines
if db.decompiler.is_available():          # Check decompiler availability
    ...
```

### `db.search` - Search Operations
Comprehensive search functionality with 17+ methods.

```python
ea = db.search.find_next(start_ea, "pattern")     # Find next occurrence
results = db.search.find_all("pattern")           # Find all occurrences
ea = db.search.find_text(start_ea, "string")      # Text search
ea = db.search.find_binary(start_ea, "90 90 90")  # Binary pattern
```

### `db.callgraph` - Inter-Procedural Analysis
Multi-hop call graph traversal for security analysis and impact analysis.

```python
callers = db.callgraph.callers_of(func_ea, max_depth=3)   # Transitive callers
callees = db.callgraph.callees_of(func_ea, max_depth=3)   # Transitive callees
paths = db.callgraph.paths_between(src_ea, dst_ea)        # Call paths
reachable = db.callgraph.reachable_from(func_ea)          # Reachability
```

### `db.imports` - Import Table
Import module and entry enumeration.

```python
for module in db.imports.get_modules():
    for entry in db.imports.get_entries(module):
        print(f"{module}: {entry.name} @ {hex(entry.address)}")

entry = db.imports.get_by_name("VirtualAlloc")  # Find import by name
```

### `db.exporter` - File Export
Export database contents to files.

```python
db.exporter.export(path, format=ExportFormat.ASM)   # Export to ASM
db.exporter.export(path, format=ExportFormat.LST)   # Export to LST
db.exporter.export_bytes(path, start_ea, end_ea)    # Export raw bytes
```

### `db.stack_frames` - Stack Frame Analysis
Comprehensive stack frame and variable operations.

```python
frame = db.stack_frames.get_frame(func_ea)
for var in db.stack_frames.get_variables(func_ea):
    print(f"{var.name}: offset={var.offset}, size={var.size}")

db.stack_frames.create_variable(func_ea, offset, name, size)
db.stack_frames.delete_variable(func_ea, offset)
```

### `db.switches` - Switch Statement Analysis
Switch/case table operations.

```python
switch = db.switches.get_at(insn_ea)
if switch:
    for case_val, target_ea in switch.cases:
        print(f"case {case_val}: -> {hex(target_ea)}")
```

### `db.problems` - Problem List
IDA problem/issue tracking.

```python
for problem in db.problems.get_all():
    print(f"{problem.type.name} @ {hex(problem.address)}: {problem.description}")

db.problems.delete_at(ea, ProblemType.BOUNDS)  # Remove specific problem
```

### `db.fixups` - Relocation Information
Fixup (relocation) operations.

```python
for fixup in db.fixups.get_all():
    print(f"{hex(fixup.address)}: {fixup.type.name}")

db.fixups.delete_at(ea)  # Remove fixup
```

### `db.try_blocks` - Exception Handling
Try/catch block analysis (C++ and SEH).

```python
for try_block in db.try_blocks.get_in_range(start_ea, end_ea):
    print(f"try @ {hex(try_block.start_ea)}")
    for handler in try_block.handlers:
        print(f"  catch @ {hex(handler.handler_ea)}")
```

---

## New Features

### Wildcard Pattern Search (Bytes)
IDA-style wildcard byte pattern search.

```python
# Find patterns with wildcards (? or ?? match any byte)
ea = db.bytes.find_pattern("48 8B ?? 90")
results = db.bytes.find_pattern_all("CC ?? ?? 90", start_ea, end_ea)
```

### Xref Mutation Methods
Create and delete cross-references programmatically.

```python
db.xrefs.add_code_xref(from_ea, to_ea, XrefType.CALL_NEAR)
db.xrefs.add_data_xref(insn_ea, data_ea, XrefType.READ)
db.xrefs.delete_xref(from_ea, to_ea)
```

### Pagination Helpers (Base)
Helper functions for paginating large result sets.

```python
from ida_domain.base import get_page, get_chunked

# Get page 2 of functions (50 per page)
page = get_page(db.functions.get_all(), page=2, page_size=50)

# Process in chunks
for chunk in get_chunked(db.strings.get_all(), chunk_size=100):
    process_batch(chunk)
```

### LLM-Friendly Unified Methods
Simplified, consistent API patterns optimized for LLM agents.

```python
# Analysis
db.analysis.wait()                      # vs wait_for_completion()
db.analysis.analyze(start, end)         # vs analyze_range()
db.analysis.schedule(ea, "function")    # Unified scheduling

# Functions
db.functions.count()                    # Total function count
db.functions.exists_at(ea)              # Check if function exists
db.functions.get_in_range(start, end)   # Functions in range

# Types
type_info = db.types.get(name)          # Get type by name
db.types.apply(ea, type_info)           # Apply type at address
db.types.create(name, declaration)      # Create new type

# Xrefs
refs = db.xrefs.get_refs_to(ea)         # All refs to address
refs = db.xrefs.get_refs_from(ea)       # All refs from address
```

### Improved Debug Output
Better `__repr__` methods for debugging.

```python
>>> xref = db.xrefs.get_code_refs_to(func_ea)[0]
>>> print(xref)
XrefInfo(from_ea=0x401234, to_ea=0x402000, type=CALL_NEAR)

>>> caller = db.xrefs.get_callers(func_ea)[0]
>>> print(caller)
CallerInfo(caller_ea=0x401234, callee_ea=0x402000)
```

### String-to-Enum API Refactoring
Methods that previously accepted string parameters now accept proper enum types while maintaining backward compatibility with strings. This makes the API more LLM-friendly by providing clear, discoverable options through enum members.

**Rationale**: Proper enums are more LLM-friendly than magic strings because:
- LLMs can see all valid options via enum member introspection
- Type hints provide clear documentation of accepted values
- IDE autocompletion works with enum members
- Invalid values are caught at runtime with helpful error messages

**New Enums Added**:

| Module | Enum | Values |
|--------|------|--------|
| `analysis` | `AnalysisType` | `CODE`, `FUNCTION`, `REANALYSIS` |
| `search` | `SearchTarget` | `UNDEFINED`, `DEFINED`, `CODE`, `DATA`, `CODE_OUTSIDE_FUNCTION` |
| `types` | `TypeLookupMode` | `NAME`, `ORDINAL`, `ADDRESS` |
| `types` | `TypeApplyMode` | `NAME`, `DECL`, `TINFO` |
| `xrefs` | `XrefKind` | `ALL`, `CODE`, `DATA`, `CALLS`, `JUMPS`, `READS`, `WRITES` |

**Existing Enums Updated to Accept Strings**:

| Module | Enum | Values |
|--------|------|--------|
| `search` | `SearchDirection` | `UP`, `DOWN` |
| `exporter` | `ExportFormat` | `ASM`, `LST`, `HTML`, `EXE`, `DIF`, `IDC`, `MAP` |

**Methods Updated**:

| Module | Method | Parameter | Now Accepts |
|--------|--------|-----------|-------------|
| `analysis` | `schedule(ea, what)` | `what` | `Union[AnalysisType, str]` |
| `search` | `find_next()`, `find_all()` | `target` | `Union[SearchTarget, str]` |
| `search` | `find_next()`, `find_all()` | `direction` | `Union[SearchDirection, str]` |
| `types` | `get()` | `by` | `Union[TypeLookupMode, str]` |
| `types` | `apply()` | `by` | `Union[TypeApplyMode, str]` |
| `xrefs` | `get_refs_to()`, `get_refs_from()` | `kind` | `Union[XrefKind, str]` |
| `xrefs` | `has_refs_to()`, `has_refs_from()` | `kind` | `Union[XrefKind, str]` |
| `exporter` | `export()` | `format` | `Union[ExportFormat, str]` |

**Backward Compatibility**: String values continue to work (case-insensitive):

```python
# Both forms are equivalent - use whichever you prefer
db.analysis.schedule(ea, AnalysisType.CODE)      # Enum form
db.analysis.schedule(ea, "code")                  # String form (still works)

db.xrefs.get_refs_to(ea, XrefKind.CALLS)         # Enum form
db.xrefs.get_refs_to(ea, "calls")                 # String form (still works)

db.search.find_next(ea, SearchTarget.CODE)       # Enum form
db.search.find_next(ea, "code")                   # String form (still works)

db.types.get("MyStruct", TypeLookupMode.NAME)    # Enum form
db.types.get("MyStruct", "name")                  # String form (still works)

db.exporter.export(path, ExportFormat.ASM)       # Enum form
db.exporter.export(path, "asm")                   # String form (still works)
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
| `is_operand_hex(ea, n)` | Check if operand is hex |
| `is_operand_decimal(ea, n)` | Check if operand is decimal |
| `is_operand_char(ea, n)` | Check if operand is char |
| `is_operand_binary(ea, n)` | Check if operand is binary |
| `is_operand_octal(ea, n)` | Check if operand is octal |
| `set_operand_hex(ea, n)` | Set operand to hex |
| `set_operand_decimal(ea, n)` | Set operand to decimal |
| `set_operand_char(ea, n)` | Set operand to char |
| `set_operand_offset(ea, n, base)` | Make operand an offset |
| `get_next_item(ea)` | Get next item address |
| `get_previous_item(ea)` | Get previous item address |

### Comments (15+ new methods)
| Method | Description |
|--------|-------------|
| `set_at(ea, comment, repeatable)` | Set comment at address |
| `append_at(ea, text, repeatable)` | Append to comment |
| `delete_at(ea, repeatable)` | Delete comment |
| `get_function_comment(func)` | Get function comment |
| `set_function_comment(func, comment)` | Set function comment |
| `get_anterior_lines(ea)` | Get anterior comment lines |
| `set_anterior_lines(ea, lines)` | Set anterior comment lines |
| `get_posterior_lines(ea)` | Get posterior comment lines |
| `set_posterior_lines(ea, lines)` | Set posterior comment lines |

### Segments (18+ new methods)
| Method | Description |
|--------|-------------|
| `create(start, end, name, ...)` | Create new segment |
| `delete(segment)` | Delete segment |
| `rename(segment, name)` | Rename segment |
| `set_type(segment, type)` | Set segment type |
| `set_permissions(segment, r, w, x)` | Set segment permissions |
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
| `has_code_refs_to(ea)` | Check for code refs to address |
| `has_data_refs_to(ea)` | Check for data refs to address |
| `has_code_refs_from(ea)` | Check for code refs from address |
| `has_data_refs_from(ea)` | Check for data refs from address |
| `count_code_refs_to(ea)` | Count code refs to address |
| `count_data_refs_to(ea)` | Count data refs to address |
| `add_code_xref(from, to, type)` | Create code xref |
| `add_data_xref(from, to, type)` | Create data xref |
| `delete_xref(from, to)` | Delete xref |
| `get_refs_to(ea)` | Unified: all refs to address |
| `get_refs_from(ea)` | Unified: all refs from address |

### Instructions (21+ new methods)
| Method | Description |
|--------|-------------|
| `is_call(ea)` | Check if instruction is call |
| `is_jump(ea)` | Check if instruction is jump |
| `is_conditional_jump(ea)` | Check if conditional jump |
| `is_unconditional_jump(ea)` | Check if unconditional jump |
| `is_return(ea)` | Check if instruction is return |
| `is_nop(ea)` | Check if instruction is NOP |
| `get_target(ea)` | Get branch/call target |
| `get_operand_value(ea, n)` | Get operand value |
| `get_operand_type(ea, n)` | Get operand type |
| `patch_byte(ea, value)` | Patch single byte |
| `patch_bytes(ea, bytes)` | Patch multiple bytes |
| `assemble(ea, instruction)` | Assemble instruction |

### Types (15+ new methods)
| Method | Description |
|--------|-------------|
| `get(name)` | Get type by name |
| `apply(ea, type_info)` | Apply type at address |
| `create(name, decl)` | Create new type |
| `delete(name)` | Delete type |
| `rename(old, new)` | Rename type |
| `get_size(type_info)` | Get type size |
| `get_fields(struct_type)` | Get struct fields |
| `add_field(struct, name, ...)` | Add struct field |
| `parse(declaration)` | Parse type declaration |
| `export_to(library, name)` | Export type to library |
| `copy_type(src, dst, name)` | Copy type between libraries |

---

## Bug Fixes

- Fixed `copy_type()` argument order in `Types` entity
- Fixed `copy_type()` error message (was "exporting", now "copying")
- Fixed Python 3.11 hooks-related crash
- Fixed string type retrieval issues (#17, #19)
- Fixed microcode retrieval for multi-block functions
- Fixed microcode format for jcnd/call instructions
- Fixed `LocalVariableAccessType` incorrect for instruction (#30)
- Fixed hook `ev_decorate_name` delegation and `stkpnts` typo

---

## Internal Improvements

- Full `mypy --strict` compliance (218 errors → 0)
- Comprehensive `ruff` linting compliance
- Added `__all__` exports to all modules
- Consistent type annotations using `ea_t` throughout
- Added deprecation decorator for API migration
- Split `bytes` module into submodules for maintainability
- Added comprehensive test coverage (700+ tests)
- Added test binaries for reliable testing

---

## Upgrading from 0.3.2

1. **Update method calls**: Use the migration table above to update renamed methods
2. **Check parameter order**: Especially for `Types.apply_at()`
3. **Handle `None` returns**: Methods like `get_by_index()` now return `None` instead of raising
4. **Convert properties to methods**: `db.problems.count` → `db.problems.count()`
5. **Run with warnings enabled**: Deprecated methods emit warnings to help identify migration needs

```python
import warnings
warnings.filterwarnings('default', category=DeprecationWarning)
```

All deprecated aliases will be removed in version 2.0.0.
