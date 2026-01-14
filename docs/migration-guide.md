# IDA Domain API Migration Guide

This guide documents the migration from the low-level IDA Python SDK to the IDA Domain API, based on the [capa project](https://github.com/mandiant/capa)'s migration here: https://github.com/mandiant/capa/pull/2810.

## Table of Contents

1. [Overview](#overview)
2. [Domain API Namespaces](#domain-api-namespaces)
3. [Aside: Dependency Injection](#aside-dependency-injection)
4. [High-Level API Mapping Table](#high-level-api-mapping-table)
5. [Gotchas and Important Notes](#gotchas-and-important-notes)
6. [Migration Patterns](#migration-patterns)
7. [SDK Fallbacks](#sdk-fallbacks)
8. [Using idalib (Headless IDA)](#using-idalib-headless-ida)
9. [Working with Temporary Directories](#working-with-temporary-directories)

---

## Overview

The IDA Domain API (`ida_domain`) provides a cleaner, more Pythonic interface to IDA Pro's functionality. Key benefits:

- **Explicit dependencies**: All functions receive a [`Database`](ref/database.md) handle instead of using global state
- **Organized namespaces**: Functions grouped logically (`db.functions.*`, `db.bytes.*`, etc.)
- **Simplified version handling**: No need for version-specific code paths (IDA 7.5/8/9)
- **Better testability**: Dependency injection enables mocking
- **Type-safe enums**: Use `FunctionFlags.THUNK` instead of `idaapi.FUNC_THUNK`

---

## Domain API Namespaces

The IDA Domain API organizes functionality into logical namespaces:

| Namespace         | Purpose                                                   |
| ----------------- | --------------------------------------------------------- |
| [`db.bytes`](ref/bytes.md)        | Binary data operations (find, read, check initialization) |
| [`db.functions`](ref/functions.md)    | Function enumeration, properties, flowcharts, comments    |
| [`db.segments`](ref/segments.md)     | Segment enumeration and lookup                            |
| [`db.heads`](ref/heads.md)        | Head (item) navigation                                    |
| [`db.instructions`](ref/instructions.md) | Instruction decoding, mnemonic, disassembly               |
| [`db.xrefs`](ref/xrefs.md)        | Cross-reference navigation                                |
| [`db.names`](ref/names.md)        | Name/symbol operations                                    |
| [`db.comments`](ref/comments.md)     | Comment retrieval                                         |
| [`db.entries`](ref/entries.md)      | Entry point enumeration                                   |

[Root-level properties and methods](ref/database.md):

- `db.md5`, `db.sha256` - File hashes
- `db.base_address` - Image base
- `db.format` - File format
- `db.architecture` - Processor name
- `db.bitness` - 16, 32, or 64
- `db.is_valid_ea(ea)` - Address validation

---

## Aside: Dependency Injection

A fundamental change is that all functions now receive a `db: Database` parameter as their first argument. Rather than relying on global accessors, we access entities through a [Database](ref/database.md) reference. This may allow us to work on multiple databases in parallel, sometime in the future.

**Before (implicit global state):**
```python
def get_functions():
    for ea in idautils.Functions():
        f = idaapi.get_func(ea)
        yield f
```

**After (explicit dependency injection):**
```python
def get_functions(db: Database):
    for f in db.functions.get_all():
        yield f
```

---

## High-Level API Mapping Table

### [Database Properties](ref/database.md)

| Old API | New API |
|---------|---------|
| `ida_nalt.retrieve_input_file_md5()` | `db.md5` |
| `ida_nalt.retrieve_input_file_sha256()` | `db.sha256` |
| `idaapi.get_imagebase()` | `db.base_address` |
| `ida_loader.get_file_type_name()` | `db.format` |
| `idaapi.get_inf_structure().procname` (IDA<9) / `idc.get_processor_name()` (IDA9+) | `db.architecture` |
| `idaapi.get_inf_structure().is_64bit()` (IDA<9) / `idaapi.inf_is_64bit()` (IDA9+) | `db.bitness == 64` |
| `idaapi.get_inf_structure().is_32bit()` (IDA<9) / `idaapi.inf_is_32bit_exactly()` (IDA9+) | `db.bitness == 32` |

### [Function Operations](ref/functions.md) (`db.functions`)

| Old API | New API |
|---------|---------|
| `idautils.Functions()` | `db.functions.get_all()` |
| `idautils.Functions(start, end)` | `db.functions.get_between(start, end)` |
| `idaapi.get_func(ea)` | `db.functions.get_at(ea)` |
| `idaapi.get_func_name(ea)` | `db.functions.get_name(f)` |
| `f.flags & idaapi.FUNC_THUNK` | `db.functions.get_flags(f) & FunctionFlags.THUNK` |
| `f.flags & idaapi.FUNC_LIB` | `db.functions.get_flags(f) & FunctionFlags.LIB` |
| `ida_funcs.get_func_cmt(f, False)` | `db.functions.get_comment(f, False)` |
| `idaapi.FlowChart(f, flags=...)` | `db.functions.get_flowchart(f, flags=...)` |

### [Byte Operations](ref/bytes.md) (`db.bytes`)

| Old API | New API |
|---------|---------|
| `idc.get_bytes(ea, count)` | `db.bytes.get_bytes_at(ea, count)` |
| `idaapi.get_bytes(ea, sz)` | `db.bytes.get_bytes_at(ea, sz)` |
| `idc.is_loaded(ea)` | `db.bytes.is_value_initialized_at(ea)` |
| `ida_bytes.bin_search()` + patterns | `db.bytes.find_binary_sequence(seq, start, end)` |

### [Segment Operations](ref/segments.md) (`db.segments`)

| Old API | New API |
|---------|---------|
| `idaapi.get_segm_qty()` + `idaapi.getnseg(n)` | `db.segments.get_all()` |
| `idaapi.getseg(ea)` | `db.segments.get_at(ea)` |
| `idc.get_segm_end(ea)` | `db.segments.get_at(ea).end_ea` |
| `idaapi.get_segm_name(seg)` | `db.segments.get_name(seg)` |

### Head/Instruction Operations ([Heads](ref/heads.md), [Instructions](ref/instructions.md))

| Old API | New API |
|---------|---------|
| `idautils.Heads(start, end)` | `db.heads.get_between(start, end)` |
| `idc.prev_head(ea)` | `db.heads.get_previous(ea)` |
| `idautils.DecodeInstruction(head)` | `db.instructions.get_at(head)` |
| `insn.get_canon_mnem()` | `db.instructions.get_mnemonic(insn)` |
| `idc.GetDisasm(ea)` | `db.instructions.get_disassembly(insn)` |
| `idaapi.is_call_insn(insn)` | `db.instructions.is_call_instruction(insn)` |
| `idaapi.is_ret_insn(insn)` | `db.instructions.breaks_sequential_flow(insn)` |
| `insn.itype == idaapi.NN_xor` | `db.instructions.get_mnemonic(insn) == "xor"` |

### [Cross-Reference Operations](ref/xrefs.md) (`db.xrefs`)

| Old API | New API |
|---------|---------|
| `idautils.CodeRefsTo(ea, True)` | `db.xrefs.code_refs_to_ea(ea)` |
| `idautils.CodeRefsFrom(ea, False)` | `db.xrefs.code_refs_from_ea(ea, flow=False)` |
| `idautils.DataRefsFrom(ea)` | `db.xrefs.data_refs_from_ea(ea)` |

### [Name Operations](ref/names.md) (`db.names`)

| Old API | New API |
|---------|---------|
| `idaapi.get_name(ea)` | `db.names.get_at(ea)` |

### [Comment Operations](ref/comments.md) (`db.comments`)

| Old API | New API |
|---------|---------|
| `ida_bytes.get_cmt(ea, False)` | `db.comments.get_at(ea)` |

### [Entry Point Operations](ref/entries.md) (`db.entries`)

| Old API | New API |
|---------|---------|
| `idautils.Entries()` | `db.entries.get_all()` |
| `ida_entry.get_entry_forwarder(ordinal)` | `entry.has_forwarder()` / `entry.forwarder_name` |

### Address Validation

| Old API | New API |
|---------|---------|
| `idaapi.is_mapped(ea)` | `db.is_valid_ea(ea)` |

---

## Gotchas and Important Notes

### 1. Return Type Differences

The Domain API often returns `None` instead of sentinel values:

| Old Behavior                             | New Behavior                                                 |
| ---------------------------------------- | ------------------------------------------------------------ |
| `idc.prev_head()` returns `BADADDR`      | `db.heads.get_previous()` returns `None`                     |
| `idaapi.get_name()` returns empty string | `db.names.get_at()` returns `None`                           |
| `ida_bytes.get_cmt()` returns string     | `db.comments.get_at()` returns object with `.comment` attribute |

**Always check for `None`:**

```python
# Old
name = idaapi.get_name(ea)
if name.startswith("sub_"):
    ...

# New - must check for None first!
name = db.names.get_at(ea)
if not name or name.startswith("sub_"):
    ...
```

### 2. Bytes Can Return None

```python
# Always use fallback
return db.bytes.get_bytes_at(ea, count) or b""
```

### 3. Function Objects vs Addresses

Old API returns addresses, new API returns function objects:

```python
# Old: enumerate addresses, then get function
for ea in idautils.Functions():
    f = idaapi.get_func(ea)
    # use ea and f

# New: enumerate function objects directly
for f in db.functions.get_all():
    # f is already the function object
    ea = f.start_ea  # get address from object
```

### 4. Explicit Flow Parameter

```python
# Old - positional boolean
idautils.CodeRefsFrom(ea, False)

# New - explicit keyword argument
db.xrefs.code_refs_from_ea(ea, flow=False)
```

### 5. Semantic Differences

`db.instructions.breaks_sequential_flow(insn)` is broader than `idaapi.is_ret_insn(insn)` - it covers returns, unconditional jumps, etc.

### 6. Retained SDK Types

The Domain API wraps SDK objects but doesn't replace them. You still work with `idaapi.func_t`, `idaapi.insn_t`, `idaapi.BasicBlock`, etc.

### 7. API Consistency Pattern

Functions that still use SDK fallbacks keep the `db` parameter for consistency:

```python
def get_file_imports(db: Database):  # db unused, kept for API consistency
    # Still uses idaapi.get_import_module_qty() etc.
    ...
```

---

## Migration Patterns

### Pattern 1: Binary Search Simplification

**Before (version-specific branching):**
```python
IDA_NALT_ENCODING = ida_nalt.get_default_encoding_idx(ida_nalt.BPU_1B)

def find_byte_sequence(start: int, end: int, seq: bytes) -> Iterator[int]:
    patterns = ida_bytes.compiled_binpat_vec_t()
    seqstr = " ".join([f"{b:02x}" for b in seq])
    err = ida_bytes.parse_binpat_str(patterns, 0, seqstr, 16, IDA_NALT_ENCODING)
    if err:
        return
    while True:
        ea = ida_bytes.bin_search(start, end, patterns, ida_bytes.BIN_SEARCH_FORWARD)
        if isinstance(ea, tuple):
            ea = ea[0]  # IDA 9 returns tuple
        if ea == idaapi.BADADDR:
            break
        start = ea + 1
        yield ea
```

**After:**
```python
def find_byte_sequence(db: Database, start: int, end: int, seq: bytes) -> Iterator[int]:
    for match in db.bytes.find_binary_sequence(seq, start, end):
        yield match
```

### Pattern 2: Function Enumeration with Flag Checking

**Before:**
```python
def get_functions(skip_thunks=False, skip_libs=False):
    for ea in idautils.Functions():
        f = idaapi.get_func(ea)
        if skip_thunks and (f.flags & idaapi.FUNC_THUNK):
            continue
        if skip_libs and (f.flags & idaapi.FUNC_LIB):
            continue
        yield f
```

**After:**
```python
def get_functions(db: Database, skip_thunks=False, skip_libs=False):
    for f in db.functions.get_all():
        flags = db.functions.get_flags(f)
        if skip_thunks and (flags & FunctionFlags.THUNK):
            continue
        if skip_libs and (flags & FunctionFlags.LIB):
            continue
        yield f
```

### Pattern 3: Entry Point Enumeration

The old API returns tuples that require unpacking, while `db.entries.get_all()` yields [`EntryInfo`](ref/entries.md) dataclass objects:

```python
@dataclass(frozen=True)
class EntryInfo:
    ordinal: int        # export ordinal number
    address: int        # address of entry point
    name: str           # entry point name
    forwarder_name: str # forwarder name (or empty string)

    def has_forwarder(self) -> bool: ...
```

**Before (tuple unpacking):**
```python
def extract_exports():
    for _, ordinal, ea, name in idautils.Entries():
        forwarded_name = ida_entry.get_entry_forwarder(ordinal)
        if forwarded_name is None:
            yield Export(name), ea
        else:
            yield Export(forwarded_name), ea
```

**After (EntryInfo properties):**
```python
def extract_exports(db: Database):
    for entry in db.entries.get_all():
        if entry.has_forwarder():
            yield Export(entry.forwarder_name), entry.address
        else:
            yield Export(entry.name), entry.address
```

### Pattern 4: Comment Retrieval

The old API returns a string directly, while `db.comments.get_at()` returns a [`CommentInfo`](ref/comments.md) dataclass (or `None`):

```python
@dataclass(frozen=True)
class CommentInfo:
    ea: int        # address of the comment
    comment: str   # the comment text
    repeatable: bool  # True if repeatable comment
```

**Before (returns string):**
```python
if contains_keywords(idaapi.get_cmt(ea, False)):
    return True
```

**After (returns CommentInfo):**
```python
cmt_info = db.comments.get_at(ea)
cmt = cmt_info.comment if cmt_info else ""
if contains_keywords(cmt):
    return True
```

### Pattern 5: Architecture Detection

**Before (version-specific with boolean predicates):**
```python
# IDA < 9
info = idaapi.get_inf_structure()
procname = info.procname
if procname == "metapc" and info.is_64bit():
    yield Arch(ARCH_AMD64)
elif procname == "metapc" and info.is_32bit():
    yield Arch(ARCH_I386)

# IDA 9+
procname = idc.get_processor_name()
if procname == "metapc" and idaapi.inf_is_64bit():
    yield Arch(ARCH_AMD64)
elif procname == "metapc" and idaapi.inf_is_32bit_exactly():
    yield Arch(ARCH_I386)
```

**After (unified integer comparison):**
```python
arch = db.architecture
bitness = db.bitness
if arch == "metapc" and bitness == 64:
    yield Arch(ARCH_AMD64)
elif arch == "metapc" and bitness == 32:
    yield Arch(ARCH_I386)
```

### Pattern 6: Mnemonic-Based Dispatch

**Before (itype constants):**
```python
if insn.itype in (idaapi.NN_xor, idaapi.NN_xorpd, idaapi.NN_xorps, idaapi.NN_pxor):
    # handle xor
```

**After (string comparison):**
```python
mnem = db.instructions.get_mnemonic(insn)
if mnem in ("xor", "xorpd", "xorps", "pxor"):
    # handle xor
```

---

## SDK Fallbacks

Some functionality has no Domain API equivalent yet:

| Function | SDK Calls Still Used |
|----------|---------------------|
| `get_file_imports()` | `idaapi.get_import_module_qty()`, `idaapi.enum_import_names()`, but https://github.com/HexRaysSA/ida-domain/pull/39 is coming |
| `find_string_at()` | `idaapi.get_strlit_contents()` |
| Various operand operations | `idc.get_operand_value()` |
| FlowChart flags | `idaapi.FC_PREDS`, `idaapi.FC_NOEXT` |
| Segment type checking | `ida_segment.SEG_XTRN` |

---

## Using idalib (Headless IDA)

When using IDA in headless/batch mode via `idalib`, the Domain API provides a clean interface through `Database.open()` with `IdaCommandOptions`.

### Pattern: Loading a Database with Domain API (Recommended)

```python
from pathlib import Path
from ida_domain import Database
from ida_domain.database import IdaCommandOptions

def analyze_file(input_path: Path, save=True):
    """Open and analyze a file using the Domain API."""
    opts = IdaCommandOptions(
        auto_analysis=True,       # Enable auto-analysis
        load_resources=True,      # Load Windows resources (helps find embedded PEs)
        # Disable Lumina via plugin options
        plugin_options="lumina:host=0.0.0.0;secondary_lumina:host=0.0.0.0",
    )

    with Database.open(str(input_path), args=opts, save_on_close=save) as db:
        for f in db.functions.get_all():
            print(db.functions.get_name(f))

```

### IdaCommandOptions Reference

| Option | Type | Purpose |
|--------|------|---------|
| `auto_analysis` | `bool` | Enable/disable automatic analysis |
| `load_resources` | `bool` | Load Windows resources (replaces `-R` flag) |
| `plugin_options` | `str` | Plugin options string (for Lumina, etc.) |
| `processor` | `str` | Processor type identifier (e.g., "arm", "metapc") |
| `loading_address` | `int` | Load address in paragraphs |
| `new_database` | `bool` | Create fresh database, deleting old one |
| `db_compression` | `str` | Compression: "compress", "pack", or "no_pack" |
| `script_file` | `str` | Script to execute on database open |
| `script_args` | `list[str]` | Arguments passed to script |

---

## Working with Temporary Directories

When processing files with idalib, IDA creates database files (`.i64`/`.idb`) alongside the input file. This can be problematic for:
- Read-only file locations
- Parallel processing of (the same) files

### Pattern: Copy to Temp Directory Before Analysis

```python
import shutil
import tempfile
from pathlib import Path
from contextlib import contextmanager

from ida_domain import Database
from ida_domain.database import IdaCommandOptions

@contextmanager
def analyze_in_temp_directory(input_path: Path):
    """
    Copy file to a temp directory before analysis to avoid
    creating .i64/.idb files in the original location.
    """
    input_path = Path(input_path)

    with tempfile.TemporaryDirectory() as tmpdir:
        # Copy the input file to temp directory
        temp_file = Path(tmpdir) / input_path.name
        shutil.copy2(input_path, temp_file)
        
        # see this function above
        analyze_file(temp_file, save=False)

# Usage:
with analyze_in_temp_directory(Path("/path/to/sample.exe")) as db:
    for f in db.functions.get_all():
        print(db.functions.get_name(f))
```
