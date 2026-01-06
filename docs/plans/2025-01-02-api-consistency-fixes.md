# API Consistency Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Standardize the ida-domain SDK public API to follow consistent naming, parameter, type annotation, and return-shape conventions across all modules.

**Architecture:** Each task targets a specific module or group of related modules. Changes are mostly mechanical renames and type annotation fixes. Deprecation aliases are added where methods are renamed to maintain backwards compatibility.

**Tech Stack:** Python 3.8+, typing_extensions, pytest

---

## Task 1: Fix `fixups.py` - Parameter Naming (`address` → `ea`)

**Files:**
- Modify: `ida_domain/fixups.py`
- Test: Run existing tests to verify no regressions

**Step 1: Rename `address` parameter to `ea` throughout**

In `ida_domain/fixups.py`, replace all occurrences of `address: ea_t` with `ea: ea_t`:

```python
# Line ~173: get_at
def get_at(self, ea: ea_t) -> Optional[FixupInfo]:

# Line ~203: get_type_at
def get_type_at(self, ea: ea_t) -> Optional[FixupType]:

# Line ~292: create
def create(self, ea: ea_t, fixup_type: FixupType, ...) -> bool:

# Line ~416: delete (will be renamed to delete_at in Task 2)
def delete(self, ea: ea_t) -> bool:
```

**Step 2: Rename range parameters `start_address/end_address` → `start_ea/end_ea`**

```python
# Line ~249: get_between
def get_between(self, start_ea: ea_t, end_ea: ea_t) -> Iterator[FixupInfo]:
```

**Step 3: Update all internal references**

Search and replace within method bodies:
- `address` → `ea`
- `start_address` → `start_ea`
- `end_address` → `end_ea`

**Step 4: Run tests**

```bash
pytest tests/ -k fixup -v
```

Expected: All tests pass

**Step 5: Commit**

```bash
git add ida_domain/fixups.py
git commit -m "refactor(fixups): rename address params to ea for consistency"
```

---

## Task 2: Fix Deletion Methods - Add `_at` Suffix

**Files:**
- Modify: `ida_domain/fixups.py`
- Modify: `ida_domain/names.py`
- Test: Run existing tests

**Step 1: Rename `delete()` to `delete_at()` in fixups.py**

```python
# Line ~416
def delete_at(self, ea: ea_t) -> bool:
    """
    Delete the fixup at the specified address.

    Args:
        ea: The effective address of the fixup to delete.

    Returns:
        True if the fixup was deleted, False otherwise.
    """
    if not self.database.is_valid_ea(ea):
        raise InvalidEAError(ea)
    return cast(bool, ida_fixup.del_fixup(ea))

@deprecated("Use delete_at() instead")
def delete(self, ea: ea_t) -> bool:
    """Deprecated: Use delete_at() instead."""
    return self.delete_at(ea)
```

**Step 2: Rename `delete()` to `delete_at()` in names.py**

```python
# Line ~212
def delete_at(self, ea: ea_t) -> bool:
    """
    Delete the name at the specified address.

    Args:
        ea: The effective address.

    Returns:
        True if the name was successfully deleted.
    """
    if not self.database.is_valid_ea(ea):
        raise InvalidEAError(ea)
    return cast(bool, ida_name.del_global_name(ea))

@deprecated("Use delete_at() instead")
def delete(self, ea: ea_t) -> bool:
    """Deprecated: Use delete_at() instead."""
    return self.delete_at(ea)
```

**Step 3: Run tests**

```bash
pytest tests/ -k "fixup or name" -v
```

Expected: All tests pass

**Step 4: Commit**

```bash
git add ida_domain/fixups.py ida_domain/names.py
git commit -m "refactor(names,fixups): rename delete() to delete_at() for consistency"
```

---

## Task 3: Fix `problems.py` - Rename `remove_at()` to `delete_at()`

**Files:**
- Modify: `ida_domain/problems.py`

**Step 1: Rename `remove_at()` to `delete_at()`**

```python
# Line ~517
def delete_at(self, ea: ea_t) -> int:
    """
    Delete all problems at the specified address.

    Args:
        ea: The effective address.

    Returns:
        The number of problems deleted.
    """
    if not self.database.is_valid_ea(ea):
        raise InvalidEAError(ea)
    count = 0
    for problem_type in ProblemType:
        if ida_problems.forget_problem(problem_type.value, ea):
            count += 1
    return count

@deprecated("Use delete_at() instead")
def remove_at(self, ea: ea_t) -> int:
    """Deprecated: Use delete_at() instead."""
    return self.delete_at(ea)
```

**Step 2: Run tests**

```bash
pytest tests/ -k problem -v
```

**Step 3: Commit**

```bash
git add ida_domain/problems.py
git commit -m "refactor(problems): rename remove_at() to delete_at()"
```

---

## Task 4: Fix `try_blocks.py` - Rename `remove_in_range()` to `delete_in_range()`

**Files:**
- Modify: `ida_domain/try_blocks.py`

**Step 1: Rename method**

```python
# Line ~684
def delete_in_range(self, start_ea: ea_t, end_ea: ea_t) -> bool:
    """
    Delete all try blocks in the specified range.

    Args:
        start_ea: Start of the range.
        end_ea: End of the range.

    Returns:
        True if any blocks were deleted.
    """
    # ... existing implementation

@deprecated("Use delete_in_range() instead")
def remove_in_range(self, start_ea: ea_t, end_ea: ea_t) -> bool:
    """Deprecated: Use delete_in_range() instead."""
    return self.delete_in_range(start_ea, end_ea)
```

**Step 2: Run tests**

```bash
pytest tests/ -k try_block -v
```

**Step 3: Commit**

```bash
git add ida_domain/try_blocks.py
git commit -m "refactor(try_blocks): rename remove_in_range() to delete_in_range()"
```

---

## Task 5: Fix `switches.py` - Rename `remove_parent()` to `delete_parent()`

**Files:**
- Modify: `ida_domain/switches.py`

**Step 1: Rename method**

```python
# Line ~495
def delete_parent(self, ea: ea_t) -> bool:
    """
    Delete the switch parent at the specified address.

    Args:
        ea: The effective address.

    Returns:
        True if deleted successfully.
    """
    # ... existing implementation

@deprecated("Use delete_parent() instead")
def remove_parent(self, ea: ea_t) -> bool:
    """Deprecated: Use delete_parent() instead."""
    return self.delete_parent(ea)
```

**Step 2: Run tests**

```bash
pytest tests/ -k switch -v
```

**Step 3: Commit**

```bash
git add ida_domain/switches.py
git commit -m "refactor(switches): rename remove_parent() to delete_parent()"
```

---

## Task 6: Fix `entries.py` - Rename `get_at_index()` to `get_by_index()` and Return None

**Files:**
- Modify: `ida_domain/entries.py`

**Step 1: Rename method and change error handling**

```python
# Line ~85
def get_by_index(self, index: int) -> Optional[EntryInfo]:
    """
    Get entry point by index.

    Args:
        index: The index of the entry point.

    Returns:
        The EntryInfo if found, None if index is out of range.
    """
    if index < 0 or index >= len(self):
        return None
    ordinal = ida_entry.get_entry_ordinal(index)
    ea = ida_entry.get_entry(ordinal)
    name = ida_entry.get_entry_name(ordinal)
    return EntryInfo(ordinal=ordinal, ea=ea, name=name if name else "")

@deprecated("Use get_by_index() instead")
def get_at_index(self, index: int) -> EntryInfo:
    """Deprecated: Use get_by_index() instead. Raises IndexError for compatibility."""
    result = self.get_by_index(index)
    if result is None:
        raise IndexError(f"Entry index {index} out of range")
    return result
```

**Step 2: Update docstrings to say EntryInfo not Entry**

Fix any docstrings that incorrectly reference "Entry" instead of "EntryInfo".

**Step 3: Run tests**

```bash
pytest tests/ -k entry -v
```

**Step 4: Commit**

```bash
git add ida_domain/entries.py
git commit -m "refactor(entries): rename get_at_index() to get_by_index(), return None for invalid"
```

---

## Task 7: Fix `strings.py` - Rename `get_at_index()` to `get_by_index()`

**Files:**
- Modify: `ida_domain/strings.py`

**Step 1: Rename method**

```python
def get_by_index(self, index: int) -> Optional[StringItem]:
    """
    Get string by index.

    Args:
        index: The index of the string.

    Returns:
        The StringItem if found, None if index is out of range.
    """
    # Change IndexError to return None
    if index < 0 or index >= len(self):
        return None
    # ... rest of implementation

@deprecated("Use get_by_index() instead")
def get_at_index(self, index: int) -> StringItem:
    """Deprecated: Use get_by_index() instead."""
    result = self.get_by_index(index)
    if result is None:
        raise IndexError(f"String index {index} out of range")
    return result
```

**Step 2: Run tests**

```bash
pytest tests/ -k string -v
```

**Step 3: Commit**

```bash
git add ida_domain/strings.py
git commit -m "refactor(strings): rename get_at_index() to get_by_index()"
```

---

## Task 8: Fix `imports.py` - Rename `find_by_name()` to `get_by_name()`

**Files:**
- Modify: `ida_domain/imports.py`

**Step 1: Rename method**

```python
# Line ~451
def get_by_name(self, name: str, module: Optional[str] = None) -> Optional[ImportEntry]:
    """
    Get import entry by name.

    Args:
        name: The name of the import.
        module: Optional module name to search within.

    Returns:
        The ImportEntry if found, None otherwise.
    """
    # ... existing implementation

@deprecated("Use get_by_name() instead")
def find_by_name(self, name: str, module: Optional[str] = None) -> Optional[ImportEntry]:
    """Deprecated: Use get_by_name() instead."""
    return self.get_by_name(name, module)
```

**Step 2: Run tests**

```bash
pytest tests/ -k import -v
```

**Step 3: Commit**

```bash
git add ida_domain/imports.py
git commit -m "refactor(imports): rename find_by_name() to get_by_name()"
```

---

## Task 9: Fix `imports.py` - Type Annotation Consistency

**Files:**
- Modify: `ida_domain/imports.py`

**Step 1: Change import source**

```python
# Line 5: Change
from typing import TYPE_CHECKING, Callable, Iterator, Optional, Union
# To:
from typing_extensions import TYPE_CHECKING, Iterator, Optional
from typing import Callable, Union
```

**Step 2: Replace `list[str]` with `List[str]`**

Add `List` to imports and replace lowercase `list` with `List`:

```python
from typing_extensions import TYPE_CHECKING, Iterator, List, Optional
```

**Step 3: Replace `str | None` with `Optional[str]`**

Search for `| None` patterns and replace with `Optional[T]`.

**Step 4: Run tests**

```bash
pytest tests/ -k import -v
```

**Step 5: Commit**

```bash
git add ida_domain/imports.py
git commit -m "refactor(imports): fix type annotation style for consistency"
```

---

## Task 10: Fix `comments.py` - Type Annotations (`int` → `ea_t`)

**Files:**
- Modify: `ida_domain/comments.py`

**Step 1: Replace `ea: int` with `ea: ea_t` throughout**

Affected methods (approximate lines):
- `set_at` (117)
- `delete_at` (140)
- `set_extra_at` (197)
- `get_extra_at` (219)
- `get_all_extra_at` (240)
- `delete_extra_at` (266)
- `get_first_free_extra_index` (323)
- `generate_disasm_line` (359)
- `generate_disassembly` (389)
- `get_prefix_color` (580)
- `get_background_color` (603)
- `add_sourcefile` (626) - also `start_ea: int, end_ea: int`
- `get_sourcefile` (657)
- `delete_sourcefile` (690)

**Step 2: Change `delete_at` return type to `bool`**

```python
def delete_at(self, ea: ea_t, repeatable: bool = False) -> bool:
    """..."""
    # Add return statement
    return ida_bytes.del_cmt(ea, repeatable)
```

**Step 3: Run tests**

```bash
pytest tests/ -k comment -v
```

**Step 4: Commit**

```bash
git add ida_domain/comments.py
git commit -m "refactor(comments): fix type annotations to use ea_t"
```

---

## Task 11: Fix `functions.py` - Type Annotations and Method Renames

**Files:**
- Modify: `ida_domain/functions.py`

**Step 1: Fix `ea: int` to `ea: ea_t`**

```python
# Line ~931
def get_next(self, ea: ea_t) -> Optional[func_t]:

# Line ~1007
def get_chunk_at(self, ea: ea_t) -> Optional[FunctionChunk]:
```

**Step 2: Rename `create()` to `create_at()` with deprecation alias**

```python
# Line ~875
def create_at(self, ea: ea_t) -> Optional[func_t]:
    """Create a function at the specified address."""
    # ... existing implementation

@deprecated("Use create_at() instead")
def create(self, ea: ea_t) -> Optional[func_t]:
    """Deprecated: Use create_at() instead."""
    return self.create_at(ea)
```

**Step 3: Fix `get_local_variable_by_name` to return None instead of raising**

```python
# Line ~1368
def get_local_variable_by_name(self, func: func_t, name: str) -> Optional[LocalVariable]:
    """
    Get a local variable by name.

    Returns:
        The LocalVariable if found, None otherwise.
    """
    # Change KeyError to return None
    for var in self.get_local_variables(func):
        if var.name == name:
            return var
    return None
```

**Step 4: Run tests**

```bash
pytest tests/ -k function -v
```

**Step 5: Commit**

```bash
git add ida_domain/functions.py
git commit -m "refactor(functions): fix types, rename create() to create_at()"
```

---

## Task 12: Fix `instructions.py` - Parameter Naming and Type Fixes

**Files:**
- Modify: `ida_domain/instructions.py`

**Step 1: Rename `start/end` to `start_ea/end_ea` in `get_between()`**

```python
# Line ~180
def get_between(self, start_ea: ea_t, end_ea: ea_t) -> Iterator[insn_t]:
```

**Step 2: Fix redundant type annotation**

```python
# Line ~240: Change
def get_operand(...) -> Optional[Operand] | None:
# To:
def get_operand(...) -> Optional[Operand]:
```

**Step 3: Run tests**

```bash
pytest tests/ -k instruction -v
```

**Step 4: Commit**

```bash
git add ida_domain/instructions.py
git commit -m "refactor(instructions): fix param names and type annotations"
```

---

## Task 13: Fix `heads.py` - Method Renames and Add `__all__`

**Files:**
- Modify: `ida_domain/heads.py`

**Step 1: Add `__all__` export**

```python
# After imports
__all__ = ['Heads']
```

**Step 2: Rename `size()` to `get_size()`**

```python
# Line ~154
def get_size(self, ea: ea_t) -> int:
    """Get the size of the item at the specified address."""
    # ... existing implementation

@deprecated("Use get_size() instead")
def size(self, ea: ea_t) -> int:
    return self.get_size(ea)
```

**Step 3: Rename `bounds()` to `get_bounds()`**

```python
# Line ~176
def get_bounds(self, ea: ea_t) -> Tuple[ea_t, ea_t]:
    """Get the bounds of the item at the specified address."""
    # ... existing implementation

@deprecated("Use get_bounds() instead")
def bounds(self, ea: ea_t) -> Tuple[ea_t, ea_t]:
    return self.get_bounds(ea)
```

**Step 4: Run tests**

```bash
pytest tests/ -k head -v
```

**Step 5: Commit**

```bash
git add ida_domain/heads.py
git commit -m "refactor(heads): add __all__, rename size/bounds to get_size/get_bounds"
```

---

## Task 14: Fix `analysis.py` - Parameter Naming and Add `__all__`

**Files:**
- Modify: `ida_domain/analysis.py`

**Step 1: Add `__all__` export**

```python
__all__ = ['Analysis']
```

**Step 2: Add `-> None` to `__init__`**

```python
def __init__(self, database: Database) -> None:
```

**Step 3: Rename `start/end` to `start_ea/end_ea` in `analyze_range()`**

```python
# Line ~160
def analyze_range(self, start_ea: ea_t, end_ea: ea_t, wait: bool = True) -> int:
```

**Step 4: Rename in `cancel_analysis()` if applicable**

```python
# Line ~396
def cancel_analysis(self, start_ea: ea_t, end_ea: ea_t) -> bool:
```

**Step 5: Run tests**

```bash
pytest tests/ -k analysis -v
```

**Step 6: Commit**

```bash
git add ida_domain/analysis.py
git commit -m "refactor(analysis): add __all__, fix param names to use start_ea/end_ea"
```

---

## Task 15: Fix `exporter.py` - Parameter Naming

**Files:**
- Modify: `ida_domain/exporter.py`

**Step 1: Rename `path` to `output_path` and `start/end` to `start_ea/end_ea` in `export()`**

```python
# Line ~107
def export(
    self,
    output_path: str,
    format: str,
    start_ea: Optional[ea_t] = None,
    end_ea: Optional[ea_t] = None
) -> bool:
```

**Step 2: Run tests**

```bash
pytest tests/ -k export -v
```

**Step 3: Commit**

```bash
git add ida_domain/exporter.py
git commit -m "refactor(exporter): rename params to output_path, start_ea/end_ea"
```

---

## Task 16: Fix `callgraph.py` - Parameter Naming

**Files:**
- Modify: `ida_domain/callgraph.py`

**Step 1: Rename `src/dst` to `src_ea/dst_ea` in `paths_between()`**

```python
# Line ~146
def paths_between(
    self,
    src_ea: ea_t,
    dst_ea: ea_t,
    max_depth: int = 10
) -> Iterator[CallPath]:
```

**Step 2: Rename `depth` to `max_depth` in `callers_of()` and `callees_of()`**

```python
def callers_of(self, ea: ea_t, max_depth: int = 1) -> Iterator[ea_t]:

def callees_of(self, ea: ea_t, max_depth: int = 1) -> Iterator[ea_t]:
```

**Step 3: Run tests**

```bash
pytest tests/ -k callgraph -v
```

**Step 4: Commit**

```bash
git add ida_domain/callgraph.py
git commit -m "refactor(callgraph): rename params for consistency"
```

---

## Task 17: Fix `names.py` - Type Annotation Style

**Files:**
- Modify: `ida_domain/names.py`

**Step 1: Standardize tuple annotations to use `Tuple`**

Replace all lowercase `tuple[...]` with `Tuple[...]`:

```python
# Ensure import
from typing_extensions import Tuple

# Fix all occurrences
def get_all(self) -> Iterator[Tuple[ea_t, str]]:
```

**Step 2: Run tests**

```bash
pytest tests/ -k name -v
```

**Step 3: Commit**

```bash
git add ida_domain/names.py
git commit -m "refactor(names): standardize Tuple type annotations"
```

---

## Task 18: Fix `flowchart.py` - Type Annotations and Add `__all__`

**Files:**
- Modify: `ida_domain/flowchart.py`

**Step 1: Add `__all__` export**

```python
__all__ = ['FlowChart', 'BasicBlock', 'FlowChartFlags']
```

**Step 2: Fix `Optional` wrapper for func parameter**

```python
# Line ~99
func: Optional[func_t] = None,
```

**Step 3: Fix tuple annotation style**

```python
# Line ~100
bounds: Optional[Tuple[ea_t, ea_t]] = None,
```

**Step 4: Fix `get_instructions()` return type**

```python
# Line ~79
def get_instructions(self) -> Iterator[insn_t]:
    """Return iterator, may be empty if no instructions."""
```

**Step 5: Run tests**

```bash
pytest tests/ -k flowchart -v
```

**Step 6: Commit**

```bash
git add ida_domain/flowchart.py
git commit -m "refactor(flowchart): add __all__, fix type annotations"
```

---

## Task 19: Fix `types.py` - Parameter Naming and Order

**Files:**
- Modify: `ida_domain/types.py`

**Step 1: Fix `apply_at()` parameter name and order**

```python
# Line ~1142
def apply_at(
    self,
    ea: ea_t,
    type_info: tinfo_t,
    flags: TypeApplyFlags = TypeApplyFlags.DEFINITE
) -> bool:
```

Note: Changed default from GUESSED to DEFINITE to match `apply_by_name()`.

**Step 2: Fix `Optional` wrapper in `get_by_name()`**

```python
# Line ~1105
def get_by_name(self, name: str, library: Optional[til_t] = None) -> Optional[tinfo_t]:
```

**Step 3: Fix docstring typos**

- Line ~998: Change "imported type" to "exported type" in `export_type()`
- Line ~1024: Change "exporting" to "copying" in `copy_type()`

**Step 4: Run tests**

```bash
pytest tests/ -k type -v
```

**Step 5: Commit**

```bash
git add ida_domain/types.py
git commit -m "refactor(types): fix param order in apply_at(), fix docstrings"
```

---

## Task 20: Fix `problems.py` - Convert `count` Property to Method

**Files:**
- Modify: `ida_domain/problems.py`

**Step 1: Convert property to method**

```python
# Line ~126: Change from property to method
def count(self) -> int:
    """
    Get the total count of problems.

    Returns:
        The number of problems.
    """
    return sum(1 for _ in self.get_all())
```

**Step 2: Update `__len__` to call method**

```python
def __len__(self) -> int:
    return self.count()
```

**Step 3: Run tests**

```bash
pytest tests/ -k problem -v
```

**Step 4: Commit**

```bash
git add ida_domain/problems.py
git commit -m "refactor(problems): convert count property to method"
```

---

## Task 21: Fix `stack_frames.py` - Error Handling Consistency

**Files:**
- Modify: `ida_domain/stack_frames.py`

**Step 1: Fix `delete_variable()` to raise LookupError**

```python
# Line ~630
def delete_variable(self, func_ea: ea_t, offset: int) -> bool:
    """
    Delete a stack variable.

    Args:
        func_ea: Function address.
        offset: Variable offset.

    Returns:
        True if deleted successfully.

    Raises:
        LookupError: If no variable exists at the offset.
    """
    frame = self.get_at(func_ea)
    if frame is None:
        raise LookupError(f"No stack frame for function at {func_ea:#x}")

    # Check if variable exists before deleting
    if not any(v.offset == offset for v in frame.variables):
        raise LookupError(f"No variable at offset {offset}")

    # ... existing delete logic
    return True
```

**Step 2: Run tests**

```bash
pytest tests/ -k stack_frame -v
```

**Step 3: Commit**

```bash
git add ida_domain/stack_frames.py
git commit -m "refactor(stack_frames): raise LookupError in delete_variable() for consistency"
```

---

## Task 22: Fix `operands.py` - Attribute Naming

**Files:**
- Modify: `ida_domain/operands.py`

**Step 1: Rename `m_database` to `_database`**

```python
# Line ~95
self._database = database
```

Update all internal references from `self.m_database` to `self._database`.

**Step 2: Run tests**

```bash
pytest tests/ -k operand -v
```

**Step 3: Commit**

```bash
git add ida_domain/operands.py
git commit -m "refactor(operands): rename m_database to _database"
```

---

## Task 23: Fix `_bytes.py` - Return Type Consistency

**Files:**
- Modify: `ida_domain/_bytes.py`

**Step 1: Fix `set_byte_at()` to return None**

```python
# Line ~315
def set_byte_at(self, ea: ea_t, value: int) -> None:
    """Set byte value at address."""
    if not self.database.is_valid_ea(ea):
        raise InvalidEAError(ea)
    ida_bytes.patch_byte(ea, value)
```

**Step 2: Fix `patch_bytes_at()` to return bool**

```python
# Line ~494
def patch_bytes_at(self, ea: ea_t, data: bytes) -> bool:
    """Patch bytes at address. Returns True on success."""
    if not self.database.is_valid_ea(ea):
        raise InvalidEAError(ea)
    return cast(bool, ida_bytes.patch_bytes(ea, data))
```

**Step 3: Run tests**

```bash
pytest tests/ -k bytes -v
```

**Step 4: Commit**

```bash
git add ida_domain/_bytes.py
git commit -m "refactor(bytes): fix return types for set_byte_at/patch_bytes_at"
```

---

## Task 24: Fix `hooks.py` - Minor Fixes

**Files:**
- Modify: `ida_domain/hooks.py`

**Step 1: Fix `ev_decorate_name` to delegate to parent**

```python
# Line ~2371
def ev_decorate_name(
    self,
    name: str,
    mangle: bool,
    cc: int,
    optional_type: 'tinfo_t',
) -> 'PyObject *':
    """..."""
    return IDP_Hooks.ev_decorate_name(self, name, mangle, cc, optional_type)
```

**Step 2: Fix typo in `stkpnts` type annotation**

```python
# Line ~4193
def stkpnts(self, mba: 'mba_t', *sps: 'stkpnts_t *') -> int:
```

**Step 3: Run tests**

```bash
pytest tests/ -k hook -v
```

**Step 4: Commit**

```bash
git add ida_domain/hooks.py
git commit -m "fix(hooks): fix ev_decorate_name delegation and stkpnts typo"
```

---

## Task 25: Add Missing `__all__` Exports

**Files:**
- Modify: `ida_domain/database.py`

**Step 1: Add `__all__` to database.py**

```python
__all__ = [
    'Database',
    'DatabaseMetadata',
    'CompilerInformation',
    'ExecutionMode',
]
```

**Step 2: Verify all modules have `__all__`**

Check that all public modules export their public API.

**Step 3: Commit**

```bash
git add ida_domain/database.py
git commit -m "refactor(database): add __all__ export list"
```

---

## Task 26: Final Verification

**Step 1: Run full test suite**

```bash
pytest tests/ -v
```

**Step 2: Run type checker if available**

```bash
mypy ida_domain/ --ignore-missing-imports
```

**Step 3: Create summary commit**

```bash
git add -A
git commit -m "docs: complete API consistency refactoring

Summary of changes:
- Standardized delete_at() for address-based deletion
- Standardized get_by_index() for index-based lookup
- Renamed find_by_name() to get_by_name()
- Fixed parameter naming to use ea, start_ea, end_ea
- Fixed type annotations to use ea_t, Optional, Tuple, List
- Added __all__ exports to all modules
- Added deprecation aliases for backwards compatibility
"
```

---

## Backwards Compatibility Notes

All renamed methods have deprecation aliases that forward to the new methods. This ensures existing code continues to work while emitting deprecation warnings.

To update client code:
1. Run with `-W default::DeprecationWarning` to see warnings
2. Update calls to use new method names
3. Remove deprecated usage before next major version
