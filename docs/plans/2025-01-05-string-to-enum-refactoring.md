# String-to-Enum Refactoring Plan

**Date:** 2025-01-05
**Status:** Proposed
**Rationale:** Current "LLM-friendly" string-based parameters are inconsistent with API best practices. Research shows enums are actually MORE LLM-friendly because they provide constraints that improve first-call success rates.

---

## Summary of Findings

| Module | Method(s) | String Param | Valid Values | New Enum |
|--------|-----------|--------------|--------------|----------|
| analysis.py | `schedule()` | `what` | code, function, reanalysis | `AnalysisType` |
| search.py | `find_next()`, `find_all()` | `what` | undefined, defined, code, data, code_outside_function | `SearchTarget` |
| search.py | `find_next()` | `direction` | forward, backward | Use existing `SearchDirection` |
| xrefs.py | `get_refs_to()`, `get_refs_from()`, `has_refs_to()`, `has_refs_from()` | `kind` | all, code, data, calls, jumps, reads, writes | `XrefKind` |
| exporter.py | `export()` | `format` | asm, lst, map, idc, exe, diff | Use existing `ExportFormat` |
| types.py | `get()` | `by` | name, ordinal, address | `TypeLookupMode` |
| types.py | `apply()` | `by` | name, decl, tinfo | `TypeApplyMode` |

**Total:** 11 methods across 5 modules need refactoring.

---

## Phase 1: Create New Enum Definitions

### 1.1 analysis.py - Add `AnalysisType`

```python
class AnalysisType(str, Enum):
    """Type of analysis to schedule."""

    CODE = "code"
    """Schedule instruction creation (CODE queue)"""

    FUNCTION = "function"
    """Schedule function creation (PROC queue)"""

    REANALYSIS = "reanalysis"
    """Schedule reanalysis (USED queue)"""
```

**Location:** After imports, before `Analysis` class (around line 30).

### 1.2 search.py - Add `SearchTarget`

```python
class SearchTarget(str, Enum):
    """Type of address to find in search operations."""

    UNDEFINED = "undefined"
    """Find undefined/unexplored bytes"""

    DEFINED = "defined"
    """Find defined items (instructions or data)"""

    CODE = "code"
    """Find code addresses"""

    DATA = "data"
    """Find data addresses"""

    CODE_OUTSIDE_FUNCTION = "code_outside_function"
    """Find orphaned code (not in functions)"""
```

**Location:** After `SearchDirection` enum (around line 33).

**Note:** `SearchDirection` already exists but needs string aliases:
```python
class SearchDirection(IntEnum):
    """Direction for search operations."""

    UP = 0
    DOWN = 1

    # String aliases for LLM compatibility
    BACKWARD = 0  # Alias for UP
    FORWARD = 1   # Alias for DOWN
```

### 1.3 xrefs.py - Add `XrefKind`

```python
class XrefKind(str, Enum):
    """Filter kind for cross-reference queries."""

    ALL = "all"
    """All cross-references"""

    CODE = "code"
    """Code cross-references only"""

    DATA = "data"
    """Data cross-references only"""

    CALLS = "calls"
    """Call cross-references only"""

    JUMPS = "jumps"
    """Jump cross-references only"""

    READS = "reads"
    """Read cross-references only"""

    WRITES = "writes"
    """Write cross-references only"""
```

**Location:** After `XrefType` enum (around line 130).

### 1.4 types.py - Add `TypeLookupMode` and `TypeApplyMode`

```python
class TypeLookupMode(str, Enum):
    """Mode for type lookup operations."""

    NAME = "name"
    """Look up type by name"""

    ORDINAL = "ordinal"
    """Look up type by ordinal number"""

    ADDRESS = "address"
    """Get type at an address"""


class TypeApplyMode(str, Enum):
    """Mode for type application operations."""

    NAME = "name"
    """Apply a named type from library"""

    DECL = "decl"
    """Parse and apply a C declaration"""

    TINFO = "tinfo"
    """Apply a tinfo_t object directly"""
```

**Location:** After existing enum definitions (around line 320).

---

## Phase 2: Update Method Signatures

### Design Pattern: Accept Both Enum and String

Use `Union[EnumType, str]` with internal normalization to maintain backward compatibility:

```python
from typing import Union

def schedule(
    self,
    ea: ea_t,
    what: Union[AnalysisType, str] = AnalysisType.REANALYSIS
) -> None:
    """..."""
    # Normalize to enum
    if isinstance(what, str):
        try:
            what = AnalysisType(what.lower())
        except ValueError:
            raise InvalidParameterError(
                'what', what,
                f'must be one of: {", ".join(e.value for e in AnalysisType)}'
            )

    # Now use enum directly
    if what == AnalysisType.CODE:
        self.schedule_code_analysis(ea)
    elif what == AnalysisType.FUNCTION:
        self.schedule_function_analysis(ea)
    elif what == AnalysisType.REANALYSIS:
        self.schedule_reanalysis(ea)
```

### Methods to Update

| Module | Method | Old Signature | New Signature |
|--------|--------|---------------|---------------|
| analysis.py | `schedule` | `what: str = "reanalysis"` | `what: Union[AnalysisType, str] = AnalysisType.REANALYSIS` |
| search.py | `find_next` | `what: str, direction: str = "forward"` | `what: Union[SearchTarget, str], direction: Union[SearchDirection, str] = SearchDirection.FORWARD` |
| search.py | `find_all` | `what: str` | `what: Union[SearchTarget, str]` |
| xrefs.py | `get_refs_to` | `kind: str = "all"` | `kind: Union[XrefKind, str] = XrefKind.ALL` |
| xrefs.py | `get_refs_from` | `kind: str = "all"` | `kind: Union[XrefKind, str] = XrefKind.ALL` |
| xrefs.py | `has_refs_to` | `kind: str = "all"` | `kind: Union[XrefKind, str] = XrefKind.ALL` |
| xrefs.py | `has_refs_from` | `kind: str = "all"` | `kind: Union[XrefKind, str] = XrefKind.ALL` |
| exporter.py | `export` | `format: str` | `format: Union[ExportFormat, str]` |
| types.py | `get` | `by: str = 'name'` | `by: Union[TypeLookupMode, str] = TypeLookupMode.NAME` |
| types.py | `apply` | `by: str = 'name'` | `by: Union[TypeApplyMode, str] = TypeApplyMode.NAME` |

---

## Phase 3: Update `__all__` Exports

Each module's `__all__` list must include the new enums:

```python
# analysis.py
__all__ = ['Analysis', 'AnalysisType']

# search.py
__all__ = ['Search', 'SearchDirection', 'SearchTarget']

# xrefs.py
__all__ = ['Xrefs', 'XrefType', 'XrefKind', 'XrefInfo', 'CallerInfo']

# types.py
__all__ = [..., 'TypeLookupMode', 'TypeApplyMode']
```

---

## Phase 4: Update Tests

For each module, update tests to:
1. Test with enum values (primary)
2. Test with string values (backward compatibility)
3. Test case-insensitivity of string values

Example test pattern:
```python
def test_schedule_with_enum(self):
    """Test schedule() accepts AnalysisType enum."""
    db.analysis.schedule(ea, AnalysisType.CODE)

def test_schedule_with_string(self):
    """Test schedule() accepts string for backward compatibility."""
    db.analysis.schedule(ea, "code")

def test_schedule_case_insensitive(self):
    """Test schedule() string parameter is case-insensitive."""
    db.analysis.schedule(ea, "CODE")
    db.analysis.schedule(ea, "Code")
```

---

## Phase 5: Update Documentation

### 5.1 Update CHANGELOG.md

Add to Breaking Changes section (with deprecation notice):

```markdown
### String Parameters Converted to Enums

The following methods now accept proper enum types instead of strings.
String values are still accepted for backward compatibility but will
emit deprecation warnings in a future release.

| Method | Old | New |
|--------|-----|-----|
| `analysis.schedule(ea, what)` | `"code"` | `AnalysisType.CODE` |
| `search.find_next(ea, what, direction)` | `"code", "forward"` | `SearchTarget.CODE, SearchDirection.FORWARD` |
| ... | ... | ... |
```

### 5.2 Update Docstrings

Update each method's docstring to show enum usage as the primary example:

```python
"""
Schedule analysis at address.

Args:
    ea: Address to schedule for analysis.
    what: Type of analysis. Use AnalysisType enum:
        - AnalysisType.CODE: Create instruction
        - AnalysisType.FUNCTION: Create function
        - AnalysisType.REANALYSIS: Reanalyze address (default)

Example:
    >>> db.analysis.schedule(0x401000, AnalysisType.CODE)
    >>> db.analysis.schedule(0x401000, "code")  # Also accepted
"""
```

---

## Implementation Order

1. **analysis.py** - Simplest case, 1 method, 1 enum
2. **search.py** - 2 methods, 1 new enum + update existing
3. **types.py** - 2 methods, 2 new enums
4. **xrefs.py** - 4 methods, 1 new enum
5. **exporter.py** - 1 method, use existing enum

---

## Verification Checklist

- [ ] All new enums inherit from `str, Enum` for JSON serialization
- [ ] All new enums have docstrings
- [ ] All method signatures use `Union[EnumType, str]`
- [ ] String values remain case-insensitive
- [ ] `__all__` exports updated
- [ ] Tests pass with both enum and string values
- [ ] mypy --strict passes
- [ ] ruff check passes
- [ ] CHANGELOG.md updated

---

## Notes

### Why `str, Enum` Instead of `Enum`?

Using `class MyEnum(str, Enum)` provides:
1. JSON serialization works automatically
2. String comparison works: `AnalysisType.CODE == "code"` is True
3. Can be used in f-strings without `.value`

### Backward Compatibility

The `Union[EnumType, str]` pattern ensures:
1. Existing code using strings continues to work
2. New code can use type-safe enums
3. IDE autocomplete shows enum values
4. LLMs see constrained options in type hints
