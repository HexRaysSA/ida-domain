# IDA-Domain API Conventions

This document defines the public API conventions for the ida-domain SDK. All contributors must follow these conventions to maintain consistency across the codebase.

---

## Table of Contents

1. [Naming Conventions](#naming-conventions)
2. [Parameter Conventions](#parameter-conventions)
3. [Type Annotation Conventions](#type-annotation-conventions)
4. [Return Shape Conventions](#return-shape-conventions)
5. [Error Signaling Conventions](#error-signaling-conventions)
6. [Module Structure Conventions](#module-structure-conventions)
7. [Deprecation Policy](#deprecation-policy)

---

## Naming Conventions

### Method Verbs

| Verb | Usage | Example |
|------|-------|---------|
| `get_*` | Retrieve data without side effects | `get_at()`, `get_by_name()` |
| `set_*` | Modify existing data | `set_at()`, `set_name()` |
| `create_*` | Create new entities | `create_at()` |
| `delete_*` | Remove entities | `delete_at()` |
| `is_*` / `has_*` / `does_*` / `can_*` | Boolean predicates | `is_valid()`, `has_name()` |
| `apply_*` | Apply configuration or types | `apply_at()` |
| `format_*` | Format data for display | `format_type()` |
| `parse_*` | Parse input data | `parse_declaration()` |

### Address-Based Operations

All methods operating on a single address **must** use the `*_at` suffix:

```python
# Correct
def get_at(self, ea: ea_t) -> Optional[T]: ...
def set_at(self, ea: ea_t, value: T) -> None: ...
def create_at(self, ea: ea_t) -> Optional[T]: ...
def delete_at(self, ea: ea_t) -> bool: ...
def exists_at(self, ea: ea_t) -> bool: ...

# Incorrect
def get(self, ea: ea_t) -> Optional[T]: ...  # Missing _at suffix
def delete(self, ea: ea_t) -> bool: ...      # Missing _at suffix
```

### Lookup-by-Attribute Operations

Methods that look up entities by an attribute use the `get_by_*` pattern:

```python
def get_by_name(self, name: str) -> Optional[T]: ...
def get_by_index(self, index: int) -> Optional[T]: ...
def get_by_ordinal(self, ordinal: int) -> Optional[T]: ...
```

### Range Operations

Methods operating on address ranges use the `*_between` suffix:

```python
def get_between(self, start_ea: ea_t, end_ea: ea_t) -> Iterator[T]: ...
def delete_between(self, start_ea: ea_t, end_ea: ea_t) -> int: ...
```

### Collection Iteration

| Method | Returns | Usage |
|--------|---------|-------|
| `get_all()` | `Iterator[T]` | Lazy iteration over all items |
| `get_page(offset, limit)` | `List[T]` | Paginated access |
| `get_chunked(chunk_size)` | `Iterator[List[T]]` | Chunked iteration |

### Deprecated Verb: `remove`

The verb `remove` is **deprecated**. Use `delete` instead:

```python
# Correct
def delete_at(self, ea: ea_t) -> bool: ...

# Deprecated (keep as alias for backwards compatibility)
@deprecated("Use delete_at() instead")
def remove_at(self, ea: ea_t) -> bool:
    return self.delete_at(ea)
```

---

## Parameter Conventions

### Address Parameters

| Parameter | Usage |
|-----------|-------|
| `ea` | Single effective address |
| `start_ea` | Start of an address range (inclusive) |
| `end_ea` | End of an address range (exclusive) |
| `func_ea` | Address of a function (when disambiguating from generic addresses) |
| `src_ea` / `dst_ea` | Source and destination addresses |
| `from_ea` / `to_ea` | Alternative for directional operations |

**Never use:**
- `address` (use `ea`)
- `start` / `end` (use `start_ea` / `end_ea`)
- `addr` (use `ea`)

```python
# Correct
def get_between(self, start_ea: ea_t, end_ea: ea_t) -> Iterator[T]: ...
def get_at(self, ea: ea_t) -> Optional[T]: ...

# Incorrect
def get_between(self, start: ea_t, end: ea_t) -> Iterator[T]: ...
def get_at(self, address: ea_t) -> Optional[T]: ...
```

### Parameter Order

1. **Address first**: The primary address parameter comes first
2. **Value/object second**: The data being set or applied
3. **Flags/options last**: Optional modifiers with defaults

```python
# Correct parameter order
def apply_at(self, ea: ea_t, type_info: tinfo_t, flags: Flags = Flags.DEFAULT) -> bool: ...
def set_at(self, ea: ea_t, value: str, repeatable: bool = False) -> None: ...

# Incorrect parameter order
def apply_at(self, type_info: tinfo_t, ea: ea_t, flags: Flags = Flags.DEFAULT) -> bool: ...
```

### Count Access

Entity counts are accessed via a **method**, not a property:

```python
# Correct
def count(self) -> int:
    """Return the total count of items."""
    return sum(1 for _ in self.get_all())

def __len__(self) -> int:
    return self.count()

# Incorrect
@property
def count(self) -> int: ...
```

---

## Type Annotation Conventions

### Import Source

Always import type hints from `typing_extensions`:

```python
from typing_extensions import (
    TYPE_CHECKING,
    Iterator,
    List,
    Optional,
    Tuple,
    cast,
)
```

### Generic Types

Use **uppercase** generic types (backwards compatible with Python 3.8):

```python
# Correct
def get_all(self) -> Iterator[T]: ...
def get_items(self) -> List[T]: ...
def get_range(self) -> Tuple[ea_t, ea_t]: ...
def get_at(self) -> Optional[T]: ...

# Incorrect (Python 3.9+ only)
def get_all(self) -> iterator[T]: ...
def get_items(self) -> list[T]: ...
def get_range(self) -> tuple[ea_t, ea_t]: ...
```

### Address Type

Always use `ea_t` for addresses, never `int`:

```python
from ida_idaapi import ea_t

# Correct
def get_at(self, ea: ea_t) -> Optional[T]: ...

# Incorrect
def get_at(self, ea: int) -> Optional[T]: ...
```

### Optional Parameters

Always wrap nullable parameters with `Optional`:

```python
# Correct
def get_by_name(self, name: str, library: Optional[til_t] = None) -> Optional[T]: ...

# Incorrect
def get_by_name(self, name: str, library: til_t = None) -> Optional[T]: ...
```

### Union Syntax

Use `Optional[T]` instead of `T | None`:

```python
# Correct
def get_at(self, ea: ea_t) -> Optional[str]: ...

# Incorrect
def get_at(self, ea: ea_t) -> str | None: ...
```

---

## Return Shape Conventions

### Single Item Lookup

Methods that retrieve a single item return `Optional[T]`:

```python
def get_at(self, ea: ea_t) -> Optional[T]:
    """Return the item at the address, or None if not found."""
    ...

def get_by_name(self, name: str) -> Optional[T]:
    """Return the item with the given name, or None if not found."""
    ...

def get_by_index(self, index: int) -> Optional[T]:
    """Return the item at the index, or None if out of range."""
    ...
```

### Collection Iteration

Methods that return multiple items use `Iterator[T]`:

```python
def get_all(self) -> Iterator[T]:
    """Iterate over all items. May return empty iterator."""
    ...

def get_between(self, start_ea: ea_t, end_ea: ea_t) -> Iterator[T]:
    """Iterate over items in range. May return empty iterator."""
    ...
```

**Never** return `Optional[Iterator[T]]`. An empty iterator represents "no results":

```python
# Correct
def get_all(self) -> Iterator[T]: ...

# Incorrect
def get_all(self) -> Optional[Iterator[T]]: ...
```

### Mutation Operations

Methods that modify data return `bool` for success/failure:

```python
def delete_at(self, ea: ea_t) -> bool:
    """Delete the item. Returns True if deleted, False otherwise."""
    ...

def create_at(self, ea: ea_t) -> bool:
    """Create an item. Returns True if created, False otherwise."""
    ...
```

Or return `None` if the operation cannot fail:

```python
def set_at(self, ea: ea_t, value: str) -> None:
    """Set the value. Always succeeds if address is valid."""
    ...
```

### Deletion with Count

Bulk delete operations return the count of deleted items:

```python
def delete_between(self, start_ea: ea_t, end_ea: ea_t) -> int:
    """Delete all items in range. Returns count of deleted items."""
    ...
```

---

## Error Signaling Conventions

### Invalid Address

Raise `InvalidEAError` for invalid effective addresses:

```python
from ida_domain.base import InvalidEAError

def get_at(self, ea: ea_t) -> Optional[T]:
    if not self.database.is_valid_ea(ea):
        raise InvalidEAError(ea)
    ...
```

### Invalid Parameter

Raise `InvalidParameterError` for invalid parameter values:

```python
from ida_domain.base import InvalidParameterError

def get_between(self, start_ea: ea_t, end_ea: ea_t) -> Iterator[T]:
    if start_ea >= end_ea:
        raise InvalidParameterError("start_ea", start_ea, "must be less than end_ea")
    ...
```

### Not Found

Return `None` or an empty iterator for "not found" cases. **Never raise** for not found:

```python
# Correct: Return None
def get_at(self, ea: ea_t) -> Optional[T]:
    item = self._lookup(ea)
    if item is None:
        return None  # Not found - return None
    return item

# Correct: Return empty iterator
def get_between(self, start_ea: ea_t, end_ea: ea_t) -> Iterator[T]:
    for item in self._items:
        if start_ea <= item.ea < end_ea:
            yield item
    # Empty iteration if nothing found

# Incorrect: Raising for not found
def get_at(self, ea: ea_t) -> T:
    item = self._lookup(ea)
    if item is None:
        raise KeyError(f"No item at {ea:#x}")  # Don't do this
    return item
```

### Mutation Pre-conditions

Raise `LookupError` when mutating a non-existent entity:

```python
def set_variable_type(self, func_ea: ea_t, offset: int, type_info: tinfo_t) -> bool:
    var = self._get_variable(func_ea, offset)
    if var is None:
        raise LookupError(f"No variable at offset {offset}")
    ...
```

---

## Module Structure Conventions

### `__all__` Export

Every module **must** define `__all__` listing all public exports:

```python
__all__ = [
    'ClassName',
    'EnumName',
    'DataClassName',
    'function_name',
]
```

### Class Structure

Entity classes follow this structure:

```python
__all__ = ['EntityName']

class EntityName(DatabaseEntity):
    """Entity docstring with description."""

    def __init__(self, database: Database) -> None:
        """Initialize the entity."""
        super().__init__(database)

    def __iter__(self) -> Iterator[T]:
        """Iterate over all items."""
        return self.get_all()

    def __len__(self) -> int:
        """Return the count of items."""
        return self.count()

    def count(self) -> int:
        """Return the count of items."""
        ...

    def get_all(self) -> Iterator[T]:
        """Iterate over all items."""
        ...

    def get_at(self, ea: ea_t) -> Optional[T]:
        """Get item at address."""
        ...
```

### Iteration Protocols

Implement `__iter__` and `__len__` only for entities that represent countable collections:

- **Yes**: `Functions`, `Segments`, `Names`, `Strings`, `Problems`
- **No**: `Analysis`, `Exporter`, `Decompiler`, `SignatureFiles`

---

## Deprecation Policy

### Adding Deprecation Aliases

When renaming a method, add a deprecated alias:

```python
from warnings import warn

def deprecated(message: str):
    """Decorator to mark a function as deprecated."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            warn(message, DeprecationWarning, stacklevel=2)
            return func(*args, **kwargs)
        return wrapper
    return decorator

# New method
def delete_at(self, ea: ea_t) -> bool:
    """Delete the item at the address."""
    ...

# Deprecated alias
@deprecated("Use delete_at() instead")
def delete(self, ea: ea_t) -> bool:
    """Deprecated: Use delete_at() instead."""
    return self.delete_at(ea)
```

### Deprecation Timeline

1. **Minor release**: Add deprecation warning, document in changelog
2. **Next minor release**: Update all examples and documentation
3. **Major release**: Remove deprecated aliases

---

## Quick Reference

| Pattern | Correct | Incorrect |
|---------|---------|-----------|
| Address param | `ea: ea_t` | `address: int` |
| Range params | `start_ea, end_ea` | `start, end` |
| Address lookup | `get_at(ea)` | `get(ea)` |
| Index lookup | `get_by_index(i)` | `get_at_index(i)` |
| Name lookup | `get_by_name(n)` | `find_by_name(n)` |
| Deletion | `delete_at(ea)` | `remove(ea)` |
| Creation | `create_at(ea)` | `create(ea)` |
| Not found | Return `None` | Raise `KeyError` |
| Count | `count()` method | `count` property |
| Optional | `Optional[T]` | `T \| None` |
| List type | `List[T]` | `list[T]` |
| Tuple type | `Tuple[T, U]` | `tuple[T, U]` |
