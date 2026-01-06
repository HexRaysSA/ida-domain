# Error Handling Guide

This guide documents the error handling conventions used throughout the IDA Domain API. Following these conventions will help you write robust and predictable code.

## Return Value Conventions

The IDA Domain API follows consistent return value conventions based on method naming patterns:

### `get_*` Methods

Methods prefixed with `get_` are used to retrieve data from the database.

- Return `Optional[T]` - the item if found, or `None` if not found
- Some return `Iterator[T]` when multiple items are possible at one location
- Never raise exceptions for "not found" cases
- Raise `InvalidEAError` for invalid addresses

```python
from ida_domain import Database

db = Database()
db.open('/path/to/database.idb')

# Returns Optional[func_t] - None if no function at address
func = db.functions.get_at(0x401000)
if func is None:
    print("No function at this address")
else:
    print(f"Found function: {func.name}")

# Returns Iterator[insn_t] for instructions in a range
for insn in db.instructions.get_in_range(0x401000, 0x402000):
    print(f"Instruction at {hex(insn.ea)}")
```

### `create_*` Methods

Methods prefixed with `create_` are used to create new items in the database.

- Most return `bool` - `True` on success, `False` on failure
- Factory methods may return the created object instead
- May raise exceptions for invalid parameters

```python
# Returns bool - True if dword was created successfully
success = db.bytes.create_dword_at(0x401000)
if not success:
    print("Failed to create dword at address")

# Returns bool - True if function was created
success = db.functions.create_at(0x401000)
if success:
    print("Function created successfully")
```

### `set_*` Methods

Methods prefixed with `set_` are used to modify existing data.

- Most return `bool` - `True` on success, `False` on failure
- Some return `None` (rely on exceptions for failure)

```python
# Returns bool - True if name was set successfully
success = db.names.set_at(0x401000, "my_function")
if not success:
    print("Failed to set name")

# Returns bool - True if comment was set
success = db.comments.set_at(0x401000, "This is a comment")
```

### `has_*` / `is_*` Methods

Predicate methods that check conditions.

- Return `bool` - `True` if condition is met, `False` otherwise
- Raise `InvalidEAError` for invalid addresses

```python
# Check if address has a function
if db.functions.has_at(0x401000):
    print("Address is inside a function")

# Check if address is code
if db.bytes.is_code(0x401000):
    print("Address contains code")
```

### `count_*` Methods

Methods that count items.

- Return `int` - the count (0 if none found)
- Raise `InvalidEAError` for invalid addresses

```python
# Count cross-references to an address
xref_count = db.xrefs.count_refs_to(0x401000)
print(f"Found {xref_count} references to this address")
```

### `delete_*` / `remove_*` Methods

Methods for removing items from the database.

- Return `bool` - `True` on success, `False` on failure
- Some return `int` indicating number of items deleted
- Some return `None` and always succeed

```python
# Returns bool - True if xref was deleted
success = db.xrefs.delete_xref(0x401000, 0x402000)
if not success:
    print("Failed to delete cross-reference")

# Returns bool - True if name was deleted
success = db.names.delete_local(0x401000)

# Returns int - number of problems removed
count = db.problems.remove_at(0x401000)
print(f"Removed {count} problems")
```

## Exceptions

The IDA Domain API defines several exception types for error conditions that cannot be handled through return values.

### Core Exceptions

These exceptions are defined in `ida_domain.base`:

#### `InvalidEAError`

Raised when an operation is attempted on an invalid effective address (EA). An EA is invalid if it does not belong to any segment in the database.

```python
from ida_domain.base import InvalidEAError

try:
    # Attempting to get data at an invalid address
    name = db.names.get_at(0xDEADBEEF)
except InvalidEAError as e:
    print(f"Invalid address: {e}")
```

**When raised:**

- Address is outside all segments
- Address is not mapped in the database

#### `InvalidParameterError`

Raised when a function receives invalid arguments that cannot be processed.

```python
from ida_domain.base import InvalidParameterError

try:
    # Example: passing invalid parameters
    db.segments.create(start=0x1000, end=0x500)  # end < start is invalid
except InvalidParameterError as e:
    print(f"Invalid parameter: {e}")
```

**When raised:**

- Parameter values are out of valid range
- Parameters are mutually exclusive or contradictory
- Required parameter format is incorrect

#### `DatabaseNotLoadedError`

Raised when an operation is attempted on a database that is not open or has been closed.

```python
from ida_domain.base import DatabaseNotLoadedError

db = Database()
# Forgot to call db.open()

try:
    functions = list(db.functions.get_all())
except DatabaseNotLoadedError as e:
    print(f"Database not loaded: {e}")
```

**When raised:**

- Database was never opened
- Database was closed and operation attempted
- Database handle is invalid

### Module-Specific Exceptions

#### `NoValueError` (bytes module)

Raised when a read operation is attempted on an uninitialized address. This occurs when the address exists in a segment but has no defined value.

```python
from ida_domain.bytes import NoValueError

try:
    value = db.bytes.get_byte_at(0x401000)
except NoValueError as e:
    print(f"Address has no initialized value: {e}")
```

**When raised:**

- Address is in BSS section (uninitialized data)
- Address value was explicitly deleted
- Memory was never initialized

#### `UnsupportedValueError` (bytes module)

Raised when a read operation is attempted on a value which has an unsupported format or encoding.

```python
from ida_domain.bytes import UnsupportedValueError

try:
    value = db.bytes.get_dword_at(0x401000)
except UnsupportedValueError as e:
    print(f"Unsupported value format: {e}")
```

**When raised:**

- Value encoding is not supported
- Data format is corrupted or unrecognized

## Best Practices

### Check for None Instead of Catching Exceptions

For `get_*` methods, prefer checking the return value over exception handling:

```python
# Preferred: Check return value
func = db.functions.get_at(ea)
if func is not None:
    process_function(func)

# Avoid: Exception handling for expected cases
try:
    func = db.functions.get_at(ea)
    process_function(func)
except Exception:
    pass  # This pattern is discouraged
```

### Validate Addresses Early

When working with user-provided addresses, validate them before performing operations:

```python
def analyze_function(db: Database, ea: int) -> None:
    """Analyze a function at the given address."""
    # Validate address belongs to a segment
    segment = db.segments.get_at(ea)
    if segment is None:
        print(f"Address {hex(ea)} is not in any segment")
        return

    # Now safe to perform operations
    func = db.functions.get_at(ea)
    if func is None:
        print(f"No function at {hex(ea)}")
        return

    # Process the function
    for insn in db.instructions.get_in_range(func.start_ea, func.end_ea):
        process_instruction(insn)
```

### Use Iterators for Large Results

When dealing with potentially large result sets, prefer iterators over collecting all results into a list:

```python
# Preferred: Use iterator directly
for func in db.functions.get_all():
    if should_process(func):
        process_function(func)

# Avoid for large databases: Collecting all results first
all_functions = list(db.functions.get_all())  # May use lots of memory
for func in all_functions:
    process_function(func)
```

### Handle Exceptions at Appropriate Levels

Catch exceptions at a level where you can meaningfully handle them:

```python
from ida_domain.base import InvalidEAError, DatabaseNotLoadedError

def process_addresses(db: Database, addresses: list[int]) -> dict[int, str]:
    """Process a list of addresses and return results."""
    results = {}

    for ea in addresses:
        try:
            name = db.names.get_at(ea)
            results[ea] = name if name else "(unnamed)"
        except InvalidEAError:
            results[ea] = "(invalid address)"

    return results

# Higher level: Handle database errors
try:
    results = process_addresses(db, [0x401000, 0x402000])
except DatabaseNotLoadedError:
    print("Please open a database first")
```

### Combine Return Value Checks with Exception Handling

For robust code, combine both patterns:

```python
from ida_domain.base import InvalidEAError

def safe_get_function_name(db: Database, ea: int) -> str:
    """Safely get a function name, handling all error cases."""
    try:
        func = db.functions.get_at(ea)
        if func is None:
            return "(no function)"
        return func.name or "(unnamed)"
    except InvalidEAError:
        return "(invalid address)"
```

## Summary

| Method Pattern | Return Type | "Not Found" Behavior | Invalid Address |
|---------------|-------------|---------------------|-----------------|
| `get_*` | `Optional[T]` or `Iterator[T]` | Returns `None` or empty iterator | Raises `InvalidEAError` |
| `create_*` | `bool` or object | Returns `False` | May raise exception |
| `set_*` | `bool` or `None` | Returns `False` | May raise exception |
| `has_*` / `is_*` | `bool` | Returns `False` | Raises `InvalidEAError` |
| `count_*` | `int` | Returns `0` | Raises `InvalidEAError` |
| `delete_*` / `remove_*` | `bool`, `int`, or `None` | Returns `False` or `0` | May raise exception |

By following these conventions, you can write predictable code that gracefully handles both expected conditions (like missing data) and exceptional conditions (like invalid addresses).
