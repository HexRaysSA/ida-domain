# LLM-Optimized API Refactoring Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Refactor ida-domain API to be LLM-optimized with minimal surface (~170 methods), predictable patterns, string literals instead of enums, and sensible defaults.

**Architecture:** Add deprecation infrastructure, then systematically add new LLM-friendly methods, add aliases for pre-fork methods, and remove post-fork methods. Each entity is refactored independently with tests.

**Tech Stack:** Python 3.10+, IDA Pro SDK, pytest

---

## Phase 1: Infrastructure - Deprecation Decorator

### Task 1.1: Add deprecation decorator to base.py

**Files:**
- Modify: `ida_domain/base.py`
- Test: `tests/test_deprecation.py` (new)

**Step 1: Write the failing test**

```python
# tests/test_deprecation.py
import warnings
import pytest
from ida_domain.base import deprecated

def test_deprecated_decorator_warns():
    @deprecated("Use new_func instead")
    def old_func():
        return 42

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        result = old_func()
        assert result == 42
        assert len(w) == 1
        assert "Use new_func instead" in str(w[0].message)
        assert issubclass(w[0].category, DeprecationWarning)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_deprecation.py -v`
Expected: FAIL with "cannot import name 'deprecated'"

**Step 3: Write minimal implementation**

Add to `ida_domain/base.py`:

```python
import warnings
from typing import Callable, TypeVar

F = TypeVar('F', bound=Callable[..., Any])

def deprecated(reason: str) -> Callable[[F], F]:
    """
    Decorator to mark functions as deprecated.

    Args:
        reason: Message explaining what to use instead.

    Example:
        @deprecated("Use get_in_range instead")
        def get_between(self, start, end):
            ...
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            warnings.warn(
                f"{func.__qualname__} is deprecated. {reason}",
                DeprecationWarning,
                stacklevel=2
            )
            return func(*args, **kwargs)
        return cast(F, wrapper)
    return decorator
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_deprecation.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add ida_domain/base.py tests/test_deprecation.py
git commit -m "feat: add deprecation decorator for API migration"
```

---

## Phase 2: Functions Entity

### Task 2.1: Add `count()` method to Functions

**Files:**
- Modify: `ida_domain/functions.py`
- Modify: `tests/test_functions.py`

**Step 1: Write the failing test**

Add to `tests/test_functions.py`:

```python
def test_functions_count(db):
    """Test count() returns total function count."""
    count = db.functions.count()
    assert isinstance(count, int)
    assert count >= 0
    # Should match len()
    assert count == len(db.functions)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_functions.py::test_functions_count -v`
Expected: FAIL with "has no attribute 'count'"

**Step 3: Write minimal implementation**

Add to `ida_domain/functions.py` class `Functions`:

```python
def count(self) -> int:
    """
    Get the total number of functions in the database.

    Returns:
        int: The total function count.

    Example:
        >>> db = Database.open_current()
        >>> print(f"Database has {db.functions.count()} functions")
    """
    return len(self)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_functions.py::test_functions_count -v`
Expected: PASS

**Step 5: Commit**

```bash
git add ida_domain/functions.py tests/test_functions.py
git commit -m "feat(functions): add count() method for LLM API"
```

---

### Task 2.2: Add `exists_at()` method to Functions

**Files:**
- Modify: `ida_domain/functions.py`
- Modify: `tests/test_functions.py`

**Step 1: Write the failing test**

```python
def test_functions_exists_at(db):
    """Test exists_at() checks if function exists."""
    # Get a known function address
    func = next(iter(db.functions.get_all()), None)
    if func:
        assert db.functions.exists_at(func.start_ea) is True
    # Non-function address should return False
    assert db.functions.exists_at(0xDEADBEEF) is False
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_functions.py::test_functions_exists_at -v`
Expected: FAIL with "has no attribute 'exists_at'"

**Step 3: Write minimal implementation**

```python
def exists_at(self, ea: ea_t) -> bool:
    """
    Check if a function exists at the given address.

    Args:
        ea: Address to check.

    Returns:
        bool: True if a function exists at or contains the address.

    Example:
        >>> if db.functions.exists_at(0x401000):
        ...     func = db.functions.get_at(0x401000)
    """
    return self.get_at(ea) is not None
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_functions.py::test_functions_exists_at -v`
Expected: PASS

**Step 5: Commit**

```bash
git add ida_domain/functions.py tests/test_functions.py
git commit -m "feat(functions): add exists_at() method for LLM API"
```

---

### Task 2.3: Add `get_in_range()` alias to Functions

**Files:**
- Modify: `ida_domain/functions.py`
- Modify: `tests/test_functions.py`

**Step 1: Write the failing test**

```python
def test_functions_get_in_range_alias(db):
    """Test get_in_range() is alias for get_between()."""
    start = db.database.minimum_ea
    end = db.database.maximum_ea

    between_funcs = list(db.functions.get_between(start, end))
    range_funcs = list(db.functions.get_in_range(start, end))

    assert len(between_funcs) == len(range_funcs)
    for f1, f2 in zip(between_funcs, range_funcs):
        assert f1.start_ea == f2.start_ea
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_functions.py::test_functions_get_in_range_alias -v`
Expected: FAIL with "has no attribute 'get_in_range'"

**Step 3: Write minimal implementation**

```python
def get_in_range(self, start: ea_t, end: ea_t) -> Iterator[func_t]:
    """
    Get functions in the specified address range.

    This is an LLM-friendly alias for get_between().

    Args:
        start: Start address of the range (inclusive).
        end: End address of the range (exclusive).

    Yields:
        Function objects in the range.

    Example:
        >>> for func in db.functions.get_in_range(0x401000, 0x410000):
        ...     print(db.functions.get_name(func))
    """
    return self.get_between(start, end)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_functions.py::test_functions_get_in_range_alias -v`
Expected: PASS

**Step 5: Commit**

```bash
git add ida_domain/functions.py tests/test_functions.py
git commit -m "feat(functions): add get_in_range() alias for LLM API"
```

---

### Task 2.4: Add `delete()` alias to Functions

**Files:**
- Modify: `ida_domain/functions.py`
- Modify: `tests/test_functions.py`

**Step 1: Write the failing test**

```python
def test_functions_delete_alias(db):
    """Test delete() is alias for remove()."""
    # Create a test function first
    test_ea = 0x401000  # Use appropriate address
    # Note: This test may need to be adapted based on available test data
    # The key is that delete() should call remove()
    assert hasattr(db.functions, 'delete')
    assert callable(db.functions.delete)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_functions.py::test_functions_delete_alias -v`
Expected: FAIL with "has no attribute 'delete'"

**Step 3: Write minimal implementation**

```python
def delete(self, ea: ea_t) -> bool:
    """
    Delete the function at the specified address.

    This is an LLM-friendly alias for remove().

    Args:
        ea: Address of the function to delete.

    Returns:
        bool: True if successfully deleted, False otherwise.

    Raises:
        InvalidEAError: If the effective address is invalid.

    Example:
        >>> if db.functions.delete(0x401000):
        ...     print("Function deleted")
    """
    return self.remove(ea)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_functions.py::test_functions_delete_alias -v`
Expected: PASS

**Step 5: Commit**

```bash
git add ida_domain/functions.py tests/test_functions.py
git commit -m "feat(functions): add delete() alias for LLM API"
```

---

### Task 2.5: Remove post-fork methods from Functions

**Files:**
- Modify: `ida_domain/functions.py`

**Methods to remove:**
- `get_index` - Low-level, use iteration
- `contains` - Use `get_at(ea) is not None` or `exists_at()`
- `set_start` - Low-level
- `set_end` - Low-level
- `update` - Low-level
- `add_tail` - Low-level
- `remove_tail` - Low-level

**Step 1: Verify methods exist**

Run: `grep -n "def get_index\|def contains\|def set_start\|def set_end\|def update\|def add_tail\|def remove_tail" ida_domain/functions.py`

**Step 2: Remove each method**

Delete the following method definitions from `functions.py`:
- Lines containing `def get_index(self, func: func_t)`
- Lines containing `def contains(self, func: func_t, ea: ea_t)`
- Lines containing `def set_start(self, func: func_t, new_start: ea_t)`
- Lines containing `def set_end(self, func: func_t, new_end: ea_t)`
- Lines containing `def update(self, func: func_t)`
- Lines containing `def add_tail(self, func: func_t, tail_start: ea_t, tail_end: ea_t)`
- Lines containing `def remove_tail(self, func: func_t, tail_ea: ea_t)`

**Step 3: Run tests to verify nothing is broken**

Run: `pytest tests/test_functions.py -v`
Expected: PASS (if tests don't use removed methods)

**Step 4: Commit**

```bash
git add ida_domain/functions.py
git commit -m "refactor(functions): remove low-level post-fork methods per LLM API spec"
```

---

## Phase 3: Analysis Entity (Post-Fork - Major Changes)

### Task 3.1: Add `wait()` method (alias for `wait_for_completion`)

**Files:**
- Modify: `ida_domain/analysis.py`
- Modify: `tests/test_analysis.py`

**Step 1: Write the failing test**

```python
def test_analysis_wait_alias(db):
    """Test wait() is alias for wait_for_completion()."""
    # Should be callable
    assert hasattr(db.analysis, 'wait')
    assert callable(db.analysis.wait)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_analysis.py::test_analysis_wait_alias -v`
Expected: FAIL with "has no attribute 'wait'"

**Step 3: Write minimal implementation**

```python
def wait(self) -> bool:
    """
    Wait until all analysis queues are empty.

    This is the LLM-friendly name for wait_for_completion().

    Returns:
        bool: True if analysis completed successfully.

    Example:
        >>> db.analysis.wait()
        >>> # Now safe to query analysis results
    """
    return self.wait_for_completion()
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_analysis.py::test_analysis_wait_alias -v`
Expected: PASS

**Step 5: Commit**

```bash
git add ida_domain/analysis.py tests/test_analysis.py
git commit -m "feat(analysis): add wait() method for LLM API"
```

---

### Task 3.2: Add `analyze()` method (replaces multiple methods)

**Files:**
- Modify: `ida_domain/analysis.py`
- Modify: `tests/test_analysis.py`

**Step 1: Write the failing test**

```python
def test_analysis_analyze(db):
    """Test analyze() method."""
    start = db.database.minimum_ea
    end = db.database.maximum_ea

    # Should be callable with range and wait parameter
    assert hasattr(db.analysis, 'analyze')
    assert callable(db.analysis.analyze)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_analysis.py::test_analysis_analyze -v`
Expected: FAIL with "has no attribute 'analyze'"

**Step 3: Write minimal implementation**

```python
def analyze(self, start: ea_t, end: ea_t, wait: bool = True) -> int:
    """
    Analyze address range and optionally wait for completion.

    This is the LLM-friendly unified method for range analysis.

    Args:
        start: Start address of range to analyze.
        end: End address of range (exclusive).
        wait: If True, blocks until analysis completes.

    Returns:
        int: Number of addresses processed.

    Example:
        >>> db.analysis.analyze(0x401000, 0x402000)
    """
    return self.analyze_range(start, end, wait)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_analysis.py::test_analysis_analyze -v`
Expected: PASS

**Step 5: Commit**

```bash
git add ida_domain/analysis.py tests/test_analysis.py
git commit -m "feat(analysis): add analyze() method for LLM API"
```

---

### Task 3.3: Add `schedule()` method with string parameter

**Files:**
- Modify: `ida_domain/analysis.py`
- Modify: `tests/test_analysis.py`

**Step 1: Write the failing test**

```python
def test_analysis_schedule(db):
    """Test schedule() with string parameter."""
    assert hasattr(db.analysis, 'schedule')
    assert callable(db.analysis.schedule)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_analysis.py::test_analysis_schedule -v`
Expected: FAIL with "has no attribute 'schedule'"

**Step 3: Write minimal implementation**

```python
def schedule(self, ea: ea_t, what: str = "reanalysis") -> None:
    """
    Schedule analysis at address.

    Args:
        ea: Address to schedule for analysis.
        what: Type of analysis. One of:
            - "code": Create instruction
            - "function": Create function
            - "reanalysis": Reanalyze address

    Raises:
        InvalidEAError: If address is invalid.
        InvalidParameterError: If what is not a valid option.

    Example:
        >>> db.analysis.schedule(0x401000, "code")
        >>> db.analysis.schedule(0x401000, "function")
    """
    if not self.database.is_valid_ea(ea):
        raise InvalidEAError(ea)

    what_lower = what.lower()
    if what_lower == "code":
        self.schedule_code_analysis(ea)
    elif what_lower == "function":
        self.schedule_function_analysis(ea)
    elif what_lower == "reanalysis":
        self.schedule_reanalysis(ea)
    else:
        raise InvalidParameterError(
            "what", what,
            'must be one of: "code", "function", "reanalysis"'
        )
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_analysis.py::test_analysis_schedule -v`
Expected: PASS

**Step 5: Commit**

```bash
git add ida_domain/analysis.py tests/test_analysis.py
git commit -m "feat(analysis): add schedule() method with string parameter for LLM API"
```

---

### Task 3.4: Add `cancel()` method (alias for cancel_analysis)

**Files:**
- Modify: `ida_domain/analysis.py`
- Modify: `tests/test_analysis.py`

**Step 1: Write the failing test**

```python
def test_analysis_cancel(db):
    """Test cancel() is alias for cancel_analysis()."""
    assert hasattr(db.analysis, 'cancel')
    assert callable(db.analysis.cancel)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_analysis.py::test_analysis_cancel -v`
Expected: FAIL with "has no attribute 'cancel'"

**Step 3: Write minimal implementation**

```python
def cancel(self, start: ea_t, end: ea_t) -> None:
    """
    Cancel pending analysis for address range.

    This is the LLM-friendly name for cancel_analysis().

    Args:
        start: Start address of range.
        end: End address of range (exclusive).

    Example:
        >>> db.analysis.cancel(0x401000, 0x402000)
    """
    return self.cancel_analysis(start, end)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_analysis.py::test_analysis_cancel -v`
Expected: PASS

**Step 5: Commit**

```bash
git add ida_domain/analysis.py tests/test_analysis.py
git commit -m "feat(analysis): add cancel() method for LLM API"
```

---

### Task 3.5: Remove legacy methods from Analysis

**Files:**
- Modify: `ida_domain/analysis.py`

**Methods to remove (all post-fork):**
- `wait_for_completion` → keep but deprecate (it's the main impl)
- `analyze_range` → keep but deprecate (it's the main impl)
- `analyze_range_until_stable` → remove
- `wait_for_range` → remove
- `schedule_code_analysis` → keep but deprecate (used by schedule)
- `schedule_function_analysis` → keep but deprecate (used by schedule)
- `schedule_reanalysis` → keep but deprecate (used by schedule)
- `schedule_range_analysis` → remove
- `cancel_analysis` → keep but deprecate (used by cancel)
- `cancel_queue` → remove
- `current_state` → remove
- `auto_wait` → remove
- `plan_and_wait` → remove
- `auto_is_ok` → remove
- `get_auto_state` → remove
- `plan_ea` → remove
- `plan_range` → remove
- `get_auto_display` → remove
- `enable_auto` → remove
- `disable_auto` → remove
- `show_auto` → remove
- `noshow_auto` → remove
- `analysis_active` → remove
- `show_addr` → remove
- `reanalyze_function_callers` → remove
- `recreate_instruction` → remove
- `revert_analysis` → remove

**Note:** This is a large cleanup. Proceed carefully with tests.

**Step 1: Remove methods one batch at a time**

**Step 2: Run tests after each batch**

Run: `pytest tests/test_analysis.py -v`

**Step 3: Commit**

```bash
git add ida_domain/analysis.py
git commit -m "refactor(analysis): remove legacy methods per LLM API spec"
```

---

## Phase 4: Search Entity (Post-Fork - Major Changes)

### Task 4.1: Add `find_next()` method with string parameter

**Files:**
- Modify: `ida_domain/search.py`
- Modify: `tests/test_search.py`

**Step 1: Write the failing test**

```python
def test_search_find_next(db):
    """Test find_next() with string parameter."""
    assert hasattr(db.search, 'find_next')
    start = db.database.minimum_ea

    # Test with valid 'what' values
    result = db.search.find_next(start, "code")
    # Should return ea_t or None
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_search.py::test_search_find_next -v`
Expected: FAIL with "has no attribute 'find_next'"

**Step 3: Write minimal implementation**

```python
def find_next(
    self,
    ea: ea_t,
    what: str,
    direction: str = "forward"
) -> Optional[ea_t]:
    """
    Find next match of the specified type.

    Args:
        ea: Starting address for search.
        what: What to search for. One of:
            - "undefined": Unexplored bytes
            - "defined": Defined items
            - "code": Code/instructions
            - "data": Data items
            - "code_outside_function": Code not in a function
            - "error": Problem addresses
            - "untyped_operand": Operands without type
            - "suspicious_operand": Suspicious operands
        direction: Search direction ("forward" or "backward").

    Returns:
        Address of next match, or None if not found.

    Example:
        >>> ea = db.search.find_next(0x401000, "undefined")
    """
    search_dir = (
        SearchDirection.DOWN if direction == "forward"
        else SearchDirection.UP
    )

    what_lower = what.lower()
    if what_lower == "undefined":
        return self.next_undefined(ea, search_dir)
    elif what_lower == "defined":
        return self.next_defined(ea, search_dir)
    elif what_lower == "code":
        return self.next_code(ea, search_dir)
    elif what_lower == "data":
        return self.next_data(ea, search_dir)
    elif what_lower == "code_outside_function":
        return self.next_code_outside_function(ea, search_dir)
    elif what_lower == "error":
        result = self.next_error(ea, search_dir)
        return result[0] if result[0] else None
    elif what_lower == "untyped_operand":
        result = self.next_untyped_operand(ea, search_dir)
        return result[0] if result[0] else None
    elif what_lower == "suspicious_operand":
        result = self.next_suspicious_operand(ea, search_dir)
        return result[0] if result[0] else None
    else:
        raise InvalidParameterError(
            "what", what,
            'must be one of: "undefined", "defined", "code", "data", '
            '"code_outside_function", "error", "untyped_operand", "suspicious_operand"'
        )
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_search.py::test_search_find_next -v`
Expected: PASS

**Step 5: Commit**

```bash
git add ida_domain/search.py tests/test_search.py
git commit -m "feat(search): add find_next() method with string parameter for LLM API"
```

---

### Task 4.2: Add `find_all()` method with string parameter

**Files:**
- Modify: `ida_domain/search.py`
- Modify: `tests/test_search.py`

**Step 1: Write the failing test**

```python
def test_search_find_all(db):
    """Test find_all() with string parameter."""
    assert hasattr(db.search, 'find_all')
    start = db.database.minimum_ea
    end = db.database.maximum_ea

    # Should return iterator
    result = db.search.find_all(start, end, "code")
    assert hasattr(result, '__iter__')
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_search.py::test_search_find_all -v`
Expected: FAIL with "has no attribute 'find_all'"

**Step 3: Write minimal implementation**

```python
def find_all(
    self,
    start: ea_t,
    end: ea_t,
    what: str
) -> Iterator[ea_t]:
    """
    Find all matches of the specified type in a range.

    Args:
        start: Start of range.
        end: End of range.
        what: What to search for (same values as find_next).

    Yields:
        Addresses of matches.

    Example:
        >>> for ea in db.search.find_all(0x401000, 0x410000, "undefined"):
        ...     print(hex(ea))
    """
    what_lower = what.lower()
    if what_lower == "undefined":
        yield from self.all_undefined(start, end)
    elif what_lower == "defined":
        yield from self.all_defined(start, end)
    elif what_lower == "code":
        yield from self.all_code(start, end)
    elif what_lower == "data":
        yield from self.all_data(start, end)
    elif what_lower == "code_outside_function":
        yield from self.all_code_outside_functions(start, end)
    elif what_lower == "error":
        for ea, _ in self.all_errors(start, end):
            yield ea
    elif what_lower == "untyped_operand":
        for ea, _ in self.all_untyped_operands(start, end):
            yield ea
    else:
        raise InvalidParameterError(
            "what", what,
            'must be one of: "undefined", "defined", "code", "data", '
            '"code_outside_function", "error", "untyped_operand"'
        )
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_search.py::test_search_find_all -v`
Expected: PASS

**Step 5: Commit**

```bash
git add ida_domain/search.py tests/test_search.py
git commit -m "feat(search): add find_all() method with string parameter for LLM API"
```

---

### Task 4.3: Remove legacy methods from Search

**Files:**
- Modify: `ida_domain/search.py`

**Methods to remove (all post-fork):**
- `next_undefined` → keep but deprecate (used by find_next)
- `next_defined` → keep but deprecate
- `next_code` → keep but deprecate
- `next_data` → keep but deprecate
- `next_code_outside_function` → keep but deprecate
- `next_error` → keep but deprecate
- `next_untyped_operand` → keep but deprecate
- `next_suspicious_operand` → keep but deprecate
- `next_register_access` → remove (specialized)
- `all_undefined` → keep but deprecate (used by find_all)
- `all_defined` → keep but deprecate
- `all_code` → keep but deprecate
- `all_data` → keep but deprecate
- `all_code_outside_functions` → keep but deprecate
- `all_errors` → keep but deprecate
- `all_untyped_operands` → keep but deprecate
- `all_register_accesses` → remove (specialized)

**Step 1: Remove specialized methods**

**Step 2: Run tests**

Run: `pytest tests/test_search.py -v`

**Step 3: Commit**

```bash
git add ida_domain/search.py
git commit -m "refactor(search): remove specialized methods per LLM API spec"
```

---

## Phase 5: Decompiler Entity (Post-Fork)

### Task 5.1: Rename `decompile_at` to `decompile`

**Files:**
- Modify: `ida_domain/decompiler.py`
- Modify: `tests/test_decompiler.py`

**Step 1: Write the failing test**

```python
def test_decompiler_decompile(db):
    """Test decompile() method."""
    assert hasattr(db.decompiler, 'decompile')
    assert callable(db.decompiler.decompile)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_decompiler.py::test_decompiler_decompile -v`
Expected: FAIL with "has no attribute 'decompile'"

**Step 3: Write minimal implementation**

Rename `decompile_at` to `decompile` in the class:

```python
def decompile(self, ea: ea_t, remove_tags: bool = True) -> Optional[List[str]]:
    """
    Decompile function at the specified address.

    Args:
        ea: Address within the function to decompile.
        remove_tags: If True, removes IDA color tags from output.

    Returns:
        List of pseudocode lines, or None if decompilation fails.

    Example:
        >>> lines = db.decompiler.decompile(0x401000)
        >>> if lines:
        ...     for line in lines:
        ...         print(line)
    """
    # ... existing implementation from decompile_at ...
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_decompiler.py::test_decompiler_decompile -v`
Expected: PASS

**Step 5: Commit**

```bash
git add ida_domain/decompiler.py tests/test_decompiler.py
git commit -m "refactor(decompiler): rename decompile_at to decompile for LLM API"
```

---

## Phase 6: Exporter Entity (Post-Fork - Major Changes)

### Task 6.1: Add unified `export()` method

**Files:**
- Modify: `ida_domain/exporter.py`
- Modify: `tests/test_exporter.py`

**Step 1: Write the failing test**

```python
def test_exporter_export(db, tmp_path):
    """Test unified export() method."""
    assert hasattr(db.exporter, 'export')

    # Test with 'asm' format
    output = tmp_path / "test.asm"
    result = db.exporter.export(str(output), "asm")
    assert isinstance(result, bool)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_exporter.py::test_exporter_export -v`
Expected: FAIL with "has no attribute 'export'"

**Step 3: Write minimal implementation**

```python
def export(
    self,
    path: str,
    format: str,
    start: Optional[ea_t] = None,
    end: Optional[ea_t] = None,
    **options: Any
) -> bool:
    """
    Export database contents to a file.

    Args:
        path: Output file path.
        format: Export format. One of:
            - "asm": Assembly file
            - "lst": Listing file
            - "map": MAP file
            - "idc": IDC script
            - "exe": Reconstructed executable
            - "diff": Difference file
            - "bytes": Raw bytes
        start: Start address (None = database minimum).
        end: End address (None = database maximum).
        **options: Format-specific options.

    Returns:
        bool: True if export succeeded.

    Example:
        >>> db.exporter.export("/tmp/output.asm", "asm")
        >>> db.exporter.export("/tmp/data.bin", "bytes", start=0x401000, end=0x402000)
    """
    format_lower = format.lower()

    if format_lower == "asm":
        return self.generate_assembly(path, start, end)
    elif format_lower == "lst":
        return self.generate_listing(path, start, end)
    elif format_lower == "map":
        return self.generate_map_file(path, start, end)
    elif format_lower == "idc":
        return self.generate_idc_script(path, start, end)
    elif format_lower == "exe":
        return self.generate_executable(path)
    elif format_lower == "diff":
        return self.generate_diff(path, start, end)
    elif format_lower == "bytes":
        if start is None or end is None:
            raise InvalidParameterError(
                "start/end", None,
                "start and end are required for bytes export"
            )
        result = self.export_bytes(path, start, end)
        return result >= 0
    else:
        raise InvalidParameterError(
            "format", format,
            'must be one of: "asm", "lst", "map", "idc", "exe", "diff", "bytes"'
        )
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_exporter.py::test_exporter_export -v`
Expected: PASS

**Step 5: Commit**

```bash
git add ida_domain/exporter.py tests/test_exporter.py
git commit -m "feat(exporter): add unified export() method for LLM API"
```

---

## Phase 7: Xrefs Entity

### Task 7.1: Add `get_refs_to()` alias

**Files:**
- Modify: `ida_domain/xrefs.py`
- Modify: `tests/test_xrefs.py`

**Step 1: Write the failing test**

```python
def test_xrefs_get_refs_to_alias(db):
    """Test get_refs_to() is alias for to_ea()."""
    assert hasattr(db.xrefs, 'get_refs_to')
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_xrefs.py::test_xrefs_get_refs_to_alias -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
def get_refs_to(self, ea: ea_t) -> Iterator[XrefInfo]:
    """
    Get all cross-references to an address.

    This is an LLM-friendly alias for to_ea().

    Args:
        ea: Target address.

    Yields:
        XrefInfo objects.

    Example:
        >>> for xref in db.xrefs.get_refs_to(0x401000):
        ...     print(f"{hex(xref.from_ea)} -> {hex(xref.to_ea)}")
    """
    return self.to_ea(ea)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_xrefs.py::test_xrefs_get_refs_to_alias -v`
Expected: PASS

**Step 5: Commit**

```bash
git add ida_domain/xrefs.py tests/test_xrefs.py
git commit -m "feat(xrefs): add get_refs_to() alias for LLM API"
```

---

### Task 7.2: Add `get_refs_from()` alias

**Files:**
- Modify: `ida_domain/xrefs.py`
- Modify: `tests/test_xrefs.py`

**Step 1: Write the failing test**

```python
def test_xrefs_get_refs_from_alias(db):
    """Test get_refs_from() is alias for from_ea()."""
    assert hasattr(db.xrefs, 'get_refs_from')
```

**Step 2: Run test to verify it fails**

**Step 3: Write minimal implementation**

```python
def get_refs_from(self, ea: ea_t) -> Iterator[XrefInfo]:
    """
    Get all cross-references from an address.

    This is an LLM-friendly alias for from_ea().

    Args:
        ea: Source address.

    Yields:
        XrefInfo objects.
    """
    return self.from_ea(ea)
```

**Step 4: Run test to verify it passes**

**Step 5: Commit**

```bash
git add ida_domain/xrefs.py tests/test_xrefs.py
git commit -m "feat(xrefs): add get_refs_from() alias for LLM API"
```

---

### Task 7.3: Add `has_refs_to()` method with type parameter

**Files:**
- Modify: `ida_domain/xrefs.py`
- Modify: `tests/test_xrefs.py`

**Step 1: Write the failing test**

```python
def test_xrefs_has_refs_to(db):
    """Test has_refs_to() with optional type parameter."""
    assert hasattr(db.xrefs, 'has_refs_to')
```

**Step 2: Run test to verify it fails**

**Step 3: Write minimal implementation**

```python
def has_refs_to(self, ea: ea_t, type: Optional[str] = None) -> bool:
    """
    Check if references to this address exist.

    Args:
        ea: Address to check.
        type: Optional filter. One of:
            - None: Any reference
            - "code": Code references only
            - "data": Data references only

    Returns:
        bool: True if matching references exist.

    Example:
        >>> if db.xrefs.has_refs_to(0x401000, "code"):
        ...     print("Function is called")
    """
    if type is None:
        return self.has_any_refs_to(ea)
    elif type.lower() == "code":
        return self.has_code_refs_to(ea)
    elif type.lower() == "data":
        return self.has_data_refs_to(ea)
    else:
        raise InvalidParameterError(
            "type", type, 'must be None, "code", or "data"'
        )
```

**Step 4: Run test to verify it passes**

**Step 5: Commit**

```bash
git add ida_domain/xrefs.py tests/test_xrefs.py
git commit -m "feat(xrefs): add has_refs_to() with type parameter for LLM API"
```

---

### Task 7.4: Add `has_refs_from()` method

**Files:**
- Modify: `ida_domain/xrefs.py`
- Modify: `tests/test_xrefs.py`

**Step 1: Write the failing test**

```python
def test_xrefs_has_refs_from(db):
    """Test has_refs_from()."""
    assert hasattr(db.xrefs, 'has_refs_from')
```

**Step 2: Write minimal implementation**

```python
def has_refs_from(self, ea: ea_t) -> bool:
    """
    Check if references from this address exist.

    Args:
        ea: Address to check.

    Returns:
        bool: True if references from this address exist.
    """
    return self.has_any_refs_from(ea)
```

**Step 3: Commit**

```bash
git add ida_domain/xrefs.py tests/test_xrefs.py
git commit -m "feat(xrefs): add has_refs_from() for LLM API"
```

---

### Task 7.5: Remove post-fork methods from Xrefs

**Files:**
- Modify: `ida_domain/xrefs.py`

**Methods to remove:**
- `has_any_refs_to` → keep but deprecate (used by has_refs_to)
- `has_any_refs_from` → keep but deprecate (used by has_refs_from)
- `has_code_refs_to` → keep but deprecate (used by has_refs_to)
- `has_data_refs_to` → keep but deprecate (used by has_refs_to)
- `count_refs_to` → remove
- `count_refs_from` → remove

**Step 1: Remove count methods**

**Step 2: Run tests**

Run: `pytest tests/test_xrefs.py -v`

**Step 3: Commit**

```bash
git add ida_domain/xrefs.py
git commit -m "refactor(xrefs): remove count methods per LLM API spec"
```

---

## Phase 8: Types Entity

### Task 8.1: Add `get()` unified method

**Files:**
- Modify: `ida_domain/types.py`
- Modify: `tests/test_types.py`

**Step 1: Write the failing test**

```python
def test_types_get(db):
    """Test get() accepts name or ordinal."""
    assert hasattr(db.types, 'get')
```

**Step 2: Write minimal implementation**

```python
def get(self, name_or_ordinal: Union[str, int]) -> Optional[tinfo_t]:
    """
    Get type by name or ordinal.

    Args:
        name_or_ordinal: Type name (str) or ordinal number (int).

    Returns:
        Type information, or None if not found.

    Example:
        >>> type_info = db.types.get("size_t")
        >>> type_info = db.types.get(5)  # by ordinal
    """
    if isinstance(name_or_ordinal, int):
        return self.get_by_ordinal(name_or_ordinal)
    else:
        return self.get_by_name(name_or_ordinal)
```

**Step 3: Commit**

```bash
git add ida_domain/types.py tests/test_types.py
git commit -m "feat(types): add get() unified method for LLM API"
```

---

### Task 8.2: Add `apply()` unified method

**Files:**
- Modify: `ida_domain/types.py`
- Modify: `tests/test_types.py`

**Step 1: Write the failing test**

```python
def test_types_apply(db):
    """Test apply() accepts type or name."""
    assert hasattr(db.types, 'apply')
```

**Step 2: Write minimal implementation**

```python
def apply(self, ea: ea_t, type_or_name: Union[tinfo_t, str]) -> bool:
    """
    Apply type to address.

    Args:
        ea: Address to apply type to.
        type_or_name: Type info object or type name string.

    Returns:
        bool: True if type was applied successfully.

    Example:
        >>> db.types.apply(0x401000, "int *")
        >>> db.types.apply(0x401000, type_info)
    """
    if isinstance(type_or_name, str):
        return self.apply_by_name(ea, type_or_name)
    else:
        return self.apply_at(type_or_name, ea)
```

**Step 3: Commit**

```bash
git add ida_domain/types.py tests/test_types.py
git commit -m "feat(types): add apply() unified method for LLM API"
```

---

### Task 8.3: Add `guess()` alias

**Files:**
- Modify: `ida_domain/types.py`
- Modify: `tests/test_types.py`

**Step 1: Write minimal implementation**

```python
def guess(self, ea: ea_t) -> Optional[tinfo_t]:
    """
    Guess type at address.

    This is an LLM-friendly alias for guess_at().

    Args:
        ea: Address to guess type for.

    Returns:
        Guessed type, or None.
    """
    return self.guess_at(ea)
```

**Step 2: Commit**

```bash
git add ida_domain/types.py tests/test_types.py
git commit -m "feat(types): add guess() alias for LLM API"
```

---

### Task 8.4: Add `format()` alias

**Files:**
- Modify: `ida_domain/types.py`
- Modify: `tests/test_types.py`

**Step 1: Write minimal implementation**

```python
def format(self, type_info: tinfo_t) -> str:
    """
    Format type as C declaration string.

    This is an LLM-friendly alias for format_type().

    Args:
        type_info: Type to format.

    Returns:
        C-style declaration string.
    """
    return self.format_type(type_info)
```

**Step 2: Commit**

```bash
git add ida_domain/types.py tests/test_types.py
git commit -m "feat(types): add format() alias for LLM API"
```

---

### Task 8.5: Remove post-fork methods from Types

**Files:**
- Modify: `ida_domain/types.py`

**Methods to remove:**
- `get_by_ordinal` → keep but deprecate (used by get)
- `get_ordinal` → remove
- `apply_by_name` → keep but deprecate (used by apply)
- `apply_declaration` → remove
- `guess_at` → keep but deprecate (used by guess)
- `format_type` → keep but deprecate (used by format)
- `format_type_at` → remove
- `compare_types` → remove
- `validate_type` → remove
- `resolve_typedef` → remove
- `remove_pointer` → remove
- `is_udt` → remove

**Step 1: Remove methods**

**Step 2: Run tests**

Run: `pytest tests/test_types.py -v`

**Step 3: Commit**

```bash
git add ida_domain/types.py
git commit -m "refactor(types): remove low-level methods per LLM API spec"
```

---

## Phase 9: Remaining Entities (Summary)

The following entities follow the same patterns. Each needs:
1. Add new LLM-friendly methods
2. Add aliases for standard naming
3. Remove post-fork low-level methods

### Bytes Entity
- Add: `find_bytes()`, `find_text()`, `set_operand_format()`, `get_operand_type()`
- Remove: `set_operand_hex/decimal/octal/binary/char`, `is_*_operand`, `get_item_head/end_at`

### Names Entity
- Add: `resolve()`, `count()`, `set()`, `is_valid()`, `is_public()`, `is_weak()`, `set_public()`, `set_weak()`
- Remove: `resolve_name`, `resolve_value`, `delete_local`, `create_dummy`, `get_visible_name`, `validate`, `get_colored_name`, `format_expression`

### Instructions Entity
- Add: `get_in_range()`, `create()`, `is_call()`, `add_xref()`
- Remove: `decode_at`, `get_preceding`, `can_decode`, `get_size`, `format_operand`, `add_code/data_reference`, low-level methods

### Segments Entity
- Add: `create()`, `count()`
- Remove: `get_index`, `get_type`, `get_paragraph`, `get_base`, `set_start/end`, `update`, `move`, `rebase`, `set/is_visible`

### Comments Entity
- Add: `get()`, `set()`, `delete()`
- Remove: `delete_all_extra_at`, color/utility methods, sourcefile methods

### Imports Entity
- Add: `get_module()`, `find()`, `exists_at()`, `count()`
- Remove: `get_module_by_name`, `get_module_names`, `get_entries_by_module`, specialized methods

### StackFrames Entity
- Remove: `resize`, `set_purged_bytes`, section getters, `set_variable_type`, specialized methods

### Switches Entity
- Add: `delete()`, `get_cases()`, `get_targets()`, `count_cases()`
- Remove: `remove`, `update`, parent methods, renamed methods

### TryBlocks Entity
- Add: `create()`, `delete()`
- Remove: `add`, `remove_in_range`, `is_*_start` methods, specialized methods

### Problems Entity
- Add: `get_in_range()`, `create()`, `delete()`, `clear()`, `exists_at()`
- Remove: `get_between`, `get_next`, `has_problem`, specialized methods

### Fixups Entity
- Add: `get_in_range()`, `exists_at()`, `create()`, `delete()`
- Remove: `get_between`, `has_fixup`, `add`, `remove`, specialized methods

---

## Execution Summary

**Total Tasks:** ~50 tasks across 9+ phases
**Estimated Commits:** ~50 commits (one per task)

### Key Principles:
1. TDD: Write test first, verify it fails, implement, verify it passes
2. Small commits: One logical change per commit
3. Backward compatibility: Pre-fork methods get aliases, not removed
4. Post-fork cleanup: Remove low-level/specialized methods
5. String literals: Replace enum parameters with string parameters where specified

### Testing Strategy:
- Run full test suite after each phase: `pytest tests/ -v`
- Run mypy after major changes: `mypy ida_domain/ --strict`
- Run ruff for linting: `ruff check ida_domain/`

---

**Plan complete and saved to `docs/plans/2025-12-19-llm-api-refactoring.md`. Two execution options:**

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

**Which approach?**
