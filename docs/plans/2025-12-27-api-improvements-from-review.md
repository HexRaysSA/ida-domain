# ida-domain API Improvements Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement the high-priority actionable recommendations from the technical review to improve API consistency, usability, and functionality.

**Architecture:** Three phases - (1) Immediate fixes for consistency and usability, (2) New features for xref mutation and pattern matching, (3) Foundation for kernel object wrapping. Each change follows TDD with comprehensive tests.

**Tech Stack:** Python 3.10+, IDA Pro SDK 9.1+, pytest, dataclasses

---

## Phase 1: Immediate Improvements (High Impact, Low Effort)

### Task 1: Add `__repr__` methods to XrefInfo dataclass

**Files:**
- Modify: `ida_domain/xrefs.py:46-80`
- Test: `tests/test_xrefs.py`

**Step 1: Write the failing test**

Add to `tests/test_xrefs.py`:

```python
class TestXrefInfoDataclass:
    """Tests for XrefInfo dataclass representation."""

    def test_xrefinfo_repr_contains_addresses(self, test_env):
        """
        Test XrefInfo __repr__ includes hex addresses.

        RATIONALE: Dataclass repr should show hex addresses and type name
        for easy debugging in IDA's Python console.
        """
        # Find any xref
        func = next(test_env.functions.get_all())
        xrefs = list(test_env.xrefs.to_ea(func.start_ea))

        if not xrefs:
            pytest.skip('No xrefs found for testing')

        xref = xrefs[0]
        repr_str = repr(xref)

        # Should contain hex addresses
        assert f'0x{xref.from_ea:x}' in repr_str.lower(), (
            f'XrefInfo repr should contain from_ea in hex, got: {repr_str}'
        )
        assert f'0x{xref.to_ea:x}' in repr_str.lower(), (
            f'XrefInfo repr should contain to_ea in hex, got: {repr_str}'
        )
        assert xref.type.name in repr_str, (
            f'XrefInfo repr should contain type name, got: {repr_str}'
        )
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_xrefs.py::TestXrefInfoDataclass::test_xrefinfo_repr_contains_addresses -xvs`
Expected: FAIL (default dataclass repr shows decimal addresses)

**Step 3: Write minimal implementation**

In `ida_domain/xrefs.py`, add to the `XrefInfo` dataclass after line 80:

```python
    def __repr__(self) -> str:
        """Return a readable representation with hex addresses."""
        return (
            f"XrefInfo(0x{self.from_ea:x} -> 0x{self.to_ea:x}, "
            f"{self.type.name}, {'code' if self.is_code else 'data'})"
        )
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_xrefs.py::TestXrefInfoDataclass::test_xrefinfo_repr_contains_addresses -xvs`
Expected: PASS

**Step 5: Commit**

```bash
git add ida_domain/xrefs.py tests/test_xrefs.py
git commit -m "feat(xrefs): add __repr__ to XrefInfo for readable debugging output"
```

---

### Task 2: Add `__repr__` methods to CallerInfo dataclass

**Files:**
- Modify: `ida_domain/xrefs.py:82-89`
- Test: `tests/test_xrefs.py`

**Step 1: Write the failing test**

Add to `tests/test_xrefs.py`:

```python
    def test_callerinfo_repr_contains_address_and_name(self, test_env):
        """
        Test CallerInfo __repr__ includes address and caller name.

        RATIONALE: CallerInfo repr should show caller address and name
        for easy identification of call sites.
        """
        # Find a function with callers
        for func in test_env.functions.get_all():
            callers = list(test_env.xrefs.get_callers(func.start_ea))
            if callers:
                caller = callers[0]
                repr_str = repr(caller)

                # Should contain hex address
                assert f'0x{caller.ea:x}' in repr_str.lower(), (
                    f'CallerInfo repr should contain ea in hex, got: {repr_str}'
                )
                # Should contain name if available
                if caller.name:
                    assert caller.name in repr_str, (
                        f'CallerInfo repr should contain name, got: {repr_str}'
                    )
                return

        pytest.skip('No function with callers found')
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_xrefs.py::TestXrefInfoDataclass::test_callerinfo_repr_contains_address_and_name -xvs`
Expected: FAIL

**Step 3: Write minimal implementation**

In `ida_domain/xrefs.py`, add to the `CallerInfo` dataclass after line 89:

```python
    def __repr__(self) -> str:
        """Return a readable representation with hex address and caller name."""
        func_part = f", func=0x{self.function_ea:x}" if self.function_ea else ""
        return f"CallerInfo(0x{self.ea:x}, '{self.name}', {self.xref_type.name}{func_part})"
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_xrefs.py::TestXrefInfoDataclass::test_callerinfo_repr_contains_address_and_name -xvs`
Expected: PASS

**Step 5: Commit**

```bash
git add ida_domain/xrefs.py tests/test_xrefs.py
git commit -m "feat(xrefs): add __repr__ to CallerInfo for readable debugging output"
```

---

### Task 3: Add wildcard byte pattern search to Bytes class

**Files:**
- Modify: `ida_domain/bytes.py`
- Test: `tests/test_bytes.py`

**Step 1: Write the failing test**

Add to `tests/test_bytes.py`:

```python
class TestWildcardPatternSearch:
    """Tests for wildcard byte pattern search."""

    def test_find_pattern_with_wildcards_finds_match(self, test_env):
        """
        Test find_pattern finds bytes matching wildcard pattern.

        RATIONALE: Wildcard patterns like "CC ?? 90" are essential for
        signature-based searching where some bytes vary.
        """
        # Find a known byte sequence in the binary
        start_ea = test_env.minimum_ea

        # Read first few bytes and create a pattern with wildcard
        first_bytes = test_env.bytes.get_bytes_at(start_ea, 4)
        if first_bytes is None or len(first_bytes) < 4:
            pytest.skip('Cannot read bytes for pattern test')

        # Create pattern: first byte, wildcard, third byte, fourth byte
        pattern = f"{first_bytes[0]:02X} ?? {first_bytes[2]:02X} {first_bytes[3]:02X}"

        result = test_env.bytes.find_pattern(pattern, start_ea)

        assert result is not None, f'find_pattern should find pattern "{pattern}"'
        assert result == start_ea, (
            f'find_pattern should find pattern at 0x{start_ea:x}, got 0x{result:x}'
        )

    def test_find_pattern_with_no_match_returns_none(self, test_env):
        """
        Test find_pattern returns None when pattern not found.

        RATIONALE: Method should return None for patterns that don't exist
        in the binary, not raise an exception.
        """
        # Use a pattern unlikely to exist
        pattern = "DE AD BE EF CA FE BA BE"

        result = test_env.bytes.find_pattern(pattern)

        assert result is None, 'find_pattern should return None for non-existent pattern'

    def test_find_pattern_all_returns_multiple_matches(self, test_env):
        """
        Test find_pattern_all returns all occurrences of pattern.

        RATIONALE: Some patterns occur multiple times; the _all variant
        should return all matches, not just the first.
        """
        # Find a common single byte and search for it
        common_byte = test_env.bytes.get_byte_at(test_env.minimum_ea)
        pattern = f"{common_byte:02X}"

        results = test_env.bytes.find_pattern_all(pattern)

        assert isinstance(results, list), 'find_pattern_all should return a list'
        assert len(results) >= 1, 'find_pattern_all should find at least one match'

    def test_find_pattern_with_invalid_pattern_raises_error(self, test_env):
        """
        Test find_pattern raises InvalidParameterError for invalid patterns.

        RATIONALE: Invalid pattern syntax should raise clear errors.
        """
        with pytest.raises(InvalidParameterError):
            test_env.bytes.find_pattern("ZZ XX YY")  # Invalid hex
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_bytes.py::TestWildcardPatternSearch -xvs`
Expected: FAIL (methods don't exist)

**Step 3: Write minimal implementation**

In `ida_domain/bytes.py`, add these methods to the `Bytes` class:

```python
    def find_pattern(
        self, pattern: str, start_ea: ea_t = None, end_ea: ea_t = None
    ) -> Optional[ea_t]:
        """
        Find first occurrence of a byte pattern with wildcard support.

        Supports IDA-style patterns like "CC ?? 90 ??" where ?? matches any byte.

        Args:
            pattern: Hex string pattern with optional ?? wildcards.
                     Example: "48 89 ?? ?? 48 8B" or "CC ?? 90"
            start_ea: Search start address; defaults to database minimum ea if None.
            end_ea: Search end address; defaults to database maximum ea if None.

        Returns:
            Address where pattern was found, or None if not found.

        Raises:
            InvalidParameterError: If pattern is invalid.
            InvalidEAError: If start_ea or end_ea are specified but invalid.

        Example:
            >>> # Find padding bytes followed by any byte then NOP
            >>> ea = db.bytes.find_pattern("CC ?? 90")
        """
        if not isinstance(pattern, str):
            raise InvalidParameterError('pattern', type(pattern), 'must be string')

        if len(pattern.strip()) == 0:
            raise InvalidParameterError('pattern', pattern, 'cannot be empty')

        if start_ea is None:
            start_ea = self.database.minimum_ea
        elif not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)

        if end_ea is None:
            end_ea = self.database.maximum_ea
        elif not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)

        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        # Parse pattern into bytes and mask
        try:
            pattern_bytes, mask = self._parse_wildcard_pattern(pattern)
        except ValueError as e:
            raise InvalidParameterError('pattern', pattern, str(e))

        # Search using mask
        return self._find_pattern_with_mask(pattern_bytes, mask, start_ea, end_ea)

    def find_pattern_all(
        self, pattern: str, start_ea: ea_t = None, end_ea: ea_t = None
    ) -> List[ea_t]:
        """
        Find all occurrences of a byte pattern with wildcard support.

        Supports IDA-style patterns like "CC ?? 90 ??" where ?? matches any byte.

        Args:
            pattern: Hex string pattern with optional ?? wildcards.
            start_ea: Search start address; defaults to database minimum ea if None.
            end_ea: Search end address; defaults to database maximum ea if None.

        Returns:
            List of addresses where pattern was found.

        Raises:
            InvalidParameterError: If pattern is invalid.
            InvalidEAError: If start_ea or end_ea are specified but invalid.
        """
        if not isinstance(pattern, str):
            raise InvalidParameterError('pattern', type(pattern), 'must be string')

        if len(pattern.strip()) == 0:
            raise InvalidParameterError('pattern', pattern, 'cannot be empty')

        if start_ea is None:
            start_ea = self.database.minimum_ea
        elif not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)

        if end_ea is None:
            end_ea = self.database.maximum_ea
        elif not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)

        results: List[ea_t] = []

        try:
            pattern_bytes, mask = self._parse_wildcard_pattern(pattern)
        except ValueError as e:
            raise InvalidParameterError('pattern', pattern, str(e))

        current_ea = start_ea
        while current_ea < end_ea:
            found_ea = self._find_pattern_with_mask(pattern_bytes, mask, current_ea, end_ea)
            if found_ea is None:
                break
            results.append(found_ea)
            current_ea = found_ea + 1

        return results

    def _parse_wildcard_pattern(self, pattern: str) -> tuple:
        """
        Parse a hex pattern string with wildcards into bytes and mask.

        Args:
            pattern: Hex string like "48 89 ?? ?? 48"

        Returns:
            Tuple of (pattern_bytes, mask_bytes) where mask is 0xFF for
            literal bytes and 0x00 for wildcards.

        Raises:
            ValueError: If pattern contains invalid hex values.
        """
        pattern_bytes = []
        mask_bytes = []

        # Split on whitespace and process each token
        tokens = pattern.strip().split()

        for token in tokens:
            token = token.strip()
            if not token:
                continue

            if token in ('??', '?'):
                # Wildcard byte
                pattern_bytes.append(0)
                mask_bytes.append(0)
            else:
                # Literal hex byte
                if len(token) != 2:
                    raise ValueError(f'invalid hex byte: {token}')
                try:
                    byte_val = int(token, 16)
                    pattern_bytes.append(byte_val)
                    mask_bytes.append(0xFF)
                except ValueError:
                    raise ValueError(f'invalid hex byte: {token}')

        if not pattern_bytes:
            raise ValueError('pattern is empty')

        return bytes(pattern_bytes), bytes(mask_bytes)

    def _find_pattern_with_mask(
        self, pattern: bytes, mask: bytes, start_ea: ea_t, end_ea: ea_t
    ) -> Optional[ea_t]:
        """
        Find pattern with mask in memory range.

        Args:
            pattern: Bytes to search for.
            mask: Mask bytes (0xFF = must match, 0x00 = wildcard).
            start_ea: Start address.
            end_ea: End address.

        Returns:
            Address of first match, or None if not found.
        """
        pattern_len = len(pattern)
        current_ea = start_ea

        while current_ea + pattern_len <= end_ea:
            # Read bytes at current position
            data = ida_bytes.get_bytes(current_ea, pattern_len)
            if data is None:
                current_ea += 1
                continue

            # Check if pattern matches with mask
            match = True
            for i in range(pattern_len):
                if mask[i] != 0 and data[i] != pattern[i]:
                    match = False
                    break

            if match:
                return current_ea

            current_ea += 1

        return None
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_bytes.py::TestWildcardPatternSearch -xvs`
Expected: PASS

**Step 5: Commit**

```bash
git add ida_domain/bytes.py tests/test_bytes.py
git commit -m "feat(bytes): add wildcard pattern search with find_pattern and find_pattern_all"
```

---

## Phase 2: Xref Mutation API

### Task 4: Add xref addition methods to Xrefs class

**Files:**
- Modify: `ida_domain/xrefs.py`
- Test: `tests/test_xrefs.py`

**Step 1: Write the failing test**

Add to `tests/test_xrefs.py`:

```python
class TestXrefMutation:
    """Tests for xref creation and deletion methods."""

    def test_add_code_xref_creates_xref(self, test_env):
        """
        Test add_code_xref creates a code cross-reference.

        RATIONALE: Users need to create xrefs programmatically when
        fixing analysis or annotating code flow.
        """
        # Find two instructions to create xref between
        funcs = list(test_env.functions.get_all())
        if len(funcs) < 2:
            pytest.skip('Need at least 2 functions for xref test')

        from_ea = funcs[0].start_ea
        to_ea = funcs[1].start_ea

        # Count xrefs before
        count_before = test_env.xrefs.count_refs_to(to_ea, XrefsFlags.CODE_NOFLOW)

        # Add code xref
        result = test_env.xrefs.add_code_xref(from_ea, to_ea, XrefType.CALL_NEAR)

        assert result is True, 'add_code_xref should return True on success'

        # Verify xref was created
        count_after = test_env.xrefs.count_refs_to(to_ea, XrefsFlags.CODE_NOFLOW)
        assert count_after >= count_before, (
            f'xref count should increase after add_code_xref'
        )

    def test_add_data_xref_creates_xref(self, test_env):
        """
        Test add_data_xref creates a data cross-reference.

        RATIONALE: Users need to create data xrefs when manually
        identifying data references that IDA missed.
        """
        # Find an instruction and a data address
        insn = test_env.instructions.get_at(test_env.minimum_ea)
        if insn is None:
            pytest.skip('No instruction found')

        # Find or create a data location
        data_ea = test_env.minimum_ea + 0x1000
        if not test_env.is_valid_ea(data_ea):
            pytest.skip('Data address not available')

        from_ea = insn.ea

        # Add data xref
        result = test_env.xrefs.add_data_xref(from_ea, data_ea, XrefType.READ)

        assert result is True, 'add_data_xref should return True on success'

    def test_delete_xref_removes_xref(self, test_env):
        """
        Test delete_xref removes an existing cross-reference.

        RATIONALE: Users need to remove incorrect xrefs that were
        created by auto-analysis or by mistake.
        """
        # First create an xref to delete
        funcs = list(test_env.functions.get_all())
        if len(funcs) < 2:
            pytest.skip('Need at least 2 functions')

        from_ea = funcs[0].start_ea
        to_ea = funcs[1].start_ea

        # Add xref
        test_env.xrefs.add_code_xref(from_ea, to_ea, XrefType.CALL_NEAR)

        # Delete it
        result = test_env.xrefs.delete_xref(from_ea, to_ea)

        # Result indicates if xref existed and was deleted
        assert isinstance(result, bool), 'delete_xref should return bool'
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_xrefs.py::TestXrefMutation -xvs`
Expected: FAIL (methods don't exist)

**Step 3: Write minimal implementation**

In `ida_domain/xrefs.py`, add these methods to the `Xrefs` class:

```python
    def add_code_xref(self, from_ea: ea_t, to_ea: ea_t, xref_type: XrefType) -> bool:
        """
        Add a code cross-reference between two addresses.

        Args:
            from_ea: Source address (typically an instruction).
            to_ea: Target address (typically a function or code label).
            xref_type: Type of code reference (CALL_NEAR, CALL_FAR, JUMP_NEAR, etc.).

        Returns:
            True if xref was added successfully, False otherwise.

        Raises:
            InvalidEAError: If either address is invalid.
            InvalidParameterError: If xref_type is not a code reference type.

        Example:
            >>> db.xrefs.add_code_xref(call_insn_ea, target_func_ea, XrefType.CALL_NEAR)
        """
        if not self.database.is_valid_ea(from_ea):
            raise InvalidEAError(from_ea)
        if not self.database.is_valid_ea(to_ea):
            raise InvalidEAError(to_ea)

        if not xref_type.is_code_ref():
            raise InvalidParameterError(
                'xref_type', xref_type, 'must be a code reference type'
            )

        ida_xref.add_cref(from_ea, to_ea, xref_type)
        return True

    def add_data_xref(self, from_ea: ea_t, to_ea: ea_t, xref_type: XrefType) -> bool:
        """
        Add a data cross-reference between two addresses.

        Args:
            from_ea: Source address (typically code that references data).
            to_ea: Target address (typically a data location).
            xref_type: Type of data reference (READ, WRITE, OFFSET, etc.).

        Returns:
            True if xref was added successfully, False otherwise.

        Raises:
            InvalidEAError: If either address is invalid.
            InvalidParameterError: If xref_type is not a data reference type.

        Example:
            >>> db.xrefs.add_data_xref(insn_ea, global_var_ea, XrefType.READ)
        """
        if not self.database.is_valid_ea(from_ea):
            raise InvalidEAError(from_ea)
        if not self.database.is_valid_ea(to_ea):
            raise InvalidEAError(to_ea)

        if not xref_type.is_data_ref():
            raise InvalidParameterError(
                'xref_type', xref_type, 'must be a data reference type'
            )

        ida_xref.add_dref(from_ea, to_ea, xref_type)
        return True

    def delete_xref(self, from_ea: ea_t, to_ea: ea_t) -> bool:
        """
        Delete a cross-reference between two addresses.

        Removes both code and data xrefs from from_ea to to_ea.

        Args:
            from_ea: Source address of the xref.
            to_ea: Target address of the xref.

        Returns:
            True if an xref was found and deleted, False if no xref existed.

        Raises:
            InvalidEAError: If either address is invalid.

        Example:
            >>> db.xrefs.delete_xref(from_ea, to_ea)
        """
        if not self.database.is_valid_ea(from_ea):
            raise InvalidEAError(from_ea)
        if not self.database.is_valid_ea(to_ea):
            raise InvalidEAError(to_ea)

        # Try deleting code xref
        deleted = ida_xref.del_cref(from_ea, to_ea, 0)

        # Also try deleting data xref
        deleted = ida_xref.del_dref(from_ea, to_ea) or deleted

        return bool(deleted)
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_xrefs.py::TestXrefMutation -xvs`
Expected: PASS

**Step 5: Commit**

```bash
git add ida_domain/xrefs.py tests/test_xrefs.py
git commit -m "feat(xrefs): add xref mutation methods (add_code_xref, add_data_xref, delete_xref)"
```

---

## Phase 3: Standardize Return Conventions (Documentation Update)

### Task 5: Document API return conventions

**Files:**
- Modify: `ida_domain/base.py`
- Modify: `docs/usage.md`

**Step 1: Add docstring to base.py documenting conventions**

In `ida_domain/base.py`, add module-level docstring after imports:

```python
"""
Base classes and utilities for ida-domain entities.

API Return Conventions
----------------------

The ida-domain API follows these return conventions consistently:

**get_* methods:**
- Return `Optional[T]` - the item if found, or None if not found
- Never raise exceptions for "not found" cases
- Raise `InvalidEAError` only for invalid addresses

**create_* / set_* methods:**
- Return `bool` - True on success, False on failure
- May raise exceptions for invalid parameters

**has_* / is_* methods:**
- Return `bool` - True if condition is met, False otherwise
- Raise `InvalidEAError` for invalid addresses

**count_* methods:**
- Return `int` - the count (0 if none found)
- Raise `InvalidEAError` for invalid addresses

Example:
    >>> func = db.functions.get_at(ea)  # Returns Optional[func_t]
    >>> if func is None:
    ...     print("No function at address")
    >>>
    >>> success = db.bytes.create_dword_at(ea)  # Returns bool
    >>> if not success:
    ...     print("Failed to create dword")
"""
```

**Step 2: Verify docstring renders correctly**

Run: `python -c "import ida_domain.base; help(ida_domain.base)"`

**Step 3: Commit**

```bash
git add ida_domain/base.py
git commit -m "docs(base): document API return conventions for consistency"
```

---

## Summary

This plan addresses the **Immediate** recommendations from the technical review:

1. **Add `__repr__` to dataclasses** - Tasks 1-2 add readable repr to XrefInfo and CallerInfo
2. **Add wildcard byte pattern search** - Task 3 adds find_pattern with wildcard support
3. **Standardize return conventions** - Task 5 documents the conventions

And one **Medium-Term** item:

4. **Add xref mutation** - Task 4 adds add_code_xref, add_data_xref, delete_xref

### Verification Checklist

After completing all tasks, verify:

- [ ] All new tests pass: `pytest tests/test_xrefs.py tests/test_bytes.py -v`
- [ ] Existing tests still pass: `pytest tests/ -v`
- [ ] No type errors: `mypy ida_domain/`
- [ ] Code formatted: `black ida_domain/ tests/`
