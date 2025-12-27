# Test Quality Improvement Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Improve test suite quality from B+ to A by strengthening weak assertions, adding state verification, and eliminating "no exception" anti-patterns. Target: Fix 125 weak/rewrite tests to provide real regression protection.

**Architecture:** Prioritized approach - fix critical broken tests first (P0), then strengthen type-only assertions (P1), then add behavioral verification (P2). Each file improved independently with comprehensive review.

**Tech Stack:** Python 3.10+, IDA Pro SDK, pytest

**Current State:** 463 tests analyzed
- ✅ 40% Strong tests (keep as-is)
- ⚠️ 33% Medium tests (strengthen)
- ❌ 27% Weak tests (rewrite/strengthen)

---

## Phase 1: Critical Fixes (P0) - Broken/Useless Tests

**Impact:** 4 tests that are completely broken or provide zero value
**Timeline:** 1 day

### Task 1.1: Fix tautological assertion in test_instructions.py

**Issue:** `test_get_operand_offset_base_returns_base_for_offset_operand` has assertion that is always true

**Files:**
- Modify: `tests/test_instructions.py` (lines 399-420)

**Current Code (Line 414):**
```python
assert retrieved_base is not None or retrieved_base is None
# This is ALWAYS true - completely useless!
```

**Step 1: Identify the test**
```bash
# Locate the broken assertion
grep -n "retrieved_base is not None or retrieved_base is None" tests/test_instructions.py
```

**Step 2: Fix the assertion**

Replace with meaningful assertion:
```python
# Verify the base matches what we set
if success:
    assert retrieved_base == base_addr, (
        f"Retrieved base {hex(retrieved_base)} should match "
        f"set base {hex(base_addr)}"
    )
else:
    pytest.skip('Could not set offset operand for testing')
```

**Step 3: Run test to verify it now provides value**
```bash
pytest tests/test_instructions.py::TestOperandOffsetOperations::test_get_operand_offset_base_returns_base_for_offset_operand -xvs
```

**Step 4: Commit**
```bash
git add tests/test_instructions.py
git commit -m "fix(tests): replace tautological assertion with actual validation in offset base test"
```

---

### Task 1.2: Add assertions to test with no assertions

**Issue:** `test_add_code_reference_with_different_reference_types` has NO assertions at all

**Files:**
- Modify: `tests/test_instructions.py` (lines 726-752)

**Current Code:**
```python
def test_add_code_reference_with_different_reference_types(self, test_env):
    # ... setup code ...
    for ref_type in [XrefType.CALL, XrefType.JUMP, XrefType.FLOW]:
        test_env.instructions.add_code_reference(from_ea, to_ea, ref_type)
    # NO ASSERTIONS!
```

**Step 1: Add verification for each reference type**

```python
def test_add_code_reference_with_different_reference_types(self, test_env):
    # ... existing setup ...

    # Test each reference type
    test_cases = [
        (XrefType.CALL, 'call'),
        (XrefType.JUMP, 'jump'),
        (XrefType.FLOW, 'flow')
    ]

    for ref_type, type_name in test_cases:
        # Add reference
        test_env.instructions.add_code_reference(from_ea, to_ea, ref_type)

        # Verify it was created
        xrefs = list(test_env.xrefs.from_ea(from_ea))
        assert len(xrefs) > 0, f"Should have created {type_name} xref"

        # Verify at least one xref has correct type
        assert any(xref.to_ea == to_ea for xref in xrefs), (
            f"{type_name} xref should point to {hex(to_ea)}"
        )
```

**Step 2: Run test**
```bash
pytest tests/test_instructions.py::TestCrossReferenceManagement::test_add_code_reference_with_different_reference_types -xvs
```

**Step 3: Commit**
```bash
git add tests/test_instructions.py
git commit -m "fix(tests): add assertions to verify xref creation in reference type test"
```

---

### Task 1.3: Fix type-only assertion in invalid opcode test

**Issue:** `test_create_at_with_invalid_opcodes_returns_false` only checks type, not value

**Files:**
- Modify: `tests/test_instructions.py` (lines 180-202)

**Current Code (Line 200):**
```python
assert isinstance(success, bool)  # USELESS - doesn't check if False!
```

**Step 1: Update to verify False is returned**

```python
# Test should return False for invalid opcodes
# Note: 0xFF 0xFF might decode on some architectures
# Using multiple invalid sequences to be thorough
invalid_sequences = [
    bytes([0xFF, 0xFF, 0xFF, 0xFF]),  # Unlikely to be valid
    bytes([0x0F, 0xFF]),               # Invalid opcode on x86
]

for seq in invalid_sequences:
    # Write invalid bytes
    test_env.bytes.patch_bytes_at(test_addr, seq)

    # Attempt to create instruction
    success = test_env.instructions.create_at(test_addr)

    # Should return False (or skip if it actually decoded)
    if success:
        # Some bytes might decode - skip this sequence
        continue
    else:
        # Found a sequence that doesn't decode - verify False
        assert success is False, (
            f"create_at should return False for invalid opcode {seq.hex()}"
        )
        return  # Test passed

# If we get here, all sequences decoded (architecture-dependent)
pytest.skip("Could not find invalid opcode sequence for this architecture")
```

**Step 2: Run test**
```bash
pytest tests/test_instructions.py::TestInstructionCreation::test_create_at_with_invalid_opcodes_returns_false -xvs
```

**Step 3: Commit**
```bash
git add tests/test_instructions.py
git commit -m "fix(tests): verify False return for invalid opcodes instead of just type checking"
```

---

### Task 1.4: Make delete test actually test deletion

**Issue:** `test_functions_delete_exists_and_is_callable` only checks method exists, never calls it

**Files:**
- Modify: `tests/test_functions.py` (lines 207-220)

**Current Code:**
```python
def test_functions_delete_exists_and_is_callable(test_env):
    assert hasattr(test_env.functions, 'delete')
    assert callable(test_env.functions.delete)
    # Never actually tests deletion!
```

**Step 1: Rewrite to test actual deletion behavior**

```python
def test_functions_delete_is_alias_for_remove(test_env):
    """
    Test that delete() is a functional alias for remove().

    RATIONALE: The delete() method should provide identical behavior
    to remove() for consistency with common programming patterns.
    """
    # Find a suitable address to test with (after last function)
    all_funcs = list(test_env.functions.get_all())
    if not all_funcs:
        pytest.skip('Need at least one function for testing')

    # Use address after last function
    last_func = all_funcs[-1]
    test_ea = last_func.end_ea + 0x10

    # Ensure it's valid and not already a function
    if not test_env.is_valid_ea(test_ea):
        pytest.skip('Test address not valid')
    if test_env.functions.exists_at(test_ea):
        pytest.skip('Test address already has function')

    # Create a function at test address
    created = test_env.functions.create(test_ea)
    if not created:
        pytest.skip('Could not create test function')

    # Verify function exists
    assert test_env.functions.exists_at(test_ea), (
        "Created function should exist before deletion"
    )

    # Test delete() method
    result = test_env.functions.delete(test_ea)
    assert result is True, "delete() should return True for successful deletion"

    # Verify function was deleted
    assert not test_env.functions.exists_at(test_ea), (
        "Function should not exist after deletion"
    )

    # Verify delete() and remove() have identical behavior
    # (both should gracefully handle deleting non-existent function)
    result_delete = test_env.functions.delete(test_ea)
    result_remove = test_env.functions.remove(test_ea)
    assert result_delete == result_remove, (
        "delete() and remove() should return same result for non-existent function"
    )
```

**Step 2: Run test**
```bash
pytest tests/test_functions.py::TestFunctionsDelete::test_functions_delete_is_alias_for_remove -xvs
```

**Step 3: Commit**
```bash
git add tests/test_functions.py
git commit -m "fix(tests): test actual deletion behavior instead of just existence check"
```

---

## Phase 2: High Priority (P1) - Type-Only Assertions

**Impact:** 30+ tests that only check types without verifying behavior
**Timeline:** 3 days

### Task 2.1: Fix operand formatting tests in test_bytes.py

**Issue:** Tests 10-13 only verify return value is True, not that formatting actually changed

**Files:**
- Modify: `tests/test_bytes.py` (lines 318-446)

**Pattern:** All `set_operand_*` tests need same fix

**Step 1: Create helper to verify operand format**

Add to test_bytes.py before the test class:
```python
def _get_operand_text(db, ea, n):
    """Helper to extract operand text from disassembly."""
    disasm = db.bytes.get_disassembly_at(ea)
    if not disasm:
        return None

    # Parse operands from disassembly
    # Format is typically: "mnemonic op1, op2, ..."
    parts = disasm.split(None, 1)  # Split mnemonic from operands
    if len(parts) < 2:
        return None

    operands = parts[1].split(',')
    if n >= len(operands):
        return None

    return operands[n].strip()
```

**Step 2: Fix test_set_operand_hex_changes_display_representation**

Replace lines 318-362 with:
```python
def test_set_operand_hex_changes_display_representation(self, test_env):
    """
    Test that set_operand_hex changes operand display to hexadecimal.

    RATIONALE: When analyzing binaries, analysts often need to view numeric operands
    in different bases. The set_operand_hex method should change the display format
    without modifying the underlying value.
    """
    # Find an instruction with an immediate operand
    first_code = test_env.minimum_ea
    search_addr = first_code
    max_attempts = 100
    found_addr = None

    for _ in range(max_attempts):
        next_head = test_env.bytes.get_next_head(search_addr)
        if next_head is None:
            break

        if test_env.bytes.is_code_at(next_head):
            # Get operand text before formatting
            before_text = _get_operand_text(test_env, next_head, 0)

            # Try to set operand to hex
            result = test_env.bytes.set_operand_hex(next_head, 0)
            if result:
                # Get operand text after formatting
                after_text = _get_operand_text(test_env, next_head, 0)

                # Verify format changed to hex (contains 0x or uses hex letters)
                if after_text and ('0x' in after_text.lower() or
                                  any(c in 'abcdefABCDEF' for c in after_text)):
                    found_addr = next_head
                    break

        search_addr = next_head + 1

    if found_addr is None:
        pytest.skip('Could not find instruction with hex-formattable operand')

    # Verify the formatting actually changed to hex
    after_text = _get_operand_text(test_env, found_addr, 0)
    assert after_text is not None, "Should have operand text"
    assert ('0x' in after_text.lower() or
            any(c in 'abcdefABCDEF' for c in after_text)), (
        f"Operand should be in hex format, got: {after_text}"
    )
```

**Step 3: Apply same pattern to decimal, octal, binary tests**

Repeat for:
- `test_set_operand_decimal_changes_display_representation` (verify no 0x prefix, only 0-9)
- `test_set_operand_octal_changes_display_representation` (verify 0o prefix or octal digits)
- `test_set_operand_binary_changes_display_representation` (verify 0b prefix or binary pattern)

**Step 4: Run tests**
```bash
pytest tests/test_bytes.py::TestBytesOperandManipulation -k "set_operand" -xvs
```

**Step 5: Commit**
```bash
git add tests/test_bytes.py
git commit -m "fix(tests): verify operand formatting actually changes display, not just returns True"
```

---

### Task 2.2: Fix operand offset tests in test_instructions.py

**Issue:** Tests 11, 12, 17, 21 only check boolean return type

**Files:**
- Modify: `tests/test_instructions.py` (lines 287-437)

**Step 1: Fix test_set_operand_offset_converts_immediate_to_offset**

```python
def test_set_operand_offset_converts_immediate_to_offset(self, test_env):
    """
    Test that set_operand_offset converts immediate operand to offset reference.

    RATIONALE: Offset operands are essential for understanding code structure.
    Setting an operand as an offset should make it display as a symbol reference
    rather than a raw number.
    """
    # Find instruction with immediate operand
    # ... existing search code ...

    if found_addr is None:
        pytest.skip('Could not find instruction with immediate operand')

    # Set as offset
    result = test_env.instructions.set_operand_offset(found_addr, 0, target_ea)

    # Verify it worked
    assert result is True, "set_operand_offset should return True"

    # CRITICAL: Verify the offset was actually set
    base = test_env.instructions.get_operand_offset_base(found_addr, 0)
    assert base is not None, (
        f"Operand at {hex(found_addr)} should now have offset base"
    )
    assert base == target_ea or base == test_env.minimum_ea, (
        f"Offset base should be set to target or default base"
    )

    # Verify operand is now marked as offset
    assert test_env.bytes.is_offset_operand(found_addr, 0), (
        f"Operand at {hex(found_addr)} should be marked as offset"
    )
```

**Step 2: Apply similar fixes to other offset tests**

For each test:
1. Assert return value is True
2. Use `get_operand_offset_base()` to verify base was set
3. Use `is_offset_operand()` to verify operand type changed
4. For `format_offset_expression()`, verify returned string contains expected components

**Step 3: Run tests**
```bash
pytest tests/test_instructions.py::TestOperandOffsetOperations -xvs
```

**Step 4: Commit**
```bash
git add tests/test_instructions.py
git commit -m "fix(tests): verify offset operations actually change operand state"
```

---

### Task 2.3: Add behavioral verification to search tests

**Issue:** 11 tests in test_search.py only check types, not that results match search criteria

**Files:**
- Modify: `tests/test_search.py` (lines 65-279)

**Step 1: Fix test_next_code_finds_instruction**

```python
def test_next_code_finds_instruction(search_db):
    """
    Test that next_code finds code addresses.

    RATIONALE: Code search is fundamental for binary analysis.
    The method must return addresses that actually contain code.
    """
    start_ea = search_db.minimum_ea
    result = search_db.search.next_code(start_ea)

    # Should find code in analyzed binary
    assert result is not None, 'Should find code in analyzed binary'

    # CRITICAL: Verify it's actually code
    assert search_db.is_code(result), (
        f"Address {hex(result)} from next_code() should be code"
    )

    # Verify it's >= start address (searching forward)
    assert result >= start_ea, (
        f"Result {hex(result)} should be >= start {hex(start_ea)}"
    )
```

**Step 2: Apply pattern to all search tests**

For each `next_*` and `all_*` test, add verification:

| Test Method | Add Verification |
|-------------|------------------|
| `next_undefined` | `assert not search_db.is_defined(result)` |
| `next_defined` | `assert search_db.is_defined(result)` |
| `next_code` | `assert search_db.is_code(result)` |
| `next_data` | `assert search_db.is_data(result)` |
| `next_code_outside_function` | `assert search_db.is_code(result) and not search_db.functions.get_at(result)` |
| `all_*` iterators | Apply same checks to each yielded address |

**Step 3: Run tests**
```bash
pytest tests/test_search.py -xvs
```

**Step 4: Commit**
```bash
git add tests/test_search.py
git commit -m "fix(tests): verify search results actually match search criteria"
```

---

## Phase 3: Medium Priority (P2) - Missing State Verification

**Impact:** 40+ tests that modify state but don't verify changes
**Timeline:** 4 days

### Task 3.1: Add state verification to analysis tests

**Issue:** Tests call analyze/schedule/cancel but don't verify they worked

**Files:**
- Modify: `tests/test_analysis.py`

**Step 1: Fix test_analyze_method_is_alias_for_analyze_range**

```python
def test_analyze_method_is_alias_for_analyze_range(test_env):
    """
    Test that analyze() actually analyzes the specified range.

    RATIONALE: Analysis should convert undefined bytes to code/data.
    We verify this by checking that analysis increases the number of
    defined items in the range.
    """
    # Find range with some undefined bytes
    start_ea = test_env.minimum_ea + 0x1000
    end_ea = start_ea + 0x100

    # Count defined items before
    defined_before = sum(
        1 for ea in range(start_ea, end_ea)
        if test_env.is_defined(ea)
    )

    # Analyze the range
    result = test_env.analysis.analyze(start_ea, end_ea)

    # Wait for analysis to complete
    test_env.analysis.wait()

    # Count defined items after
    defined_after = sum(
        1 for ea in range(start_ea, end_ea)
        if test_env.is_defined(ea)
    )

    # Verify analysis occurred (some undefined became defined)
    assert defined_after >= defined_before, (
        f"Analysis should not decrease defined items: "
        f"before={defined_before}, after={defined_after}"
    )

    # If we had undefined bytes, they should have been analyzed
    if defined_before < (end_ea - start_ea):
        assert defined_after > defined_before, (
            "Analysis should have converted some undefined bytes"
        )
```

**Step 2: Fix schedule tests**

Add verification that analysis was queued:
```python
def test_schedule_method_exists_and_dispatches(test_env):
    # ... existing setup ...

    # Check if analyzing before scheduling
    was_analyzing = test_env.analysis.is_analyzing()

    # Schedule analysis
    test_env.analysis.schedule('code', start_ea, end_ea)

    # Verify analysis is now queued or running
    # (might complete quickly for small range)
    is_analyzing = test_env.analysis.is_analyzing()

    # Either it started analyzing, or it completed already
    assert is_analyzing or test_env.analysis.get_completion_percentage() == 100.0, (
        "Scheduling should either start analysis or have it complete"
    )
```

**Step 3: Run tests**
```bash
pytest tests/test_analysis.py -xvs
```

**Step 4: Commit**
```bash
git add tests/test_analysis.py
git commit -m "fix(tests): verify analysis operations actually modify database state"
```

---

### Task 3.2: Strengthen export validation tests

**Issue:** Export tests only check file exists and size > 0, not content

**Files:**
- Modify: `tests/test_exporter.py`

**Step 1: Add content validation helpers**

```python
import re

def _validate_asm_file(path):
    """Verify ASM file has valid structure."""
    with open(path, 'r') as f:
        content = f.read()

    # Should have assembly directives
    assert re.search(r'\.(text|data|bss)', content), (
        "ASM file should contain segment directives"
    )

    # Should have some instructions
    assert re.search(r'^\s+(mov|push|call|jmp)', content, re.M), (
        "ASM file should contain instructions"
    )

    return True

def _validate_map_file(path):
    """Verify MAP file has valid structure."""
    with open(path, 'r') as f:
        content = f.read()

    # Should have address mappings
    assert re.search(r'[0-9A-Fa-f]{8,}:\s+\w+', content), (
        "MAP file should contain address:symbol mappings"
    )

    return True

def _validate_idc_file(path):
    """Verify IDC file has valid structure."""
    with open(path, 'r') as f:
        content = f.read()

    # Should be valid Python/IDC
    assert 'def ' in content or 'static ' in content, (
        "IDC file should contain function definitions"
    )

    # Should have IDA API calls
    assert 'MakeName' in content or 'MakeFunction' in content, (
        "IDC file should contain IDA API calls"
    )

    return True
```

**Step 2: Update export tests to validate content**

```python
def test_generate_asm_file_creates_valid_assembly(test_env):
    """Test ASM file generation with content validation."""
    output_path = tempfile.mktemp(suffix='.asm')

    try:
        test_env.exporter.generate_asm_file(output_path)

        # Verify file exists and has content
        assert os.path.exists(output_path), "ASM file should be created"
        assert os.path.getsize(output_path) > 0, "ASM file should not be empty"

        # CRITICAL: Validate content structure
        assert _validate_asm_file(output_path), (
            "ASM file should have valid assembly structure"
        )
    finally:
        if os.path.exists(output_path):
            os.remove(output_path)
```

**Step 3: Apply to all export tests**

Update:
- `test_generate_asm_file_*` → use `_validate_asm_file()`
- `test_generate_map_file_*` → use `_validate_map_file()`
- `test_generate_idc_file_*` → use `_validate_idc_file()`

**Step 4: Add byte export round-trip test**

```python
def test_export_import_bytes_round_trip(test_env):
    """Test that exported bytes can be reimported correctly."""
    start_ea = test_env.minimum_ea
    length = 0x100

    # Read original bytes
    original = test_env.bytes.get_bytes_at(start_ea, length)

    # Export to file
    export_path = tempfile.mktemp(suffix='.bin')
    try:
        count = test_env.exporter.export_bytes(start_ea, length, export_path)
        assert count == length

        # Read exported file
        with open(export_path, 'rb') as f:
            exported = f.read()

        # Verify match
        assert exported == original, (
            f"Exported bytes should match original: "
            f"exported {len(exported)} bytes, original {len(original)} bytes"
        )
    finally:
        if os.path.exists(export_path):
            os.remove(export_path)
```

**Step 5: Run tests**
```bash
pytest tests/test_exporter.py -xvs
```

**Step 6: Commit**
```bash
git add tests/test_exporter.py
git commit -m "fix(tests): validate exported file content, not just existence"
```

---

## Phase 4: Low Priority - Consolidation and Cleanup

**Impact:** Reduces duplication, improves maintainability
**Timeline:** 2 days

### Task 4.1: Parametrize repetitive error tests

**Issue:** Many files have 5+ separate tests for InvalidEAError on different methods

**Files:**
- Modify: `tests/test_bytes.py`, `tests/test_instructions.py`, others

**Step 1: Create parametrized error validation test**

Example for test_bytes.py:
```python
@pytest.mark.parametrize("method_name,args", [
    ("get_item_head_at", (0xFFFFFFFFFFFFFFFF,)),
    ("get_item_end_at", (0xFFFFFFFFFFFFFFFF,)),
    ("get_item_size_at", (0xFFFFFFFFFFFFFFFF,)),
    ("set_operand_hex", (0xFFFFFFFFFFFFFFFF, 0)),
    ("set_operand_decimal", (0xFFFFFFFFFFFFFFFF, 0)),
    # ... etc
])
def test_invalid_address_raises_error(test_env, method_name, args):
    """Test that methods validate addresses and raise InvalidEAError."""
    method = getattr(test_env.bytes, method_name)

    with pytest.raises(InvalidEAError):
        method(*args)
```

**Step 2: Remove individual error tests**

Delete the now-redundant individual tests:
- `test_get_item_head_at_with_invalid_address_raises_error`
- `test_get_item_end_at_with_invalid_address_raises_error`
- etc.

**Step 3: Run tests to verify same coverage**
```bash
pytest tests/test_bytes.py -k "invalid_address" -xvs
```

**Step 4: Commit**
```bash
git add tests/test_bytes.py
git commit -m "refactor(tests): parametrize repetitive error validation tests"
```

---

### Task 4.2: Remove meaningless assertions

**Issue:** Some tests have `assert True` or other always-passing assertions

**Files:**
- Modify: `tests/test_search.py` (line 549)

**Step 1: Remove `assert True` from test_multiple_searches_on_same_database**

```python
def test_multiple_searches_on_same_database(search_db):
    # ... existing code ...

    # Verify results are deterministic (same each time)
    assert result1 == search_db.search.next_code(search_db.minimum_ea)
    assert result2 == search_db.search.next_data(search_db.minimum_ea)

    # Remove this useless line:
    # assert True, 'Multiple different search types should work'
```

**Step 2: Search for other meaningless assertions**
```bash
grep -n "assert True" tests/*.py
grep -n "assert.*>= 0.*At minimum" tests/*.py
```

**Step 3: Remove or fix each found assertion**

**Step 4: Commit**
```bash
git add tests/
git commit -m "refactor(tests): remove meaningless always-passing assertions"
```

---

## Phase 5: Documentation and Best Practices

**Timeline:** 1 day

### Task 5.1: Create test quality guidelines

**Files:**
- Create: `docs/testing-guidelines.md`

**Step 1: Write comprehensive testing guide**

```markdown
# Testing Guidelines for IDA Domain

## Assertion Quality Standards

### ✅ GOOD: Verify Behavior
```python
# Test actual state change
result = db.bytes.set_operand_hex(ea, 0)
assert result is True
operand_text = _get_operand_text(db, ea, 0)
assert '0x' in operand_text.lower()
```

### ❌ BAD: Type-Only Assertions
```python
# Only checks type - would pass even if broken
result = db.bytes.set_operand_hex(ea, 0)
assert isinstance(result, bool)  # DON'T DO THIS
```

### ❌ BAD: Tautological Assertions
```python
# Always passes - completely useless
assert x is not None or x is None
assert len(list) >= 0
```

## Testing Patterns

### Pattern 1: Round-Trip Validation
For any setter, verify with getter:
```python
db.functions.set_name(ea, "test_func")
assert db.functions.get_name(ea) == "test_func"
```

### Pattern 2: Cross-Validation
Compare different methods that should agree:
```python
count = db.imports.count()
manual_count = len(list(db.imports.get_all()))
assert count == manual_count
```

### Pattern 3: State Change Verification
For mutations, verify before/after:
```python
before = db.bytes.is_code_at(ea)
db.instructions.create_at(ea)
after = db.bytes.is_code_at(ea)
assert after != before  # State changed
assert after is True     # Changed to expected state
```

## Common Mistakes

1. **Testing existence instead of behavior**
   - Bad: `assert hasattr(obj, 'method')`
   - Good: Call method and verify result

2. **Accepting "either" result**
   - Bad: `assert result is None or isinstance(result, int)`
   - Good: `assert result is None` OR `assert isinstance(result, int)` (pick one based on context)

3. **Not verifying file contents**
   - Bad: `assert os.path.exists(file) and os.path.getsize(file) > 0`
   - Good: Parse file and validate structure

4. **Skipping instead of failing**
   - Bad: `if not can_create(): pytest.skip()`
   - Consider: Is this a test failure rather than skip?

## Model Tests

See these for examples:
- `test_imports.py::test_imports_get_statistics` - Cross-validation
- `test_problems.py::test_add_creates_problem_at_address` - Round-trip
- `test_decompiler.py::test_decompile_with_function_start_vs_middle` - Equivalence
```

**Step 2: Commit**
```bash
git add docs/testing-guidelines.md
git commit -m "docs: add comprehensive testing guidelines with examples"
```

---

### Task 5.2: Add test quality checks to CI

**Files:**
- Create: `.github/workflows/test-quality-check.yml`

**Step 1: Create GitHub Action to detect weak patterns**

```yaml
name: Test Quality Check

on: [pull_request]

jobs:
  check-test-quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Check for weak test patterns
        run: |
          echo "Checking for weak test patterns..."

          # Check for type-only assertions
          echo "::group::Type-only assertions"
          grep -rn "assert isinstance.*bool)" tests/ || echo "✓ None found"
          echo "::endgroup::"

          # Check for tautological assertions
          echo "::group::Tautological assertions"
          grep -rn "is not None or.*is None" tests/ && exit 1 || echo "✓ None found"
          echo "::endgroup::"

          # Check for assert True
          echo "::group::Meaningless assert True"
          grep -rn "assert True," tests/ && exit 1 || echo "✓ None found"
          echo "::endgroup::"

          echo "✓ Test quality checks passed"
```

**Step 2: Commit**
```bash
git add .github/workflows/test-quality-check.yml
git commit -m "ci: add test quality checks to catch weak patterns"
```

---

## Success Criteria

### Phase Completion Metrics

| Phase | Tests Fixed | Quality Improvement | Pass Criteria |
|-------|-------------|---------------------|---------------|
| P0 | 4 tests | Critical → Strong | All 4 tests have meaningful assertions |
| P1 | 30 tests | Weak → Medium/Strong | <5% type-only assertions remain |
| P2 | 40 tests | Medium → Strong | All mutations verify state changes |
| P3 | N/A | Reduce duplication | <10 redundant error tests |
| P4 | N/A | Documentation | Guidelines in place, CI checks added |

### Overall Success

- **Test Quality Distribution Target:**
  - Strong: 65% (up from 40%)
  - Medium: 30% (down from 33%)
  - Weak: 5% (down from 27%)

- **Zero tolerance for:**
  - Tautological assertions
  - Tests with no assertions
  - Type-only checks where behavior can be verified

### Validation

Run full test suite and verify:
```bash
# All tests still pass
pytest tests/ -v

# No weak patterns detected
.github/workflows/test-quality-check.yml

# Code coverage maintained or improved
pytest tests/ --cov=ida_domain --cov-report=html
```

---

## Notes

- Each task should be completed independently with its own commit
- Tests must pass after each task before moving to next
- Document any test that must remain weak with clear RATIONALE comment explaining why
- Update this plan as new weak patterns are discovered
- Reference commits in plan for future maintainers

---

## Future Work

After this plan completes:

1. **Add property-based testing** for complex state machines
2. **Create performance regression tests** for iteration-heavy operations
3. **Build test data generators** for richer test binaries
4. **Add mutation testing** to verify tests actually catch bugs
5. **Cross-platform testing** to catch architecture-specific assumptions
