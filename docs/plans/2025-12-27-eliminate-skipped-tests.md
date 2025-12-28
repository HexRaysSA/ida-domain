# Eliminate Skipped Tests Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce skipped tests from 16 to 3 (only known IDA API issues remain)

**Architecture:** Modify tests to be self-sufficient by creating required test data dynamically, improving address discovery logic, and using richer test fixtures where needed. The 3 tests with known IDA API issues will remain skipped with clear documentation.

**Tech Stack:** pytest, IDA Python API, ida-domain library

**Current State:**
- Total tests: 463
- Passing: 447
- Skipping: 16
  - 3 are permanent (IDA API bugs)
  - 13 can be fixed (dynamic content checks)

**Target State:**
- Total tests: 463
- Passing: 460
- Skipping: 3 (documented as permanent)

---

## Task 1: Fix test_analysis.py Dynamic Skip (1 test)

**Files:**
- Modify: `tests/test_analysis.py:110-119`

**Issue:** Test skips when calculated address range (minimum_ea + 0x1000 to +0x1100) is not valid in the small test binary.

**Step 1: Read current test code**

```bash
# Read the test to understand current logic
```

**Step 2: Modify test to use actual binary bounds**

Replace fixed offset calculation with dynamic range selection:

```python
# OLD CODE (around line 113-118):
start_ea = analysis_db.minimum_ea + 0x1000
end_ea = min(start_ea + 0x100, analysis_db.maximum_ea)

if not analysis_db.is_valid_ea(start_ea) or not analysis_db.is_valid_ea(end_ea - 1):
    pytest.skip('Test range not valid in this binary')

# NEW CODE:
# Use a range that definitely exists in any binary
start_ea = analysis_db.minimum_ea
# Use first 0x100 bytes or less if binary is smaller
range_size = min(0x100, (analysis_db.maximum_ea - analysis_db.minimum_ea) // 2)
end_ea = start_ea + range_size

# This should never skip now since we're using actual bounds
assert analysis_db.is_valid_ea(start_ea), 'minimum_ea should always be valid'
assert analysis_db.is_valid_ea(end_ea - 1), 'calculated end_ea should be valid'
```

**Step 3: Run test to verify it passes**

```bash
uv run pytest tests/test_analysis.py::test_analyze_method_is_alias_for_analyze_range -v
```

Expected: PASS

**Step 4: Commit**

```bash
git add tests/test_analysis.py
git commit -m "fix(tests): eliminate skip in test_analyze_method_is_alias_for_analyze_range

Use actual binary bounds instead of fixed offsets to ensure test range
is always valid, preventing unnecessary skips on small test binaries."
```

---

## Task 2: Fix test_bytes.py Item Size Skip (1 test)

**Files:**
- Modify: `tests/test_bytes.py:80-93`

**Issue:** Test skips when test_env.minimum_ea + 0x100 is not mapped or can't create dword.

**Step 1: Read current test implementation**

```bash
# Examine test_get_item_size_at_returns_correct_size
```

**Step 2: Improve address selection logic**

Replace fixed offset with robust address finding:

```python
# OLD CODE (around line 83-92):
test_addr = test_env.minimum_ea + 0x100

if not test_env.is_valid_ea(test_addr):
    pytest.skip('Test address not mapped in database')

success = test_env.bytes.create_dword_at(test_addr, count=1, force=True)
if not success:
    pytest.skip('Could not create dword at test address')

# NEW CODE:
# Find first valid address with enough space for a dword (4 bytes)
test_addr = None
for offset in [0x100, 0x200, 0x50, 0x20, 0x10, 0]:
    candidate = test_env.minimum_ea + offset
    if test_env.is_valid_ea(candidate) and test_env.is_valid_ea(candidate + 3):
        test_addr = candidate
        break

assert test_addr is not None, 'Should find valid address in any binary'

# Force create dword - this should succeed since we verified the range
success = test_env.bytes.create_dword_at(test_addr, count=1, force=True)
assert success, f'create_dword_at should succeed at validated address 0x{test_addr:x}'
```

**Step 3: Run test**

```bash
uv run pytest tests/test_bytes.py::TestBytesItemNavigation::test_get_item_size_at_returns_correct_size -v
```

Expected: PASS

**Step 4: Commit**

```bash
git add tests/test_bytes.py
git commit -m "fix(tests): eliminate skip in test_get_item_size_at_returns_correct_size

Improve address selection to try multiple offsets and validate ranges,
ensuring test can always find suitable address for dword creation."
```

---

## Task 3: Fix test_bytes.py Decimal Operand Skip (1 test)

**Files:**
- Modify: `tests/test_bytes.py:400-410`

**Issue:** Test skips when it can't find instruction with decimal-formattable operand.

**Step 1: Analyze current operand search logic**

```bash
# Read the test and understand search pattern
```

**Step 2: Expand search to be more thorough**

```python
# OLD CODE (around line 401-409):
found_addr = None
for func in test_env.functions.get_all():
    for head in test_env.bytes.iterate_heads(func.start_ea, func.end_ea):
        if test_env.instructions.can_decode(head):
            # Try to format as decimal
            if test_env.bytes.set_operand_decimal(head, 0):
                found_addr = head
                break
    if found_addr:
        break

if found_addr is None:
    pytest.skip('Could not find instruction with decimal-formattable operand')

# NEW CODE:
found_addr = None
# Search more thoroughly - try all instructions, all operands
for func in test_env.functions.get_all():
    for head in test_env.bytes.iterate_heads(func.start_ea, func.end_ea):
        if test_env.instructions.can_decode(head):
            # Try all operands (0-5)
            for op_num in range(6):
                try:
                    if test_env.bytes.set_operand_decimal(head, op_num):
                        found_addr = head
                        break
                except:
                    continue
        if found_addr:
            break
    if found_addr:
        break

# If still not found, create a simple instruction with immediate
if found_addr is None:
    # Find first function and create test data there
    funcs = list(test_env.functions.get_all())
    if funcs:
        # Use end of first function as safe area
        test_addr = funcs[0].end_ea - 0x10
        if test_env.is_valid_ea(test_addr):
            # Create instruction (this will be architecture-dependent but IDA will handle it)
            test_env.instructions.create_at(test_addr)
            if test_env.instructions.can_decode(test_addr):
                found_addr = test_addr

assert found_addr is not None, 'Should find or create instruction with formattable operand'
```

**Step 3: Run test**

```bash
uv run pytest tests/test_bytes.py::TestBytesOperandManipulation::test_set_operand_decimal_changes_display_representation -v
```

Expected: PASS

**Step 4: Commit**

```bash
git add tests/test_bytes.py
git commit -m "fix(tests): eliminate skip in test_set_operand_decimal

Search all operands (not just operand 0) and create test instruction
if needed, ensuring test always has suitable operand to format."
```

---

## Task 4: Fix test_bytes.py String Search Skip (1 test)

**Files:**
- Modify: `tests/test_bytes.py:1235-1244`

**Issue:** Test skips when no suitable string found in binary.

**Step 1: Review string search test**

```bash
# Read test_find_text_between_finds_existing_string
```

**Step 2: Create test string if not found**

```python
# OLD CODE (around line 1235-1244):
# [existing search logic]
if result:
    assert db.is_valid_ea(result), f'Result 0x{result:x} should be a valid address'
else:
    pytest.skip('No suitable string found in binary to test with')

# NEW CODE:
# [keep existing search logic]
if not result:
    # Create a test string in a safe location
    # Find unused space in database
    test_addr = db.minimum_ea + 0x1000

    # Find actually valid address
    while not db.is_valid_ea(test_addr) and test_addr < db.maximum_ea:
        test_addr += 0x100

    if db.is_valid_ea(test_addr):
        # Create a simple string "TEST" at this location
        test_string = b"TEST\x00"
        for i, byte in enumerate(test_string):
            db.bytes.patch_byte(test_addr + i, byte)

        # Now search for it
        result = db.bytes.find_text_between(
            "TEST",
            db.minimum_ea,
            db.maximum_ea,
            flags=0
        )

assert result is not None, 'Should find existing or created string'
assert db.is_valid_ea(result), f'Result 0x{result:x} should be a valid address'
```

**Step 3: Run test**

```bash
uv run pytest tests/test_bytes.py::TestBytesSearchMethods::test_find_text_between_finds_existing_string -v
```

Expected: PASS

**Step 4: Commit**

```bash
git add tests/test_bytes.py
git commit -m "fix(tests): eliminate skip in test_find_text_between

Create test string data if not found in binary, ensuring test
can always validate text search functionality."
```

---

## Task 5: Fix test_functions.py Delete Function Skip (1 test)

**Files:**
- Modify: `tests/test_functions.py:234-255`

**Issue:** Test skips when it can't create a test function for deletion.

**Step 1: Read function deletion test**

```bash
# Review test_functions_delete_is_alias_for_remove
```

**Step 2: Improve function creation logic**

```python
# OLD CODE (around line 240-255):
all_funcs = list(test_env.functions.get_all())
if len(all_funcs) == 0:
    pytest.skip('Need at least one function for testing')

last_func = all_funcs[-1]
test_ea = last_func.end_ea + 0x10

if not test_env.is_valid_ea(test_ea):
    pytest.skip('Test address not valid')
if test_env.functions.exists_at(test_ea):
    pytest.skip('Test address already has function')

created = test_env.functions.create(test_ea)
if not created:
    pytest.skip('Could not create test function')

# NEW CODE:
all_funcs = list(test_env.functions.get_all())
assert len(all_funcs) > 0, 'Test binary should have at least one function'

# Try multiple addresses after last function
last_func = all_funcs[-1]
test_ea = None
created = False

for offset in [0x10, 0x20, 0x40, 0x4, 0x8]:
    candidate = last_func.end_ea + offset
    if (test_env.is_valid_ea(candidate) and
        not test_env.functions.exists_at(candidate)):
        # Try to create code first to make function creation more likely
        test_env.bytes.create_byte_at(candidate, force=True)
        created = test_env.functions.create(candidate)
        if created:
            test_ea = candidate
            break

assert created and test_ea is not None, (
    'Should be able to create function for deletion test'
)
```

**Step 3: Run test**

```bash
uv run pytest tests/test_functions.py::TestFunctionsDelete::test_functions_delete_is_alias_for_remove -v
```

Expected: PASS

**Step 4: Commit**

```bash
git add tests/test_functions.py
git commit -m "fix(tests): eliminate skip in test_functions_delete

Try multiple offsets for function creation and prepare addresses
with byte data to increase success rate."
```

---

## Task 6: Fix test_instructions.py Address Validation Skips (6 tests)

**Files:**
- Modify: `tests/test_instructions.py:75-310`

**Issue:** Multiple tests skip when fixed address offsets don't exist in small binaries.

**Step 1: Read affected tests**

```bash
# Review all instruction validation tests that use minimum_ea + fixed offset
```

**Step 2: Create helper function for finding valid test addresses**

Add at top of TestInstructionValidation class:

```python
def _find_valid_test_address(self, test_env, size_needed=4, avoid_code=False):
    """
    Helper to find a valid address for testing.

    Args:
        test_env: Test environment
        size_needed: Bytes needed at address
        avoid_code: If True, prefer non-code areas

    Returns:
        Valid address or raises assertion
    """
    # Try multiple strategies
    candidates = [
        test_env.minimum_ea + 0x100,
        test_env.minimum_ea + 0x200,
        test_env.minimum_ea + 0x50,
        test_env.minimum_ea,
        test_env.maximum_ea - size_needed - 0x100,
    ]

    for candidate in candidates:
        # Check if address and required range are valid
        if not test_env.is_valid_ea(candidate):
            continue
        if not test_env.is_valid_ea(candidate + size_needed - 1):
            continue

        # If avoiding code, skip instruction addresses
        if avoid_code and test_env.instructions.can_decode(candidate):
            continue

        return candidate

    # Should always find something
    raise AssertionError(
        f'Could not find valid address with {size_needed} bytes. '
        f'Binary range: 0x{test_env.minimum_ea:x}-0x{test_env.maximum_ea:x}'
    )
```

**Step 3: Update all affected tests to use helper**

```python
# For test_can_decode_with_data_address_returns_false (line 75):
def test_can_decode_with_data_address_returns_false(self, test_env):
    """Test can_decode returns False for data addresses."""
    test_addr = self._find_valid_test_address(test_env, avoid_code=True)

    # Ensure this is data, not code
    test_env.bytes.create_dword_at(test_addr, count=1, force=True)

    assert not test_env.instructions.can_decode(test_addr), (
        f'can_decode should return False for data address at 0x{test_addr:x}'
    )

# Similar pattern for:
# - test_can_decode_with_undefined_bytes_returns_false
# - test_create_at_converts_undefined_bytes_to_instruction
# - test_create_at_with_data_creates_instruction_if_valid
# - test_create_at_with_invalid_opcodes_returns_false
# - test_create_at_and_validate_round_trip
```

**Step 4: Run all affected instruction tests**

```bash
uv run pytest tests/test_instructions.py::TestInstructionValidation -v
uv run pytest tests/test_instructions.py::TestInstructionCreation -v
```

Expected: All PASS

**Step 5: Commit**

```bash
git add tests/test_instructions.py
git commit -m "fix(tests): eliminate 6 skips in instruction validation/creation tests

Add helper function to robustly find valid test addresses using
multiple strategies, ensuring tests work on binaries of any size."
```

---

## Task 7: Fix test_instructions.py Data Reference Skip (1 test)

**Files:**
- Modify: `tests/test_instructions.py:1300-1350` (approximate location)

**Issue:** Test skips when it can't find suitable address for data reference testing.

**Step 1: Locate and read the test**

```bash
# Find test_add_data_reference_with_different_reference_types
```

**Step 2: Modify to create test data if needed**

```python
# PATTERN:
# 1. Try to find existing suitable address
# 2. If not found, create one
# 3. Assert that we have valid address (never skip)

def test_add_data_reference_with_different_reference_types(self, test_env_mutable):
    """Test adding data references with different reference types."""
    test_env = test_env_mutable

    # Find or create code address
    code_addr = None
    for func in test_env.functions.get_all():
        for head in test_env.bytes.iterate_heads(func.start_ea, func.end_ea):
            if test_env.instructions.can_decode(head):
                code_addr = head
                break
        if code_addr:
            break

    if not code_addr:
        # Create instruction at safe address
        code_addr = self._find_valid_test_address(test_env)
        test_env.instructions.create_at(code_addr)

    # Find or create data address
    data_addr = self._find_valid_test_address(test_env, avoid_code=True)
    test_env.bytes.create_dword_at(data_addr, force=True)

    assert code_addr is not None, 'Should have code address'
    assert data_addr is not None, 'Should have data address'

    # Rest of test logic...
```

**Step 3: Run test**

```bash
uv run pytest tests/test_instructions.py::TestCrossReferenceManagement::test_add_data_reference_with_different_reference_types -v
```

Expected: PASS

**Step 4: Commit**

```bash
git add tests/test_instructions.py
git commit -m "fix(tests): eliminate skip in test_add_data_reference

Create necessary code and data addresses if not found,
ensuring data reference test can always execute."
```

---

## Task 8: Fix test_xrefs.py Data Reference Skip (1 test)

**Files:**
- Modify: `tests/test_xrefs.py` (locate test_has_code_refs_to_for_data_address)

**Issue:** Test skips when it can't find data with code references.

**Step 1: Find the test**

```bash
# Locate test_has_code_refs_to_for_data_address
```

**Step 2: Modify to create test scenario**

```python
def test_has_code_refs_to_for_data_address(self, test_env_mutable):
    """Test has_code_refs_to for data addresses."""
    test_env = test_env_mutable

    # Find instruction and data addresses
    instr_addr = None
    for func in test_env.functions.get_all():
        for head in test_env.bytes.iterate_heads(func.start_ea, func.end_ea):
            if test_env.instructions.can_decode(head):
                instr_addr = head
                break
        if instr_addr:
            break

    # Create data if needed
    if not instr_addr:
        # Need at least one instruction - use first function's start
        funcs = list(test_env.functions.get_all())
        assert len(funcs) > 0, 'Binary should have functions'
        instr_addr = funcs[0].start_ea

    # Find data area
    data_addr = test_env.minimum_ea + 0x2000
    if not test_env.is_valid_ea(data_addr):
        data_addr = test_env.maximum_ea - 0x100

    # Create data and reference
    test_env.bytes.create_dword_at(data_addr, force=True)
    test_env.instructions.add_data_reference(instr_addr, data_addr)

    # Test has_code_refs_to
    result = test_env.xrefs.has_code_refs_to(data_addr)
    assert result is True, f'Data at 0x{data_addr:x} should have code references'
```

**Step 3: Run test**

```bash
uv run pytest tests/test_xrefs.py::TestXrefExistence::test_has_code_refs_to_for_data_address -v
```

Expected: PASS

**Step 4: Commit**

```bash
git add tests/test_xrefs.py
git commit -m "fix(tests): eliminate skip in test_has_code_refs_to_for_data_address

Create data address and add code reference to it, ensuring
test scenario always exists."
```

---

## Task 9: Document Permanent Skips (3 tests)

**Files:**
- Modify: `tests/test_stack_frames.py:784-1012`
- Modify: `docs/skipped-tests-report.md`

**Issue:** Three tests are permanently skipped due to known IDA API bugs. Ensure they're well-documented.

**Step 1: Verify skip decorators are present and descriptive**

```bash
# Read the three skip decorators to ensure good documentation
```

**Step 2: Add comment above each skipped test**

```python
# AROUND LINE 784:
# NOTE: This test is permanently skipped due to a known limitation in IDA's API
# when used in automated test environments. The define_stkvar API does not
# reliably rename variables created dynamically in test scenarios, though it
# works correctly in interactive IDA usage. This is not a bug in ida-domain,
# but rather a limitation of the underlying IDA SDK in headless mode.
@pytest.mark.skip(
    reason="Known IDA API issue: define_stkvar doesn't rename existing "
    'variables reliably on test binaries'
)
def test_rename_variable_changes_variable_name(self, db_mutable):
    # ... rest of test
```

Repeat for the other two tests.

**Step 3: Update the skipped tests report**

```bash
# Edit docs/skipped-tests-report.md to update statistics and conclusion
```

Update conclusion section:

```markdown
## Conclusion (Updated 2025-12-27)

After optimization work, the ida-domain test suite now has minimal skips:

- **460 tests passing** (99.4% pass rate)
- **3 tests skipped** (0.6% skip rate) - all due to known IDA API limitations

The three remaining skips are permanent and documented. They are not bugs in
ida-domain but rather limitations in IDA's headless API behavior. The affected
functionality (stack variable renaming and deletion) works correctly in
interactive IDA usage.

All dynamic content checks have been eliminated by making tests self-sufficient:
- Tests now create required test data dynamically when not found
- Address selection logic uses multiple fallback strategies
- Tests validate conditions and assert rather than skip

This ensures consistent test results across different test binaries and
environments while maintaining test reliability and meaningful failure detection.
```

**Step 4: Run all tests to verify final state**

```bash
uv run pytest tests/ -v --tb=no 2>&1 | tail -20
```

Expected: 460 passed, 3 skipped

**Step 5: Commit**

```bash
git add tests/test_stack_frames.py docs/skipped-tests-report.md
git commit -m "docs: clarify permanent skips and update skip statistics

Add detailed comments explaining why 3 tests remain skipped due to
IDA API limitations. Update report to reflect 99.4% pass rate after
eliminating all addressable skips."
```

---

## Task 10: Verification and Final Report

**Files:**
- Create: `docs/skipped-tests-elimination-report.md`

**Step 1: Run full test suite**

```bash
uv run pytest tests/ -v --tb=short > /tmp/test-results.txt 2>&1
```

**Step 2: Generate statistics**

```bash
uv run pytest tests/ --co -q 2>&1 | wc -l  # Total tests
uv run pytest tests/ -v --tb=no 2>&1 | grep "passed"  # Pass count
uv run pytest tests/ -v --tb=no 2>&1 | grep "skipped"  # Skip count
```

**Step 3: Create final report**

```markdown
# Skipped Tests Elimination Report

**Date:** 2025-12-27

## Objective
Eliminate all addressable skipped tests, reducing skip count from 16 to 3.

## Results

### Before
- Total tests: 463
- Passing: 447 (96.5%)
- Skipping: 16 (3.5%)

### After
- Total tests: 463
- Passing: 460 (99.4%)
- Skipping: 3 (0.6%)

### Improvement
- **13 tests fixed** (81% reduction in skips)
- **99.4% pass rate** achieved
- Only permanent IDA API limitation skips remain

## Tests Fixed

1. ✓ test_analysis.py::test_analyze_method_is_alias_for_analyze_range
2. ✓ test_bytes.py::TestBytesItemNavigation::test_get_item_size_at_returns_correct_size
3. ✓ test_bytes.py::TestBytesOperandManipulation::test_set_operand_decimal_changes_display_representation
4. ✓ test_bytes.py::TestBytesSearchMethods::test_find_text_between_finds_existing_string
5. ✓ test_functions.py::TestFunctionsDelete::test_functions_delete_is_alias_for_remove
6. ✓ test_instructions.py::TestInstructionValidation::test_can_decode_with_data_address_returns_false
7. ✓ test_instructions.py::TestInstructionValidation::test_can_decode_with_undefined_bytes_returns_false
8. ✓ test_instructions.py::TestInstructionCreation::test_create_at_converts_undefined_bytes_to_instruction
9. ✓ test_instructions.py::TestInstructionCreation::test_create_at_with_data_creates_instruction_if_valid
10. ✓ test_instructions.py::TestInstructionCreation::test_create_at_with_invalid_opcodes_returns_false
11. ✓ test_instructions.py::TestInstructionCreation::test_create_at_and_validate_round_trip
12. ✓ test_instructions.py::TestCrossReferenceManagement::test_add_data_reference_with_different_reference_types
13. ✓ test_xrefs.py::TestXrefExistence::test_has_code_refs_to_for_data_address

## Permanent Skips (Documented)

These 3 tests remain skipped due to known IDA SDK limitations:

1. test_stack_frames.py::test_rename_variable_changes_variable_name
2. test_stack_frames.py::test_delete_variable_removes_variable
3. test_stack_frames.py::test_delete_variables_in_range_removes_multiple_variables

**Reason:** IDA's define_stkvar and delete_frame_members APIs do not work reliably in headless/automated environments, though they function correctly in interactive usage.

## Techniques Used

### 1. Dynamic Address Selection
- Replaced fixed offsets with multiple fallback strategies
- Validated address ranges before use
- Asserted instead of skipping when addresses should exist

### 2. Self-Sufficient Tests
- Tests create required data dynamically when not found
- Prepared memory/code structures as needed
- Made tests independent of specific binary characteristics

### 3. Robust Search Logic
- Extended search loops to try all operands, not just first
- Created test scenarios when natural ones not found
- Used helper functions for common address-finding patterns

## Impact

- **Reliability:** Tests now run consistently across different binaries
- **Coverage:** 99.4% of tests execute and validate functionality
- **Maintainability:** Clear distinction between fixable and permanent skips
- **Confidence:** Higher test pass rate provides better CI/CD signal

## Recommendations

1. Monitor the 3 permanent skips - if IDA fixes the API issues, remove skip decorators
2. Apply similar self-sufficiency patterns to future tests
3. Consider creating a richer "comprehensive test binary" with all edge cases for performance testing
4. Document expected skip count (3) in CI configuration

## Conclusion

Successfully reduced skipped tests by 81% while maintaining test quality and
reliability. The remaining 3 skips are properly documented permanent limitations
beyond ida-domain's control. The test suite now provides excellent coverage
with a 99.4% pass rate.
```

**Step 4: Save report**

```bash
# File created above
```

**Step 5: Final commit**

```bash
git add docs/skipped-tests-elimination-report.md
git commit -m "docs: add skipped tests elimination report

Document successful reduction of skips from 16 to 3 (81% improvement),
achieving 99.4% test pass rate with only permanent IDA API limitations
remaining."
```

---

## Summary

This plan systematically eliminates 13 out of 16 skipped tests by:

1. **Making tests self-sufficient** - creating required data instead of skipping
2. **Improving address selection** - using multiple fallback strategies
3. **Robust error handling** - asserting on expected conditions rather than skipping
4. **Clear documentation** - properly documenting the 3 permanent skips

**Expected outcome:** 460/463 tests passing (99.4%), with only 3 skipped due to documented IDA API limitations.

**Commits:** 10 focused commits, each fixing specific test category
**Testing:** Each task includes verification step
**Documentation:** Updates both inline and report documentation
