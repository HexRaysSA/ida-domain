# Testing Guidelines for IDA Domain

## Assertion Quality Standards

### ✅ GOOD: Verify Behavior

```python
# Test actual state change
result = db.bytes.set_operand_hex(ea, 0)
assert result is True

# Verify the formatting actually changed
operand_text = _get_operand_text(db, ea, 0)
assert '0x' in operand_text.lower() or any(c in 'abcdefABCDEF' for c in operand_text)
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
assert True
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

### Pattern 4: Content Validation

For export/generation methods, verify the content:

```python
# Don't just check file exists
assert os.path.exists(output_path)
assert os.path.getsize(output_path) > 0

# Verify actual content
with open(output_path, 'r') as f:
    content = f.read()
assert 'expected_pattern' in content
```

## Common Mistakes

### 1. Testing Existence Instead of Behavior

**Bad:**
```python
assert hasattr(obj, 'method')
assert callable(obj.method)
```

**Good:**
```python
# Call the method and verify the result
result = obj.method(args)
assert result == expected_value
```

### 2. Accepting "Either" Result

**Bad:**
```python
assert result is None or isinstance(result, int)
```

**Good:**
```python
# Be specific about what's expected
if should_find_result:
    assert isinstance(result, int)
    assert result > 0
else:
    assert result is None
```

### 3. Not Verifying File Contents

**Bad:**
```python
assert os.path.exists(file) and os.path.getsize(file) > 0
```

**Good:**
```python
assert os.path.exists(file)
with open(file, 'r') as f:
    content = f.read()
# Verify structure/format
assert re.search(r'expected_pattern', content)
```

### 4. Skipping Instead of Failing

**Bad:**
```python
if not can_create():
    pytest.skip('Cannot create')
# This might hide real bugs
```

**Consider:**
- Is this a test failure rather than skip?
- Should the test verify why creation failed?

## Parametrized Tests

Use `@pytest.mark.parametrize` for repetitive tests:

**Bad:**
```python
def test_method1_validates_address(self):
    with pytest.raises(InvalidEAError):
        obj.method1(invalid_addr)

def test_method2_validates_address(self):
    with pytest.raises(InvalidEAError):
        obj.method2(invalid_addr)
```

**Good:**
```python
@pytest.mark.parametrize("method_name,args", [
    ("method1", (invalid_addr,)),
    ("method2", (invalid_addr,)),
])
def test_methods_validate_addresses(self, method_name, args):
    method = getattr(obj, method_name)
    with pytest.raises(InvalidEAError):
        method(*args)
```

## Search/Iterator Tests

Verify results match search criteria:

```python
# BAD: Only checks type
result = db.search.next_code(start_ea)
assert isinstance(result, int)

# GOOD: Verifies it's actually code
result = db.search.next_code(start_ea)
assert result is not None
assert db.bytes.is_code_at(result)
assert result >= start_ea
```

## Analysis/Mutation Tests

Verify state changes occurred:

```python
# BAD: Only checks method completes
db.analysis.analyze(start_ea, end_ea)
db.analysis.wait()

# GOOD: Verifies analysis actually happened
defined_before = count_defined_items(start_ea, end_ea)
db.analysis.analyze(start_ea, end_ea)
db.analysis.wait()
defined_after = count_defined_items(start_ea, end_ea)
assert defined_after >= defined_before
```

## Model Tests

Reference these for examples:

- `tests/test_search.py::test_next_code_finds_instruction` - Behavioral verification
- `tests/test_exporter.py::test_export_bytes_creates_binary_file` - Round-trip validation
- `tests/test_bytes.py::TestBytesItemNavigation::test_item_navigation_methods_validate_addresses` - Parametrized error tests

## Test Organization

### Test Structure

```python
def test_descriptive_name(test_fixture):
    """
    One-line summary of what is tested.

    RATIONALE: Why this test matters and what it validates.
    Include context about edge cases or design decisions.
    """
    # Arrange: Set up test conditions
    initial_state = setup_test_data()

    # Act: Perform the operation
    result = perform_operation()

    # Assert: Verify behavior, not just types
    assert_behavior_correct(result)
```

### RATIONALE Comments

All tests should include a RATIONALE explaining:
- Why the test exists
- What behavior it validates
- What would break if this test failed

## Coverage vs Quality

**Coverage** = Tests exist for all methods ✅
**Quality** = Tests verify actual behavior ✅✅

Prioritize quality over coverage. One test that verifies behavior is better than five tests that only check types.

## Checklist for New Tests

- [ ] Test has clear, descriptive name
- [ ] Docstring includes RATIONALE
- [ ] Assertions verify behavior, not just types
- [ ] State changes are verified with before/after checks
- [ ] No tautological assertions (always true/false)
- [ ] No meaningless assertions (`assert True`, `len >= 0`)
- [ ] File operations verify content, not just existence
- [ ] Search operations verify results match criteria
- [ ] Consider parametrization for repetitive patterns
