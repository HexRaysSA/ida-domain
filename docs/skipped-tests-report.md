# Skipped Tests Report

## Overview

This report provides a comprehensive analysis of all skipped tests in the ida-domain test suite, categorizing them by reason and providing guidance on when they execute.

## Executive Summary

The test suite contains approximately **100+ skip conditions** distributed across multiple test files. These skips fall into five main categories:

- **Setup-dependent skips**: 11 tests requiring pre-generated databases or test binaries
- **License-dependent skips**: 6 tests requiring the Hex-Rays decompiler plugin
- **Dynamic content skips**: 80+ tests that skip when database lacks specific characteristics
- **Known API issues**: 3 tests permanently skipped due to IDA API limitations in test environments

## Skip Categories

### 1. Missing Pre-Analyzed Databases

Several test files require IDB files that have been pre-analyzed by IDA to create specific structures (switches, try blocks, stack frames, types, imports).

**Affected Tests:**
- `tests/test_switches.py:42`
- `tests/test_try_blocks.py:50`
- `tests/test_stack_frames.py:65`
- `tests/test_types.py:50`
- `tests/test_imports.py:36`

**Skip Message:**
```
Pre-analyzed database not found. Run: python tests/resources/create_idbs.py
```

**Resolution:**
Run the database creation script before executing these tests:
```bash
python tests/resources/create_idbs.py
```

### 2. Missing Test Binaries

These tests require binary files that may not be present in the test environment.

**Affected Tests:**
- `tests/test_exporter.py:33`
- `tests/test_decompiler.py:32`
- `tests/test_search.py:37`
- `tests/test_problems.py:34`
- `tests/test_analysis.py:35`
- `tests/test_fixups.py:36`

**Skip Message:**
```
Test binary not found
```

**Resolution:**
Ensure test binaries are present in the expected test resources directory.

### 3. Hex-Rays Decompiler Not Available

Multiple tests require the commercial Hex-Rays decompiler plugin.

**Affected Tests:**
- `tests/test_decompiler.py:98` - `test_decompile_returns_pseudocode_for_valid_address`
- `tests/test_decompiler.py:134` - `test_decompile_with_options_respects_flags`
- `tests/test_decompiler.py:168` - `test_get_decompiled_line_returns_line_for_valid_address`
- `tests/test_decompiler.py:189` - `test_get_variable_at_returns_variable_info`
- `tests/test_decompiler.py:257` - `test_rename_variable_changes_variable_name_in_pseudocode`
- `tests/test_decompiler.py:295` - `test_set_variable_type_changes_variable_type_in_pseudocode`

**Skip Message:**
```
Hex-Rays decompiler not available
```

**Resolution:**
This requires a valid Hex-Rays decompiler license and installation. These tests will remain skipped in environments without the decompiler.

### 4. Dynamic Database Content Checks

The majority of skips are **intentional and by design**. Tests check if the database contains the specific characteristics needed for testing and gracefully skip if not found. This makes the test suite resilient across different binaries and architectures.

#### test_names.py (15 dynamic skips)
Tests skip when:
- No names exist in database
- Not enough names for comparison tests
- Address space too small
- No named functions found
- Cannot find unnamed addresses for testing

**Example locations:** Lines 70, 106, 138, 185, 210, 311, 334, 362, 540, 563, 590, 632, 665, 700, 740, 790

#### test_bytes.py (18 dynamic skips)
Tests skip when:
- Test addresses not mapped in database
- Cannot create data types at test addresses
- Cannot find instructions with specific operand types (hex/decimal/character formattable)
- No code found in database
- Cannot find suitable data addresses
- Insufficient functions for pattern/range tests
- No suitable strings found

**Example locations:** Lines 87, 92, 152, 169, 358, 409, 454, 495, 547, 583, 629, 670, 995, 1029, 1244

#### test_instructions.py (30+ dynamic skips)
Tests skip when:
- Test addresses not available
- Cannot find invalid opcode sequences
- No suitable immediate operands found
- Cannot convert operands to offsets
- No segments found
- No register operands found
- No call/return instructions found
- Insufficient sequential instructions

**Example locations:** Lines 83, 108, 158, 228, 269, 306, 341, 426, 437, 501, 518, 600, 607, 617, 679, 749, 756, 764, 838, 845, 853, 862, 942, 949, 1032, 1077, 1215, 1261, 1469, 1471, 1536, 1585, 1592

#### test_decompiler.py (3 dynamic skips)
Tests skip when:
- Cannot find addresses without functions
- Cannot find suitable functions for testing

**Example locations:** Lines 213, 278

#### test_functions.py (4 dynamic skips)
Tests skip when:
- Need at least one function but none exists
- Test address not valid
- Test address already has a function
- Cannot create test function

**Example locations:** Lines 240, 248, 250, 255

#### test_xrefs.py (15 dynamic skips)
Tests skip when:
- No functions with callers found
- Cannot find multi-byte instructions
- No call instructions found
- No data with references found
- No functions with multiple callers
- No functions with code references found

**Example locations:** Lines 70, 100, 137, 192, 215, 263, 315, 351, 388, 443, 530, 557, 619, 651, 674, 698, 758

#### test_switches.py (3 dynamic skips)
Tests skip when:
- Cannot find valid test addresses
- Cannot find valid addresses for parent tests

**Example locations:** Lines 175, 415, 456

#### test_stack_frames.py (3 dynamic skips)
Tests skip when:
- `many_arguments` function not found
- Function has no stack frame
- All functions have stack frames (cannot test frameless functions)

**Example locations:** Lines 471, 476, 1410

#### test_analysis.py (1 dynamic skip)
Tests skip when:
- Test range not valid in binary

**Example location:** Line 118

#### test_fixups.py (1 dynamic skip)
Tests skip when:
- Test address already has a fixup

**Example location:** Line 433

### 5. Known IDA API Issues

Three tests are **permanently skipped** due to known bugs in IDA's API when used in automated test environments. These methods work correctly in real IDA usage but fail in test scenarios.

#### test_rename_variable_changes_variable_name
**Location:** `tests/test_stack_frames.py:784-787`

**Skip Reason:**
```
Known IDA API issue: define_stkvar doesn't rename existing variables reliably on test binaries
```

**Description:**
The `define_stkvar` API doesn't reliably rename existing stack variables when called from automated tests, though it works correctly in interactive IDA usage.

#### test_delete_variable_removes_variable
**Location:** `tests/test_stack_frames.py:926-929`

**Skip Reason:**
```
Known IDA API issue: delete_frame_members doesn't reliably delete dynamically created variables on test binaries
```

**Description:**
The `delete_frame_members` API doesn't reliably delete dynamically created variables in test environments, though it works in real usage.

#### test_delete_variables_in_range_removes_multiple_variables
**Location:** `tests/test_stack_frames.py:992-995`

**Skip Reason:**
```
Known IDA API issue: delete_frame_members doesn't reliably delete dynamically created variables on test binaries
```

**Description:**
Same API limitation as above, affecting bulk deletion of variables in a range.

## Design Philosophy

The extensive use of dynamic skips in categories 4 is **intentional and represents good testing practice**:

1. **Resilience**: Tests work across different binaries, architectures, and analysis states
2. **Graceful degradation**: Tests skip rather than fail when prerequisites aren't met
3. **No false positives**: Skips prevent meaningless test failures that don't indicate actual bugs
4. **Binary independence**: Tests adapt to whatever characteristics the test binary happens to have

This approach ensures the test suite remains stable and meaningful across diverse testing scenarios.

## Recommendations

### For Test Execution

1. **Full test coverage**: Run `python tests/resources/create_idbs.py` before testing to minimize setup-related skips
2. **Monitor skip counts**: Use `pytest --verbose` to see which tests skip and why
3. **Binary selection**: Choose feature-rich test binaries to maximize test execution
4. **License awareness**: Accept that Hex-Rays tests will skip without the decompiler license

### For Test Development

1. **Continue defensive skipping**: Maintain the pattern of checking prerequisites and skipping gracefully
2. **Document known issues**: Clearly mark permanently skipped tests with detailed explanations
3. **Avoid false assumptions**: Don't assume specific binary characteristics will always be present
4. **Test early**: Add skip conditions at the start of tests to fail fast

## Statistics

| Category | Count | Percentage |
|----------|-------|------------|
| Dynamic content checks | ~80 | ~80% |
| Setup-dependent | 11 | ~11% |
| License-dependent | 6 | ~6% |
| Known API issues | 3 | ~3% |
| **Total** | **~100** | **100%** |

## Conclusion

The ida-domain test suite's skip patterns reflect a mature, defensive testing strategy that prioritizes stability and meaningful results over raw test counts. The high number of dynamic skips is not a weakness but a strength, ensuring tests remain reliable across diverse execution environments and binary characteristics.
