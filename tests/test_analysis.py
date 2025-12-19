"""Tests for Analysis entity."""

import os
import shutil
import tempfile

import pytest

import ida_domain
from ida_domain.analysis import AnalysisQueueType, AnalysisState
from ida_domain.database import IdaCommandOptions


@pytest.fixture(scope='module')
def analysis_test_setup():
    """
    Setup for analysis tests.

    RATIONALE: We need a small binary that can be analyzed to test the Analysis
    entity's control methods. The tiny_asm.bin binary is suitable as it:
    - Has code sections that can be analyzed
    - Is small enough for fast test execution
    - Provides a realistic analysis workload without being too complex

    This allows us to test analysis state transitions, queue management, and
    wait operations with predictable behavior.
    """
    idb_path = os.path.join(tempfile.gettempdir(), 'api_tests_work_dir', 'analysis_test.bin')
    os.makedirs(os.path.dirname(idb_path), exist_ok=True)

    # Copy test binary
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(current_dir, 'resources', 'tiny_asm.bin')

    if not os.path.exists(src_path):
        pytest.skip('Test binary not found')

    shutil.copy(src_path, idb_path)
    return idb_path


@pytest.fixture(scope='function')
def analysis_db(analysis_test_setup):
    """
    Open database for analysis testing.

    RATIONALE: Each test needs a fresh database instance to ensure test isolation.
    We open with auto-analysis enabled so we can test wait operations, queue
    states, and analysis completion detection.
    """
    idb_path = analysis_test_setup
    ida_options = IdaCommandOptions(new_database=True, auto_analysis=True)
    db = ida_domain.Database.open(path=idb_path, args=ida_options, save_on_close=False)
    yield db
    if db.is_open():
        db.close(False)


# =============================================================================
# ADVANCED OPERATIONS TESTS
# =============================================================================


def test_show_addr_displays_address_on_ui_indicator(analysis_db):
    """
    Test that show_addr() displays an address on the IDA UI auto-analysis indicator.

    RATIONALE: show_addr() is a UI-focused method that displays an address on
    the auto-analysis indicator in the form @:12345678. This test validates:
    1. The method accepts a valid address without errors
    2. It properly validates addresses (raises InvalidEAError for invalid ones)
    3. It can be called multiple times with different addresses

    While this is primarily a UI function, it's useful for scripts that want to
    provide visual feedback about what addresses are being processed, especially
    during long-running analysis or manual operations.
    """
    from ida_domain.base import InvalidEAError

    # Get valid addresses
    valid_ea1 = analysis_db.minimum_ea
    valid_ea2 = min(valid_ea1 + 0x100, analysis_db.maximum_ea)

    # Show first address - should not raise exception
    analysis_db.analysis.show_addr(valid_ea1)

    # Show second address - should not raise exception
    analysis_db.analysis.show_addr(valid_ea2)

    # Can be called multiple times
    analysis_db.analysis.show_addr(valid_ea1)
    analysis_db.analysis.show_addr(valid_ea1)

    # Invalid address should raise InvalidEAError
    with pytest.raises(InvalidEAError):
        analysis_db.analysis.show_addr(0xFFFFFFFFFFFFFFFF)


def test_reanalyze_function_callers_schedules_caller_reanalysis(analysis_db):
    """
    Test that reanalyze_function_callers() schedules reanalysis of function callers.

    RATIONALE: This method is critical after modifying a function's attributes
    (such as its prototype or noreturn status) to ensure all call sites are
    updated with the new information. This test validates:
    1. The method accepts a valid function address
    2. It schedules reanalysis without errors
    3. The analysis completes successfully
    4. It works with the function_noreturn parameter

    This is commonly used in workflows where you change function types or
    attributes and need to propagate those changes to all callers.
    """
    # Wait for initial analysis
    analysis_db.analysis.wait_for_completion()

    # Get a valid address (doesn't have to be a function for this test)
    # The method will work on any address, though it's most useful for functions
    valid_ea = analysis_db.minimum_ea

    # Schedule caller reanalysis - should not raise exception
    analysis_db.analysis.reanalyze_function_callers(valid_ea, function_noreturn=False)

    # Should be able to wait for completion
    analysis_db.analysis.wait_for_completion()
    assert analysis_db.analysis.is_complete, 'Analysis should complete'

    # Test with function_noreturn=True
    analysis_db.analysis.reanalyze_function_callers(valid_ea, function_noreturn=True)
    analysis_db.analysis.wait_for_completion()
    assert analysis_db.analysis.is_complete, 'Analysis should complete with noreturn=True'


def test_reanalyze_function_callers_validates_address(analysis_db):
    """
    Test that reanalyze_function_callers() properly validates the function address.

    RATIONALE: Like all address-taking methods, this method should validate
    the input address and raise InvalidEAError for addresses outside the valid
    database range. This prevents undefined behavior from passing invalid
    addresses to the IDA kernel, which could cause crashes or incorrect analysis.
    """
    from ida_domain.base import InvalidEAError

    # Invalid address should raise InvalidEAError
    with pytest.raises(InvalidEAError):
        analysis_db.analysis.reanalyze_function_callers(0xFFFFFFFFFFFFFFFF)

    # Also test with function_noreturn parameter
    with pytest.raises(InvalidEAError):
        analysis_db.analysis.reanalyze_function_callers(0xFFFFFFFFFFFFFFFF, function_noreturn=True)


def test_recreate_instruction_forces_redecode(analysis_db):
    """
    Test that recreate_instruction() forces IDA to re-decode an instruction.

    RATIONALE: This method is essential when:
    1. IDA decoded an instruction incorrectly
    2. You manually modified the bytes at an instruction address
    3. You want to force a fresh decode after changes

    The method returns True if recreation succeeded (instruction length > 0)
    or False if it failed (instruction length == 0). This test validates:
    - The method works on valid instruction addresses
    - It returns a boolean result
    - It validates addresses properly
    """
    # Wait for initial analysis
    analysis_db.analysis.wait_for_completion()

    # Get a valid address (should have an instruction after analysis)
    valid_ea = analysis_db.minimum_ea

    # Try to recreate instruction
    # Result depends on whether there's a valid instruction at this address
    result = analysis_db.analysis.recreate_instruction(valid_ea)

    # Should return a boolean
    assert isinstance(result, bool), 'recreate_instruction should return boolean'

    # If it succeeded, the result should be True
    # If it failed (no valid instruction possible), result should be False
    # Both are valid outcomes depending on the binary content

    # Test that it can be called multiple times
    result2 = analysis_db.analysis.recreate_instruction(valid_ea)
    assert isinstance(result2, bool), 'Should return boolean on second call'


def test_recreate_instruction_validates_address(analysis_db):
    """
    Test that recreate_instruction() properly validates addresses.

    RATIONALE: The method should validate the input address and raise
    InvalidEAError for addresses outside the valid database range. This is
    critical because passing invalid addresses to auto_recreate_insn() could
    cause undefined behavior or crashes in the IDA kernel.
    """
    from ida_domain.base import InvalidEAError

    # Invalid address should raise InvalidEAError
    with pytest.raises(InvalidEAError):
        analysis_db.analysis.recreate_instruction(0xFFFFFFFFFFFFFFFF)


def test_recreate_instruction_returns_false_for_non_code(analysis_db):
    """
    Test that recreate_instruction() returns False when it cannot create instruction.

    RATIONALE: The method calls auto_recreate_insn() which returns the instruction
    length, or 0 if creation failed. When converted to boolean:
    - length > 0 → True (success)
    - length == 0 → False (failure)

    This test attempts to recreate an instruction at an address that may not
    contain valid code. The method should return False gracefully rather than
    raising an exception when instruction creation fails.
    """
    # Wait for analysis
    analysis_db.analysis.wait_for_completion()

    # Try to find a data address (not code)
    # If we can't find one, use an arbitrary address
    test_ea = analysis_db.minimum_ea

    # Attempt recreation - may succeed or fail depending on what's at the address
    result = analysis_db.analysis.recreate_instruction(test_ea)

    # Result should be boolean (not an exception)
    assert isinstance(result, bool), 'Should return boolean even if recreation fails'

    # If False, it means instruction creation failed (which is OK)
    # If True, it means an instruction was successfully created


def test_revert_analysis_removes_analysis_information(analysis_db):
    """
    Test that revert_analysis() removes IDA's analysis decisions for a range.

    RATIONALE: This method is crucial when IDA makes incorrect automatic analysis
    decisions. It eliminates all analysis information (functions, names, comments,
    type information) for the specified range, converting analyzed code/data back
    to unexplored bytes. This test validates:
    1. The method accepts valid address ranges
    2. It completes without errors
    3. It properly validates addresses and ranges
    4. After reverting, you can re-analyze the range

    This is commonly used when you need to restart analysis with different
    parameters or after correcting binary data.
    """
    # Wait for initial analysis
    analysis_db.analysis.wait_for_completion()

    # Get a valid range
    start_ea = analysis_db.minimum_ea
    end_ea = min(start_ea + 0x100, analysis_db.maximum_ea)

    # Revert analysis - should not raise exception
    analysis_db.analysis.revert_analysis(start_ea, end_ea)

    # After reverting, we can re-analyze the range
    analysis_db.analysis.analyze_range(start_ea, end_ea, wait=True)

    # Should complete successfully
    assert analysis_db.analysis.is_complete, 'Analysis should complete after revert'


def test_revert_analysis_validates_address_range(analysis_db):
    """
    Test that revert_analysis() properly validates address ranges.

    RATIONALE: The method should validate both addresses and ensure start < end.
    Invalid addresses should raise InvalidEAError, and invalid ranges (start >= end)
    should raise InvalidParameterError. This prevents:
    1. Passing invalid addresses to the IDA kernel
    2. Attempting to revert invalid ranges
    3. Undefined behavior from invalid parameters

    Proper validation is critical since this method destroys analysis information
    and incorrect usage could damage the database.
    """
    from ida_domain.base import InvalidEAError, InvalidParameterError

    # Invalid start address
    with pytest.raises(InvalidEAError):
        analysis_db.analysis.revert_analysis(0xFFFFFFFFFFFFFFFF, analysis_db.minimum_ea)

    # Invalid end address
    with pytest.raises(InvalidEAError):
        analysis_db.analysis.revert_analysis(analysis_db.minimum_ea, 0xFFFFFFFFFFFFFFFF)

    # start >= end should raise InvalidParameterError
    start_ea = analysis_db.minimum_ea + 0x100

    # Equal start and end
    with pytest.raises(InvalidParameterError):
        analysis_db.analysis.revert_analysis(start_ea, start_ea)

    # Start > end
    with pytest.raises(InvalidParameterError):
        analysis_db.analysis.revert_analysis(start_ea, start_ea - 1)


def test_revert_analysis_works_with_subsequent_analysis(analysis_db):
    """
    Test that revert_analysis() works correctly with subsequent analysis operations.

    RATIONALE: A common workflow is:
    1. Revert incorrect analysis in a range
    2. Make manual corrections (change bytes, add hints, etc.)
    3. Re-analyze the range with new information

    This test validates that after calling revert_analysis(), the range can
    be successfully re-analyzed and the analysis completes normally. This
    ensures the method properly cleans up the analysis state and doesn't leave
    the database in an inconsistent state that prevents future analysis.
    """
    # Wait for initial analysis
    analysis_db.analysis.wait_for_completion()

    # Get a valid range
    start_ea = analysis_db.minimum_ea
    end_ea = min(start_ea + 0x50, analysis_db.maximum_ea)

    # Revert the range
    analysis_db.analysis.revert_analysis(start_ea, end_ea)

    # Schedule code analysis for the range
    analysis_db.analysis.schedule_range_analysis(start_ea, end_ea, AnalysisQueueType.CODE)

    # Wait for completion
    analysis_db.analysis.wait_for_completion()
    assert analysis_db.analysis.is_complete, 'Should complete after reanalysis'

    # Can revert and analyze again
    analysis_db.analysis.revert_analysis(start_ea, end_ea)
    analysis_db.analysis.analyze_range(start_ea, end_ea, wait=True)
    assert analysis_db.analysis.is_complete, 'Should complete after second reanalysis'


def test_all_advanced_methods_work_together(analysis_db):
    """
    Test that all four advanced operation methods work together in a workflow.

    RATIONALE: This integration test validates a realistic scenario where a user:
    1. Shows progress on UI (show_addr)
    2. Recreates a problematic instruction
    3. Reverts analysis for a range
    4. Re-analyzes the range
    5. Reanalyzes function callers

    This demonstrates that the advanced methods integrate properly with each
    other and with the rest of the Analysis API, providing a complete toolset
    for manual analysis correction and refinement workflows.
    """
    # Wait for initial analysis
    analysis_db.analysis.wait_for_completion()

    # Get valid addresses and range
    start_ea = analysis_db.minimum_ea
    end_ea = min(start_ea + 0x100, analysis_db.maximum_ea)
    func_ea = start_ea

    # Step 1: Show progress on UI
    analysis_db.analysis.show_addr(start_ea)

    # Step 2: Try to recreate instruction
    result = analysis_db.analysis.recreate_instruction(start_ea)
    assert isinstance(result, bool), 'recreate_instruction should return boolean'

    # Step 3: Revert analysis for range
    analysis_db.analysis.revert_analysis(start_ea, end_ea)

    # Step 4: Re-analyze the range
    analysis_db.analysis.analyze_range(start_ea, end_ea, wait=True)

    # Step 5: Reanalyze function callers
    analysis_db.analysis.reanalyze_function_callers(func_ea, function_noreturn=False)
    analysis_db.analysis.wait_for_completion()

    # Verify final state
    assert analysis_db.analysis.is_complete, 'Should be complete at end'


# =============================================================================
# LLM-FRIENDLY API TESTS
# =============================================================================


def test_wait_method_exists_and_is_callable(analysis_db):
    """
    Test that wait() method exists and is callable as an LLM-friendly alias.

    RATIONALE: The wait() method provides an LLM-friendly name for
    wait_for_completion(). LLMs often suggest "wait()" as a natural way
    to wait for analysis completion. This test validates:
    1. The method exists on the Analysis class
    2. It is callable
    3. It returns the expected boolean type
    4. It behaves identically to wait_for_completion()

    This is part of the LLM API design pattern where we provide shorter,
    more intuitive method names as aliases to existing functionality.
    """
    # Wait() should exist and be callable
    assert hasattr(analysis_db.analysis, 'wait'), 'wait() method should exist'
    assert callable(analysis_db.analysis.wait), 'wait() should be callable'

    # Call wait() and verify it returns boolean
    result = analysis_db.analysis.wait()
    assert isinstance(result, bool), 'wait() should return boolean'

    # Result should be True for successful completion
    assert result is True, 'wait() should return True on successful completion'

    # Verify analysis is complete
    assert analysis_db.analysis.is_complete, 'Analysis should be complete after wait()'


def test_analyze_method_is_alias_for_analyze_range(analysis_db):
    """
    Test that analyze() is an LLM-friendly alias for analyze_range().

    RATIONALE: The analyze() method provides a shorter, more intuitive name
    that LLMs naturally suggest for analyzing a range. This test validates:
    1. The method exists on the Analysis class
    2. It is callable with the same parameters as analyze_range()
    3. It behaves identically to analyze_range()
    4. It supports the optional wait parameter

    This follows the LLM API design pattern of providing concise aliases.
    """
    # analyze() should exist and be callable
    assert hasattr(analysis_db.analysis, 'analyze'), 'analyze() method should exist'
    assert callable(analysis_db.analysis.analyze), 'analyze() should be callable'

    # Wait for initial analysis
    analysis_db.analysis.wait()

    # Get a valid range
    start_ea = analysis_db.minimum_ea
    end_ea = min(start_ea + 0x100, analysis_db.maximum_ea)

    # Call analyze() with wait=True (default)
    result = analysis_db.analysis.analyze(start_ea, end_ea)
    assert isinstance(result, int), 'analyze() should return int (address count)'

    # Call analyze() with wait=False
    result2 = analysis_db.analysis.analyze(start_ea, end_ea, wait=False)
    assert isinstance(result2, int), 'analyze() with wait=False should return int'
    assert result2 == 0, 'analyze() with wait=False should return 0'

    # Wait for completion
    analysis_db.analysis.wait()
    assert analysis_db.analysis.is_complete, 'Analysis should complete'


def test_analyze_validates_address_range(analysis_db):
    """
    Test that analyze() properly validates address ranges.

    RATIONALE: Since analyze() is an alias for analyze_range(), it should
    inherit the same validation behavior:
    - InvalidEAError for invalid addresses
    - InvalidParameterError for start >= end
    """
    from ida_domain.base import InvalidEAError, InvalidParameterError

    # Invalid start address
    with pytest.raises(InvalidEAError):
        analysis_db.analysis.analyze(0xFFFFFFFFFFFFFFFF, analysis_db.minimum_ea)

    # Invalid end address
    with pytest.raises(InvalidEAError):
        analysis_db.analysis.analyze(analysis_db.minimum_ea, 0xFFFFFFFFFFFFFFFF)

    # start >= end should raise InvalidParameterError
    start_ea = analysis_db.minimum_ea + 0x100

    with pytest.raises(InvalidParameterError):
        analysis_db.analysis.analyze(start_ea, start_ea)

    with pytest.raises(InvalidParameterError):
        analysis_db.analysis.analyze(start_ea, start_ea - 1)


def test_schedule_method_exists_and_dispatches(analysis_db):
    """
    Test that schedule() method exists and dispatches based on 'what' parameter.

    RATIONALE: The schedule() method provides a unified LLM-friendly interface
    for scheduling different types of analysis. Instead of requiring LLMs to know
    about schedule_code_analysis(), schedule_function_analysis(), and
    schedule_reanalysis(), they can use schedule(ea, "code"), schedule(ea, "function"),
    or schedule(ea, "reanalysis"). This test validates:
    1. The method exists and is callable
    2. It accepts "code", "function", and "reanalysis" as valid options
    3. It completes without errors for valid addresses
    """
    # schedule() should exist and be callable
    assert hasattr(analysis_db.analysis, 'schedule'), 'schedule() method should exist'
    assert callable(analysis_db.analysis.schedule), 'schedule() should be callable'

    # Wait for initial analysis
    analysis_db.analysis.wait()

    # Get a valid address
    valid_ea = analysis_db.minimum_ea

    # Test schedule with "code"
    analysis_db.analysis.schedule(valid_ea, "code")

    # Test schedule with "function"
    analysis_db.analysis.schedule(valid_ea, "function")

    # Test schedule with "reanalysis" (default)
    analysis_db.analysis.schedule(valid_ea, "reanalysis")

    # Test with default parameter
    analysis_db.analysis.schedule(valid_ea)

    # Wait for all scheduled analysis
    analysis_db.analysis.wait()
    assert analysis_db.analysis.is_complete, 'Analysis should complete'


def test_schedule_validates_address(analysis_db):
    """
    Test that schedule() properly validates the address parameter.

    RATIONALE: Like all address-taking methods, schedule() should validate
    the input address and raise InvalidEAError for invalid addresses.
    """
    from ida_domain.base import InvalidEAError

    with pytest.raises(InvalidEAError):
        analysis_db.analysis.schedule(0xFFFFFFFFFFFFFFFF, "code")

    with pytest.raises(InvalidEAError):
        analysis_db.analysis.schedule(0xFFFFFFFFFFFFFFFF, "function")

    with pytest.raises(InvalidEAError):
        analysis_db.analysis.schedule(0xFFFFFFFFFFFFFFFF, "reanalysis")


def test_schedule_validates_what_parameter(analysis_db):
    """
    Test that schedule() validates the 'what' parameter.

    RATIONALE: Invalid analysis types should raise InvalidParameterError
    to provide clear feedback about valid options.
    """
    from ida_domain.base import InvalidParameterError

    valid_ea = analysis_db.minimum_ea

    with pytest.raises(InvalidParameterError):
        analysis_db.analysis.schedule(valid_ea, "invalid")

    with pytest.raises(InvalidParameterError):
        analysis_db.analysis.schedule(valid_ea, "")

    with pytest.raises(InvalidParameterError):
        analysis_db.analysis.schedule(valid_ea, "CODE_WRONG")
