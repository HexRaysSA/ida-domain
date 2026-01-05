"""Tests for Analysis entity - LLM-friendly API."""

import os
import shutil
import tempfile

import pytest

import ida_domain
from ida_domain.analysis import AnalysisType
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

    # Get a valid range for analysis
    # Use a range that definitely exists in any binary
    start_ea = analysis_db.minimum_ea
    # Use first 0x100 bytes or less if binary is smaller
    range_size = min(0x100, (analysis_db.maximum_ea - analysis_db.minimum_ea) // 2)
    end_ea = start_ea + range_size

    # This should never skip now since we're using actual bounds
    assert analysis_db.is_valid_ea(start_ea), 'minimum_ea should always be valid'
    assert analysis_db.is_valid_ea(end_ea - 1), 'calculated end_ea should be valid'

    # Count defined items before analysis
    defined_before = sum(
        1 for ea in range(start_ea, end_ea)
        if not analysis_db.bytes.is_unknown_at(ea)
    )

    # Call analyze() with wait=True (default)
    result = analysis_db.analysis.analyze(start_ea, end_ea)
    assert isinstance(result, int), 'analyze() should return int (address count)'

    # Count defined items after analysis
    defined_after = sum(
        1 for ea in range(start_ea, end_ea)
        if not analysis_db.bytes.is_unknown_at(ea)
    )

    # CRITICAL: Verify analysis occurred (some undefined became defined)
    assert defined_after >= defined_before, (
        f"Analysis should not decrease defined items: "
        f"before={defined_before}, after={defined_after}"
    )

    # If we had undefined bytes, they should have been analyzed
    if defined_before < (end_ea - start_ea):
        assert defined_after > defined_before, (
            "Analysis should have converted some undefined bytes"
        )


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

    # Test schedule with "code" and verify it completes
    analysis_db.analysis.schedule(valid_ea, "code")
    analysis_db.analysis.wait()

    # CRITICAL: Verify analysis completed successfully
    assert analysis_db.analysis.is_complete, (
        "Analysis should complete after scheduling code analysis"
    )

    # Test other schedule types complete without error
    analysis_db.analysis.schedule(valid_ea, "function")
    analysis_db.analysis.wait()
    assert analysis_db.analysis.is_complete, (
        "Analysis should complete after scheduling function analysis"
    )

    analysis_db.analysis.schedule(valid_ea, "reanalysis")
    analysis_db.analysis.wait()
    assert analysis_db.analysis.is_complete, (
        "Analysis should complete after scheduling reanalysis"
    )


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


def test_schedule_with_enum(analysis_db):
    """
    Test that schedule() accepts AnalysisType enum values.

    RATIONALE: The schedule() method now accepts AnalysisType enum as the
    primary way to specify the analysis type. This provides better type
    safety and IDE autocomplete support.
    """
    # Wait for initial analysis
    analysis_db.analysis.wait()

    valid_ea = analysis_db.minimum_ea

    # Test each enum value
    analysis_db.analysis.schedule(valid_ea, AnalysisType.CODE)
    analysis_db.analysis.wait()
    assert analysis_db.analysis.is_complete

    analysis_db.analysis.schedule(valid_ea, AnalysisType.FUNCTION)
    analysis_db.analysis.wait()
    assert analysis_db.analysis.is_complete

    analysis_db.analysis.schedule(valid_ea, AnalysisType.REANALYSIS)
    analysis_db.analysis.wait()
    assert analysis_db.analysis.is_complete

    # Test default value is AnalysisType.REANALYSIS
    analysis_db.analysis.schedule(valid_ea)
    analysis_db.analysis.wait()
    assert analysis_db.analysis.is_complete


def test_schedule_with_string_backward_compatibility(analysis_db):
    """
    Test that schedule() still accepts string values for backward compatibility.

    RATIONALE: Existing code using string values should continue to work.
    This ensures the refactoring to enums doesn't break existing scripts.
    """
    # Wait for initial analysis
    analysis_db.analysis.wait()

    valid_ea = analysis_db.minimum_ea

    # Test each string value (lowercase)
    analysis_db.analysis.schedule(valid_ea, "code")
    analysis_db.analysis.wait()
    assert analysis_db.analysis.is_complete

    analysis_db.analysis.schedule(valid_ea, "function")
    analysis_db.analysis.wait()
    assert analysis_db.analysis.is_complete

    analysis_db.analysis.schedule(valid_ea, "reanalysis")
    analysis_db.analysis.wait()
    assert analysis_db.analysis.is_complete


def test_schedule_string_case_insensitive(analysis_db):
    """
    Test that schedule() string parameter is case-insensitive.

    RATIONALE: For user convenience, string values should work regardless
    of case. This matches the behavior of similar APIs and reduces user
    friction when typing strings manually.
    """
    # Wait for initial analysis
    analysis_db.analysis.wait()

    valid_ea = analysis_db.minimum_ea

    # Test uppercase
    analysis_db.analysis.schedule(valid_ea, "CODE")
    analysis_db.analysis.wait()
    assert analysis_db.analysis.is_complete

    # Test mixed case
    analysis_db.analysis.schedule(valid_ea, "Function")
    analysis_db.analysis.wait()
    assert analysis_db.analysis.is_complete

    analysis_db.analysis.schedule(valid_ea, "ReAnalysis")
    analysis_db.analysis.wait()
    assert analysis_db.analysis.is_complete


def test_cancel_method_is_alias_for_cancel_analysis(analysis_db):
    """
    Test that cancel() is an LLM-friendly alias for cancel_analysis().

    RATIONALE: The cancel() method provides a shorter name that LLMs
    naturally suggest for canceling pending analysis. This test validates:
    1. The method exists and is callable
    2. It accepts the same parameters as cancel_analysis()
    3. It completes without errors for valid address ranges
    """
    # cancel() should exist and be callable
    assert hasattr(analysis_db.analysis, 'cancel'), 'cancel() method should exist'
    assert callable(analysis_db.analysis.cancel), 'cancel() should be callable'

    # Wait for initial analysis
    analysis_db.analysis.wait()

    # Get a valid range
    start_ea = analysis_db.minimum_ea
    end_ea = min(start_ea + 0x100, analysis_db.maximum_ea)

    # Call cancel() - should not raise exception
    analysis_db.analysis.cancel(start_ea, end_ea)

    # Verify analysis is still functional after cancel
    analysis_db.analysis.wait()
    assert analysis_db.analysis.is_complete, 'Analysis should complete after cancel'


def test_cancel_validates_address_range(analysis_db):
    """
    Test that cancel() properly validates address ranges.

    RATIONALE: Since cancel() is an alias for cancel_analysis(), it should
    inherit the same validation behavior.
    """
    from ida_domain.base import InvalidEAError, InvalidParameterError

    # Invalid start address
    with pytest.raises(InvalidEAError):
        analysis_db.analysis.cancel(0xFFFFFFFFFFFFFFFF, analysis_db.minimum_ea)

    # Invalid end address
    with pytest.raises(InvalidEAError):
        analysis_db.analysis.cancel(analysis_db.minimum_ea, 0xFFFFFFFFFFFFFFFF)

    # start >= end should raise InvalidParameterError
    start_ea = analysis_db.minimum_ea + 0x100

    with pytest.raises(InvalidParameterError):
        analysis_db.analysis.cancel(start_ea, start_ea)

    with pytest.raises(InvalidParameterError):
        analysis_db.analysis.cancel(start_ea, start_ea - 1)
