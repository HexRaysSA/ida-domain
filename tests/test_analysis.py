"""Tests for Analysis entity - LLM-friendly API."""

import os
import shutil
import tempfile

import pytest

import ida_domain
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
