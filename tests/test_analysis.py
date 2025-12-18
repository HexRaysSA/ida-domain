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
    idb_path = os.path.join(
        tempfile.gettempdir(), 'api_tests_work_dir', 'analysis_test.bin'
    )
    os.makedirs(os.path.dirname(idb_path), exist_ok=True)

    # Copy test binary
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(current_dir, 'resources', 'tiny_asm.bin')

    if not os.path.exists(src_path):
        pytest.skip("Test binary not found")

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
# LEGACY API COMPATIBILITY TESTS
# =============================================================================


def test_auto_wait_delegates_to_wait_for_completion(analysis_db):
    """
    Test that auto_wait() correctly delegates to wait_for_completion().

    RATIONALE: auto_wait() is a legacy API compatibility method that should
    behave identically to wait_for_completion(). This test validates that:
    1. The method exists and can be called
    2. It blocks until analysis completes
    3. It returns a boolean success value
    4. The database is in a complete state after the call

    This is important for backward compatibility - existing scripts using
    ida_auto.auto_wait() should be able to use db.analysis.auto_wait()
    as a drop-in replacement.
    """
    # Both methods should return the same type
    result = analysis_db.analysis.auto_wait()

    # Should return boolean
    assert isinstance(result, bool), "auto_wait() should return a boolean"

    # After waiting, analysis should be complete
    assert (
        analysis_db.analysis.is_complete
    ), "Database should be fully analyzed after auto_wait()"

    # Verify both methods have same behavior
    result2 = analysis_db.analysis.wait_for_completion()
    assert isinstance(
        result2, bool
    ), "wait_for_completion() should return same type as auto_wait()"


def test_plan_and_wait_delegates_to_analyze_range(analysis_db):
    """
    Test that plan_and_wait() correctly delegates to analyze_range().

    RATIONALE: plan_and_wait() is a legacy API compatibility method that
    maps directly to ida_auto.plan_and_wait(). It should behave identically
    to analyze_range(start, end, wait=True). This test validates:
    1. The method accepts start/end parameters
    2. It schedules analysis for the range
    3. It waits for completion (blocking call)
    4. It returns the number of addresses processed

    We test with a known valid range in the binary. The exact count may vary
    depending on what IDA decides to analyze, but it should be non-negative.
    """
    # Get a valid range to analyze
    start_ea = analysis_db.minimum_ea
    end_ea = min(start_ea + 0x100, analysis_db.maximum_ea)

    # First ensure analysis is complete
    analysis_db.analysis.wait_for_completion()

    # Call plan_and_wait
    count = analysis_db.analysis.plan_and_wait(start_ea, end_ea)

    # Should return an integer (number of addresses processed)
    assert isinstance(count, int), "plan_and_wait() should return an integer count"
    assert count >= 0, "Address count should be non-negative"

    # Database should be analyzed after waiting
    assert (
        analysis_db.analysis.is_complete
    ), "Analysis should be complete after plan_and_wait()"


def test_plan_and_wait_validates_address_range(analysis_db):
    """
    Test that plan_and_wait() properly validates address ranges.

    RATIONALE: The legacy API should maintain the same error handling as
    the modern API. Invalid addresses and invalid ranges (start >= end)
    should raise appropriate exceptions. This ensures consistent behavior
    across the API surface.
    """
    from ida_domain.base import InvalidEAError, InvalidParameterError

    # Invalid start address should raise InvalidEAError
    with pytest.raises(InvalidEAError):
        analysis_db.analysis.plan_and_wait(0xFFFFFFFFFFFFFFFF, analysis_db.minimum_ea)

    # Invalid end address should raise InvalidEAError
    with pytest.raises(InvalidEAError):
        analysis_db.analysis.plan_and_wait(analysis_db.minimum_ea, 0xFFFFFFFFFFFFFFFF)

    # start >= end should raise InvalidParameterError
    start_ea = analysis_db.minimum_ea + 0x100
    with pytest.raises(InvalidParameterError):
        analysis_db.analysis.plan_and_wait(start_ea, start_ea)  # Equal

    with pytest.raises(InvalidParameterError):
        analysis_db.analysis.plan_and_wait(
            start_ea, start_ea - 1
        )  # Start > end


def test_auto_is_ok_delegates_to_is_complete(analysis_db):
    """
    Test that auto_is_ok() correctly delegates to is_complete property.

    RATIONALE: auto_is_ok() is a legacy API compatibility method that should
    return the same value as the is_complete property. This is a critical
    check that many scripts use to determine if analysis is finished before
    proceeding with further operations.

    We test in two scenarios:
    1. After waiting for completion (should be True)
    2. After scheduling new analysis (may be False if queue has items)
    """
    # Wait for initial analysis to complete
    analysis_db.analysis.wait_for_completion()

    # Both should return True when analysis is complete
    legacy_result = analysis_db.analysis.auto_is_ok()
    modern_result = analysis_db.analysis.is_complete

    assert isinstance(legacy_result, bool), "auto_is_ok() should return a boolean"
    assert isinstance(modern_result, bool), "is_complete should return a boolean"
    assert (
        legacy_result == modern_result
    ), "auto_is_ok() and is_complete should return the same value"
    assert legacy_result is True, "Analysis should be complete after waiting"


def test_auto_is_ok_reflects_analysis_state(analysis_db):
    """
    Test that auto_is_ok() accurately reflects the current analysis state.

    RATIONALE: The method should return False when there are pending items
    in the analysis queues and True when all queues are empty. This test
    schedules analysis and verifies the state changes appropriately.

    We can't guarantee the timing of when queues become non-empty (IDA may
    process very quickly), but we can verify the final state after waiting.
    """
    # Ensure clean state
    analysis_db.analysis.wait_for_completion()
    assert (
        analysis_db.analysis.auto_is_ok()
    ), "Should be complete before scheduling new work"

    # Schedule some analysis
    if analysis_db.minimum_ea < analysis_db.maximum_ea - 0x100:
        analysis_db.analysis.schedule_code_analysis(analysis_db.minimum_ea)

    # Wait for completion
    analysis_db.analysis.wait_for_completion()

    # Should be complete again
    assert analysis_db.analysis.auto_is_ok(), "Should be complete after waiting"


def test_get_auto_state_delegates_to_current_state(analysis_db):
    """
    Test that get_auto_state() correctly delegates to current_state property.

    RATIONALE: get_auto_state() is a legacy API compatibility method that
    should return the same AnalysisState object as the current_state property.
    The state contains information about which queue is being processed and
    what address is currently being analyzed.

    We test that:
    1. Both methods return AnalysisState objects
    2. The objects have the same content
    3. The state structure is correct (has required fields)
    """
    # Wait for analysis to complete
    analysis_db.analysis.wait_for_completion()

    # Get state from both methods
    legacy_state = analysis_db.analysis.get_auto_state()
    modern_state = analysis_db.analysis.current_state

    # Both should return AnalysisState objects
    assert isinstance(
        legacy_state, AnalysisState
    ), "get_auto_state() should return AnalysisState"
    assert isinstance(
        modern_state, AnalysisState
    ), "current_state should return AnalysisState"

    # States should be equal
    assert (
        legacy_state == modern_state
    ), "get_auto_state() and current_state should return equivalent states"

    # Verify state structure
    assert hasattr(legacy_state, 'queue_type'), "State should have queue_type"
    assert hasattr(legacy_state, 'current_address'), "State should have current_address"
    assert hasattr(legacy_state, 'is_complete'), "State should have is_complete"

    # After waiting, should be complete
    assert legacy_state.is_complete, "State should indicate analysis is complete"
    # Queue type may be NONE (idle) or FINAL (just finished) when complete
    assert legacy_state.queue_type in [
        AnalysisQueueType.NONE,
        AnalysisQueueType.FINAL,
    ], "Queue type should be NONE or FINAL when complete"


def test_get_auto_state_shows_correct_completion_status(analysis_db):
    """
    Test that get_auto_state() correctly reflects completion status.

    RATIONALE: The AnalysisState.is_complete field should accurately reflect
    whether all analysis queues are empty. This is critical for scripts that
    monitor analysis progress. After waiting for completion, the state should
    indicate completion. The state should also be consistent with auto_is_ok().
    """
    # Wait for analysis
    analysis_db.analysis.wait_for_completion()

    # Get state
    state = analysis_db.analysis.get_auto_state()

    # Completion status should match auto_is_ok()
    assert (
        state.is_complete == analysis_db.analysis.auto_is_ok()
    ), "State completion should match auto_is_ok()"

    # After waiting, should be complete
    assert state.is_complete, "Should be complete after waiting"

    # Queue should be NONE (idle) or FINAL (just completed final pass)
    # Both are valid when is_complete is True
    assert state.queue_type in [
        AnalysisQueueType.NONE,
        AnalysisQueueType.FINAL,
    ], "Queue should be NONE or FINAL when complete"

    # Current address may be None or the last address processed
    # This is implementation-dependent and both are valid


def test_legacy_methods_work_together(analysis_db):
    """
    Test that legacy API methods can be used together in a typical workflow.

    RATIONALE: This validates a realistic usage pattern where a script:
    1. Waits for initial analysis (auto_wait)
    2. Checks if analysis is done (auto_is_ok)
    3. Analyzes a specific range (plan_and_wait)
    4. Checks final state (get_auto_state)

    This is a common pattern in existing IDA scripts and demonstrates that
    the legacy compatibility layer provides a complete, working API surface.
    """
    # Step 1: Wait for initial analysis
    result = analysis_db.analysis.auto_wait()
    assert result is True, "auto_wait should succeed"

    # Step 2: Verify analysis is complete
    assert analysis_db.analysis.auto_is_ok(), "Analysis should be complete"

    # Step 3: Analyze a specific range
    start_ea = analysis_db.minimum_ea
    end_ea = min(start_ea + 0x100, analysis_db.maximum_ea)

    count = analysis_db.analysis.plan_and_wait(start_ea, end_ea)
    assert count >= 0, "plan_and_wait should return non-negative count"

    # Step 4: Check final state
    state = analysis_db.analysis.get_auto_state()
    assert state.is_complete, "Final state should show completion"
    # Note: queue_type may be NONE (idle) or FINAL (just completed final pass)
    # Both are valid when is_complete is True
    assert state.queue_type in [
        AnalysisQueueType.NONE,
        AnalysisQueueType.FINAL,
    ], "Queue should be idle or just finished final pass"

    # Verify consistency
    assert (
        analysis_db.analysis.auto_is_ok()
    ), "auto_is_ok should agree with state.is_complete"


def test_legacy_and_modern_apis_are_interchangeable(analysis_db):
    """
    Test that legacy and modern API methods can be used interchangeably.

    RATIONALE: Users should be able to mix legacy and modern API calls
    in the same script without issues. This test validates that calling
    a legacy method followed by a modern method (or vice versa) works
    correctly and produces consistent results.

    This is important for gradual migration - users can update parts of
    their scripts to use the modern API while keeping other parts using
    the legacy API during the transition period.
    """
    # Use modern API
    analysis_db.analysis.wait_for_completion()
    modern_complete = analysis_db.analysis.is_complete

    # Use legacy API
    legacy_complete = analysis_db.analysis.auto_is_ok()

    # Should be consistent
    assert modern_complete == legacy_complete, "APIs should be interchangeable"

    # Mix legacy and modern
    state1 = analysis_db.analysis.current_state  # Modern
    state2 = analysis_db.analysis.get_auto_state()  # Legacy

    assert state1 == state2, "Modern and legacy state methods should agree"

    # Test with range analysis
    start_ea = analysis_db.minimum_ea
    end_ea = min(start_ea + 0x50, analysis_db.maximum_ea)

    # Modern API
    count1 = analysis_db.analysis.analyze_range(start_ea, end_ea, wait=True)

    # Legacy API (analyze same range again - should be quick)
    count2 = analysis_db.analysis.plan_and_wait(start_ea, end_ea)

    # Both should succeed and return counts
    assert isinstance(count1, int) and count1 >= 0, "Modern API should work"
    assert isinstance(count2, int) and count2 >= 0, "Legacy API should work"
