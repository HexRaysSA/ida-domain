import ida_idaapi
import ida_problems
import pytest

from ida_domain.base import InvalidEAError, InvalidParameterError


def test_analysis_enabled_property(test_env):
    db = test_env

    assert db.analysis.enabled is True

    db.analysis.enabled = False
    assert db.analysis.enabled is False

    db.analysis.enabled = True
    assert db.analysis.enabled is True


def test_analysis_schedule_and_wait(test_env):
    db = test_env

    # The database was opened with auto analysis, queues are empty
    assert db.analysis.is_idle() is True

    db.analysis.schedule(0x67)
    assert db.analysis.is_idle() is False
    assert db.analysis.wait() is True
    assert db.analysis.is_idle() is True

    db.analysis.schedule_range(db.minimum_ea, db.maximum_ea)
    assert db.analysis.is_idle() is False
    assert db.analysis.wait_range(db.minimum_ea, db.maximum_ea) >= 0
    assert db.analysis.wait() is True
    assert db.analysis.is_idle() is True

    db.analysis.schedule_code(0x67)
    db.analysis.schedule_function(0x67)
    assert db.analysis.wait() is True
    assert db.analysis.is_idle() is True


def test_analysis_cancel(test_env):
    db = test_env

    db.analysis.schedule_range(db.minimum_ea, db.maximum_ea)
    assert db.analysis.is_idle() is False
    db.analysis.cancel(db.minimum_ea, db.maximum_ea)
    assert db.analysis.is_idle() is True


def test_analysis_revert_decisions(test_env):
    db = test_env

    # Auto-analysis recorded at least one heuristic decision (PR_FINAL)
    ea = ida_problems.get_problem(ida_problems.PR_FINAL, db.minimum_ea)
    assert ea <= db.maximum_ea

    db.analysis.revert_decisions(db.minimum_ea, db.maximum_ea)

    # The recorded decisions are forgotten
    ea = ida_problems.get_problem(ida_problems.PR_FINAL, db.minimum_ea)
    assert ea == ida_idaapi.BADADDR


def test_analysis_invalid_parameters(test_env):
    db = test_env

    with pytest.raises(InvalidEAError):
        db.analysis.schedule(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.analysis.schedule_code(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.analysis.schedule_function(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.analysis.schedule_range(0xFFFFFFFF, 0xFFFFFFFF + 0x10)

    with pytest.raises(InvalidEAError):
        db.analysis.wait_range(db.minimum_ea, 0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.analysis.cancel(0xFFFFFFFF, 0xFFFFFFFF + 0x10)

    with pytest.raises(InvalidEAError):
        db.analysis.revert_decisions(0xFFFFFFFF, 0xFFFFFFFF + 0x10)

    with pytest.raises(InvalidParameterError):
        db.analysis.schedule_range(0x67, 0x67)

    with pytest.raises(InvalidParameterError):
        db.analysis.wait_range(0x67, 0x50)
