import ida_idaapi
import ida_problems
import pytest

from ida_domain.base import InvalidEAError, InvalidParameterError


def test_auto_analysis_enabled_property(test_env):
    db = test_env

    assert db.auto_analysis.enabled is True

    db.auto_analysis.enabled = False
    assert db.auto_analysis.enabled is False

    db.auto_analysis.enabled = True
    assert db.auto_analysis.enabled is True


def test_auto_analysis_schedule_and_wait(test_env):
    db = test_env

    # The database was opened with auto analysis, queues are empty
    assert db.auto_analysis.is_idle() is True

    db.auto_analysis.schedule(0x67)
    assert db.auto_analysis.is_idle() is False
    assert db.auto_analysis.wait() is True
    assert db.auto_analysis.is_idle() is True

    db.auto_analysis.schedule_range(db.minimum_ea, db.maximum_ea)
    assert db.auto_analysis.is_idle() is False
    assert db.auto_analysis.wait_range(db.minimum_ea, db.maximum_ea) >= 0
    assert db.auto_analysis.wait() is True
    assert db.auto_analysis.is_idle() is True

    db.auto_analysis.schedule_code(0x67)
    db.auto_analysis.schedule_function(0x67)
    assert db.auto_analysis.wait() is True
    assert db.auto_analysis.is_idle() is True


def test_auto_analysis_cancel(test_env):
    db = test_env

    db.auto_analysis.schedule_range(db.minimum_ea, db.maximum_ea)
    assert db.auto_analysis.is_idle() is False
    db.auto_analysis.cancel(db.minimum_ea, db.maximum_ea)
    assert db.auto_analysis.is_idle() is True


def test_auto_analysis_revert_decisions(test_env):
    db = test_env

    # Auto-analysis recorded at least one heuristic decision (PR_FINAL)
    ea = ida_problems.get_problem(ida_problems.PR_FINAL, db.minimum_ea)
    assert ea <= db.maximum_ea

    db.auto_analysis.revert_decisions(db.minimum_ea, db.maximum_ea)

    # The recorded decisions are forgotten
    ea = ida_problems.get_problem(ida_problems.PR_FINAL, db.minimum_ea)
    assert ea == ida_idaapi.BADADDR


def test_auto_analysis_invalid_parameters(test_env):
    db = test_env

    with pytest.raises(InvalidEAError):
        db.auto_analysis.schedule(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.auto_analysis.schedule_code(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.auto_analysis.schedule_function(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.auto_analysis.schedule_range(0xFFFFFFFF, 0xFFFFFFFF + 0x10)

    with pytest.raises(InvalidEAError):
        db.auto_analysis.wait_range(db.minimum_ea, 0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.auto_analysis.cancel(0xFFFFFFFF, 0xFFFFFFFF + 0x10)

    with pytest.raises(InvalidEAError):
        db.auto_analysis.revert_decisions(0xFFFFFFFF, 0xFFFFFFFF + 0x10)

    with pytest.raises(InvalidParameterError):
        db.auto_analysis.schedule_range(0x67, 0x67)

    with pytest.raises(InvalidParameterError):
        db.auto_analysis.wait_range(0x67, 0x50)
