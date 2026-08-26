from __future__ import annotations

import logging

import ida_auto
from ida_idaapi import ea_t
from typing_extensions import TYPE_CHECKING

from .base import (
    DatabaseEntity,
    InvalidEAError,
    InvalidParameterError,
    check_db_open,
    decorate_all_methods,
)

if TYPE_CHECKING:
    from .database import Database

logger = logging.getLogger(__name__)


@decorate_all_methods(check_db_open)
class AutoAnalysis(DatabaseEntity):
    """
    Provides access to IDA's auto-analysis engine.

    Auto-analysis is queue based: the scheduling methods only insert work into
    the analysis queues and return immediately. When IDA runs as a library
    there is no background analysis thread, so the queues are processed
    synchronously inside `wait()` / `wait_range()` and `is_idle()` only becomes
    True after such a call drains them. When running inside the IDA GUI, the
    queues are also processed during the main loop idle time.

    Args:
        database: Reference to the active IDA database.
    """

    def __init__(self, database: Database):
        super().__init__(database)

    @property
    @check_db_open
    def enabled(self) -> bool:
        """
        Whether the auto-analyzer is enabled.

        Note:
            This is only relevant when running inside the IDA GUI, where it
            stops the analyzer from processing the queues during the main loop
            idle time (e.g. around bulk modifications). In library (idalib)
            mode the queues are only ever processed by an explicit `wait()` /
            `wait_range()` call, and those process pending work regardless of
            this setting.
        """
        return ida_auto.is_auto_enabled()

    @enabled.setter
    @check_db_open
    def enabled(self, value: bool) -> None:
        ida_auto.enable_auto(value)

    def is_idle(self) -> bool:
        """
        Check whether all analysis queues are empty.

        Returns:
            True if auto-analysis has finished (no pending work), False if
            analysis work is still queued. Note that in library mode pending
            work is only processed inside `wait()` / `wait_range()`.
        """
        return ida_auto.auto_is_ok()

    def wait(self) -> bool:
        """
        Process all analysis queues and block until they are empty.

        Returns:
            True if analysis completed, False if it was interrupted.
        """
        return ida_auto.auto_wait()

    def wait_range(self, start_ea: ea_t, end_ea: ea_t) -> int:
        """
        Process all analysis queues for the given range and block until no
        pending work remains inside it.

        Args:
            start_ea: Start address of the range.
            end_ea: End address of the range (exclusive).

        Returns:
            Number of analysis steps performed, or -1 if the user cancelled.

        Raises:
            InvalidEAError: If an effective address is not in the database range.
            InvalidParameterError: If start_ea is not less than end_ea.
        """
        self._check_range(start_ea, end_ea)
        return ida_auto.auto_wait_range(start_ea, end_ea)

    def schedule(self, ea: ea_t) -> None:
        """
        Queue an address for (re)analysis.

        Args:
            ea: The effective address to analyze.

        Raises:
            InvalidEAError: If the effective address is not in the database range.
        """
        if not self.database.is_valid_ea(ea, strict_check=False):
            raise InvalidEAError(ea)
        ida_auto.plan_ea(ea)

    def schedule_range(self, start_ea: ea_t, end_ea: ea_t) -> None:
        """
        Queue an address range for (re)analysis.

        Args:
            start_ea: Start address of the range.
            end_ea: End address of the range (exclusive).

        Raises:
            InvalidEAError: If an effective address is not in the database range.
            InvalidParameterError: If start_ea is not less than end_ea.
        """
        self._check_range(start_ea, end_ea)
        ida_auto.plan_range(start_ea, end_ea)

    def schedule_code(self, ea: ea_t) -> None:
        """
        Queue an address to be converted to code.

        Args:
            ea: The effective address to convert.

        Raises:
            InvalidEAError: If the effective address is not in the database range.
        """
        if not self.database.is_valid_ea(ea, strict_check=False):
            raise InvalidEAError(ea)
        ida_auto.auto_make_code(ea)

    def schedule_function(self, ea: ea_t) -> None:
        """
        Queue an address to be converted to code and become a function.

        Args:
            ea: The effective address of the future function entry point.

        Raises:
            InvalidEAError: If the effective address is not in the database range.
        """
        if not self.database.is_valid_ea(ea, strict_check=False):
            raise InvalidEAError(ea)
        ida_auto.auto_make_proc(ea)

    def cancel(self, start_ea: ea_t, end_ea: ea_t) -> None:
        """
        Remove pending analysis work for the given range from the queues.

        Args:
            start_ea: Start address of the range.
            end_ea: End address of the range (exclusive).

        Raises:
            InvalidEAError: If an effective address is not in the database range.
            InvalidParameterError: If start_ea is not less than end_ea.
        """
        self._check_range(start_ea, end_ea)
        ida_auto.auto_cancel(start_ea, end_ea)

    def revert_decisions(self, start_ea: ea_t, end_ea: ea_t) -> None:
        """
        Delete all analysis info that IDA generated for the given range.

        Args:
            start_ea: Start address of the range.
            end_ea: End address of the range (exclusive).

        Raises:
            InvalidEAError: If an effective address is not in the database range.
            InvalidParameterError: If start_ea is not less than end_ea.
        """
        self._check_range(start_ea, end_ea)
        ida_auto.revert_ida_decisions(start_ea, end_ea)

    def _check_range(self, start_ea: ea_t, end_ea: ea_t) -> None:
        if not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')
