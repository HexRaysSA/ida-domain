from __future__ import annotations

import logging
from enum import Enum

import ida_auto
from ida_idaapi import ea_t
from typing_extensions import TYPE_CHECKING, Union, cast

from .base import (
    DatabaseEntity,
    InvalidEAError,
    InvalidParameterError,
    check_db_open,
    decorate_all_methods,
)

if TYPE_CHECKING:
    from .database import Database

__all__ = ['Analysis', 'AnalysisType']


class AnalysisType(str, Enum):
    """Type of analysis to schedule."""

    CODE = "code"
    """Schedule instruction creation (CODE queue)"""

    FUNCTION = "function"
    """Schedule function creation (PROC queue)"""

    REANALYSIS = "reanalysis"
    """Schedule reanalysis (USED queue)"""

logger = logging.getLogger(__name__)


@decorate_all_methods(check_db_open)
class Analysis(DatabaseEntity):
    """
    Provides access to auto-analysis control and queue management.

    Controls IDA's automatic analysis engine, including queue management,
    analysis execution, and state monitoring.
    """

    def __init__(self, database: Database) -> None:
        """
        Initialize the Analysis entity.

        Args:
            database: Reference to the Database instance
        """
        super().__init__(database)

    @property
    def is_enabled(self) -> bool:
        """
        Check if auto-analysis is currently enabled.

        Returns:
            True if auto-analysis is enabled, False if disabled

        Example:
            >>> db = Database.open_current()
            >>> if db.analysis.is_enabled:
            ...     print("Auto-analysis is running")
            ... else:
            ...     print("Auto-analysis is disabled")
        """
        return cast(bool, ida_auto.is_auto_enabled())

    @property
    def is_complete(self) -> bool:
        """
        Check if all analysis queues are empty (non-blocking).

        Returns:
            True if analysis is complete, False if queues have pending items

        Example:
            >>> db = Database.open_current()
            >>> if db.analysis.is_complete:
            ...     print("Analysis finished")
            ... else:
            ...     print("Still analyzing...")
        """
        return cast(bool, ida_auto.auto_is_ok())

    def wait_for_completion(self) -> bool:
        """
        Wait until all analysis queues are empty (blocks execution).

        This is the most common auto-analysis operation. It processes all
        queued items across all queues until everything is analyzed. Use this
        to ensure the database is in a stable state before querying analysis
        results.

        Returns:
            True if analysis completed successfully

        Example:
            >>> db = Database.open_current()
            >>> # Create a function
            >>> db.functions.create(0x401000)
            >>> # Wait for analysis to complete
            >>> db.analysis.wait_for_completion()
            >>> # Now safe to query function properties
            >>> func = db.functions.get_at(0x401000)
            >>> print(f"Function has {len(list(func.basic_blocks))} basic blocks")
        """
        return cast(bool, ida_auto.auto_wait())

    def wait(self) -> bool:
        """
        Wait until all analysis queues are empty (LLM-friendly alias).

        This is an LLM-friendly alias for wait_for_completion(). It provides
        a shorter, more intuitive name that LLMs naturally suggest when waiting
        for analysis to complete.

        Returns:
            True if analysis completed successfully

        Example:
            >>> db = Database.open_current()
            >>> # Create a function
            >>> db.functions.create(0x401000)
            >>> # Wait for analysis to complete (LLM-friendly)
            >>> db.analysis.wait()
            >>> # Now safe to query function properties
            >>> func = db.functions.get_at(0x401000)

        Note:
            This method is functionally identical to wait_for_completion().
            Use whichever name feels more natural for your workflow.
        """
        return self.wait_for_completion()

    def analyze(self, start_ea: ea_t, end_ea: ea_t, wait: bool = True) -> int:
        """
        Analyze address range (LLM-friendly alias for analyze_range).

        This is an LLM-friendly alias for analyze_range(). It provides a
        shorter, more intuitive name that LLMs naturally suggest when
        analyzing a range of addresses.

        Args:
            start_ea: Start address of range to analyze
            end_ea: End address of range (exclusive)
            wait: If True, blocks until analysis completes. If False, schedules
                analysis and returns immediately.

        Returns:
            Number of addresses processed

        Raises:
            InvalidEAError: If start_ea or end_ea address is invalid
            InvalidParameterError: If start_ea >= end_ea

        Example:
            >>> db = Database.open_current()
            >>> # Analyze a specific range and wait
            >>> count = db.analysis.analyze(0x401000, 0x402000)
            >>> print(f"Analyzed {count} addresses")
            >>> # Schedule analysis without waiting
            >>> db.analysis.analyze(0x402000, 0x403000, wait=False)

        Note:
            This method is functionally identical to analyze_range().
            Use whichever name feels more natural for your workflow.
        """
        return self.analyze_range(start_ea, end_ea, wait)

    def analyze_range(self, start_ea: ea_t, end_ea: ea_t, wait: bool = True) -> int:
        """
        Analyze address range and optionally wait for completion.

        This is a convenience method that schedules analysis for a range and
        optionally waits. It's equivalent to manually scheduling the range and
        calling wait_for_completion().

        Args:
            start_ea: Start address of range to analyze
            end_ea: End address of range (exclusive)
            wait: If True, blocks until analysis completes. If False, schedules
                analysis and returns immediately.

        Returns:
            Number of addresses processed

        Raises:
            InvalidEAError: If start_ea or end_ea address is invalid
            InvalidParameterError: If start_ea >= end_ea

        Example:
            >>> db = Database.open_current()
            >>> # Analyze a specific range and wait
            >>> count = db.analysis.analyze_range(0x401000, 0x402000)
            >>> print(f"Analyzed {count} addresses")
            >>> # Schedule analysis without waiting
            >>> db.analysis.analyze_range(0x402000, 0x403000, wait=False)
            >>> # Continue working while analysis runs in background
        """
        # Validate inputs
        if not self.database.is_valid_ea(start_ea):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        if wait:
            # plan_and_wait does scheduling + waiting + final pass
            # Returns number of addresses processed
            return cast(int, ida_auto.plan_and_wait(start_ea, end_ea, final_pass=True))
        else:
            # Just schedule for reanalysis
            ida_auto.auto_mark_range(start_ea, end_ea, ida_auto.AU_USED)
            return 0  # Unknown until processed

    def set_enabled(self, enabled: bool) -> bool:
        """
        Enable or disable auto-analysis at runtime.

        Temporarily disables the auto-analyzer. Use with caution - disabling
        auto-analysis can leave the database in an inconsistent state. Always
        re-enable it when done.

        Args:
            enabled: True to enable auto-analysis, False to disable

        Returns:
            Previous enabled state

        Example:
            >>> db = Database.open_current()
            >>> # Temporarily disable auto-analysis for performance
            >>> prev_state = db.analysis.set_enabled(False)
            >>> try:
            ...     # Do many operations without auto-analysis overhead
            ...     for ea in range(0x401000, 0x410000, 4):
            ...         db.bytes.patch_dword(ea, 0x90909090)
            ... finally:
            ...     # Always re-enable
            ...     db.analysis.set_enabled(prev_state)
            ...     db.analysis.wait_for_completion()
        """
        return cast(bool, ida_auto.enable_auto(enabled))

    def schedule(
        self, ea: ea_t, what: Union[AnalysisType, str] = AnalysisType.REANALYSIS
    ) -> None:
        """
        Schedule analysis at address (LLM-friendly unified scheduling method).

        This is an LLM-friendly unified interface for scheduling different types
        of analysis. It dispatches to the appropriate schedule_*_analysis() method
        based on the 'what' parameter.

        Args:
            ea: Address to schedule for analysis.
            what: Type of analysis. Use AnalysisType enum:
                - AnalysisType.CODE: Create instruction (schedule_code_analysis)
                - AnalysisType.FUNCTION: Create function (schedule_function_analysis)
                - AnalysisType.REANALYSIS: Reanalyze address (schedule_reanalysis)
                String values ("code", "function", "reanalysis") also accepted.

        Raises:
            InvalidEAError: If address is invalid.
            InvalidParameterError: If what is not a valid option.

        Example:
            >>> db = Database.open_current()
            >>> db.analysis.schedule(0x401000, AnalysisType.CODE)
            >>> db.analysis.schedule(0x401000, "code")  # Also accepted
            >>> db.analysis.wait()

        Note:
            This method provides a simpler API for LLMs that don't need to
            remember the specific method names for each scheduling type.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Normalize to enum
        if isinstance(what, str):
            try:
                what = AnalysisType(what.lower())
            except ValueError:
                raise InvalidParameterError(
                    'what', what,
                    f'must be one of: {", ".join(e.value for e in AnalysisType)}'
                )

        # Use enum for comparison
        if what == AnalysisType.CODE:
            self.schedule_code_analysis(ea)
        elif what == AnalysisType.FUNCTION:
            self.schedule_function_analysis(ea)
        elif what == AnalysisType.REANALYSIS:
            self.schedule_reanalysis(ea)

    def schedule_code_analysis(self, ea: ea_t) -> None:
        """
        Schedule instruction creation at address (adds to CODE queue).

        Use this to request IDA to create an instruction at a specific address.
        The instruction will be created when the CODE queue is processed.

        Args:
            ea: Address where instruction should be created

        Raises:
            InvalidEAError: If address is invalid

        Example:
            >>> db = Database.open_current()
            >>> # Schedule instruction creation
            >>> db.analysis.schedule_code_analysis(0x401000)
            >>> db.analysis.wait_for_completion()
            >>> # Now instruction exists
            >>> insn = db.instructions.get_at(0x401000)
        """
        # Validate address
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Schedule code creation
        ida_auto.auto_make_code(ea)

    def schedule_function_analysis(self, ea: ea_t) -> None:
        """
        Schedule function creation at address (adds to PROC queue).

        Use this to request IDA to create a function at a specific address. The
        function will be created when the PROC queue is processed (after CODE queue).

        Args:
            ea: Address where function should be created

        Raises:
            InvalidEAError: If address is invalid

        Example:
            >>> db = Database.open_current()
            >>> # Schedule function creation
            >>> db.analysis.schedule_function_analysis(0x401000)
            >>> db.analysis.wait_for_completion()
            >>> # Now function exists
            >>> func = db.functions.get_at(0x401000)
        """
        # Validate address
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Schedule function creation
        ida_auto.auto_make_proc(ea)

    def schedule_reanalysis(self, ea: ea_t) -> None:
        """
        Schedule reanalysis of single address (adds to USED queue).

        Use this to request IDA to reanalyze an address (e.g., after manual
        changes). The address will be reanalyzed when the USED queue is
        processed.

        Args:
            ea: Address to reanalyze

        Raises:
            InvalidEAError: If address is invalid

        Example:
            >>> db = Database.open_current()
            >>> # Make manual change
            >>> db.bytes.patch_byte(0x401000, 0x90)  # NOP
            >>> # Request reanalysis
            >>> db.analysis.schedule_reanalysis(0x401000)
            >>> db.analysis.wait_for_completion()
        """
        # Validate address
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Schedule reanalysis
        ida_auto.plan_ea(ea)

    def cancel(self, start_ea: ea_t, end_ea: ea_t) -> None:
        """
        Cancel pending analysis for address range (LLM-friendly alias).

        This is an LLM-friendly alias for cancel_analysis(). It provides a
        shorter, more intuitive name that LLMs naturally suggest when
        canceling pending analysis.

        Args:
            start_ea: Start address of range
            end_ea: End address of range (exclusive)

        Raises:
            InvalidEAError: If start_ea or end_ea address is invalid
            InvalidParameterError: If start_ea >= end_ea

        Example:
            >>> db = Database.open_current()
            >>> # Cancel pending analysis for data section
            >>> db.analysis.cancel(0x403000, 0x404000)

        Note:
            This method is functionally identical to cancel_analysis().
            Use whichever name feels more natural for your workflow.
        """
        return self.cancel_analysis(start_ea, end_ea)

    def cancel_analysis(self, start_ea: ea_t, end_ea: ea_t) -> None:
        """
        Cancel pending analysis for address range.

        Removes the specified range from CODE, PROC, and USED queues. Use this
        to prevent IDA from analyzing a specific region.

        Args:
            start_ea: Start address of range
            end_ea: End address of range (exclusive)

        Raises:
            InvalidEAError: If start_ea or end_ea address is invalid
            InvalidParameterError: If start_ea >= end_ea

        Example:
            >>> db = Database.open_current()
            >>> # Cancel pending analysis for data section
            >>> db.analysis.cancel_analysis(0x403000, 0x404000)
        """
        # Validate inputs
        if not self.database.is_valid_ea(start_ea):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        # Cancel analysis for range
        ida_auto.auto_cancel(start_ea, end_ea)
