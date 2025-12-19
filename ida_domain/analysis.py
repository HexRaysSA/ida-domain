from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import IntEnum

import ida_auto
from ida_idaapi import BADADDR, ea_t
from typing_extensions import TYPE_CHECKING, Optional, cast

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


class AnalysisQueueType(IntEnum):
    """Auto-analysis queue types, ordered by priority."""

    NONE = ida_auto.AU_NONE
    """Placeholder, not used"""
    UNK = ida_auto.AU_UNK
    """Convert to unexplored"""
    CODE = ida_auto.AU_CODE
    """Convert to instruction"""
    WEAK = ida_auto.AU_WEAK
    """Convert to instruction (IDA decision)"""
    PROC = ida_auto.AU_PROC
    """Convert to procedure start"""
    TAIL = ida_auto.AU_TAIL
    """Add procedure tail (function chunk)"""
    FCHUNK = ida_auto.AU_FCHUNK
    """Find function chunks"""
    USED = ida_auto.AU_USED
    """Reanalyze"""
    USD2 = ida_auto.AU_USD2
    """Reanalyze, second pass"""
    TYPE = ida_auto.AU_TYPE
    """Apply type information"""
    LIBF = ida_auto.AU_LIBF
    """Apply signature to address"""
    LBF2 = ida_auto.AU_LBF2
    """Apply signature, second pass"""
    LBF3 = ida_auto.AU_LBF3
    """Apply signature, third pass"""
    CHLB = ida_auto.AU_CHLB
    """Load signature file"""
    FINAL = ida_auto.AU_FINAL
    """Final pass"""


@dataclass(frozen=True)
class AnalysisState:
    """Current state of the auto-analyzer."""

    queue_type: AnalysisQueueType
    """Which queue is currently being processed (NONE if idle)"""

    current_address: Optional[ea_t]
    """Address currently being analyzed (None if idle)"""

    is_complete: bool
    """True if all queues are empty"""


@decorate_all_methods(check_db_open)
class Analysis(DatabaseEntity):
    """
    Provides access to auto-analysis control and queue management.

    Controls IDA's automatic analysis engine, including queue management,
    analysis execution, and state monitoring.
    """

    def __init__(self, database: Database):
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

    @property
    def current_state(self) -> AnalysisState:
        """
        Get current analyzer state (which queue is being processed, current address).

        Returns:
            Current state of the analyzer

        Example:
            >>> db = Database.open_current()
            >>> state = db.analysis.current_state
            >>> if state.is_complete:
            ...     print("Idle")
            ... else:
            ...     print(f"Processing {state.queue_type.name} at {hex(state.current_address)}")
        """
        # Get current display state
        display = ida_auto.auto_display_t()
        success = ida_auto.get_auto_display(display)

        if not success:
            # Analysis is idle
            return AnalysisState(
                queue_type=AnalysisQueueType.NONE, current_address=None, is_complete=True
            )

        # Convert to AnalysisState
        queue_type = AnalysisQueueType(display.type)
        current_address = display.ea if display.ea != BADADDR else None
        is_complete = ida_auto.auto_is_ok()

        return AnalysisState(
            queue_type=queue_type, current_address=current_address, is_complete=is_complete
        )

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

    def analyze(self, start: ea_t, end: ea_t, wait: bool = True) -> int:
        """
        Analyze address range (LLM-friendly alias for analyze_range).

        This is an LLM-friendly alias for analyze_range(). It provides a
        shorter, more intuitive name that LLMs naturally suggest when
        analyzing a range of addresses.

        Args:
            start: Start address of range to analyze
            end: End address of range (exclusive)
            wait: If True, blocks until analysis completes. If False, schedules
                analysis and returns immediately.

        Returns:
            Number of addresses processed

        Raises:
            InvalidEAError: If start or end address is invalid
            InvalidParameterError: If start >= end

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
        return self.analyze_range(start, end, wait)

    def analyze_range(self, start: ea_t, end: ea_t, wait: bool = True) -> int:
        """
        Analyze address range and optionally wait for completion.

        This is a convenience method that schedules analysis for a range and
        optionally waits. It's equivalent to manually scheduling the range and
        calling wait_for_completion().

        Args:
            start: Start address of range to analyze
            end: End address of range (exclusive)
            wait: If True, blocks until analysis completes. If False, schedules
                analysis and returns immediately.

        Returns:
            Number of addresses processed

        Raises:
            InvalidEAError: If start or end address is invalid
            InvalidParameterError: If start >= end

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
        if not self.database.is_valid_ea(start):
            raise InvalidEAError(start)
        if not self.database.is_valid_ea(end):
            raise InvalidEAError(end)
        if start >= end:
            raise InvalidParameterError('start', start, 'must be less than end')

        if wait:
            # plan_and_wait does scheduling + waiting + final pass
            # Returns number of addresses processed
            return cast(int, ida_auto.plan_and_wait(start, end, final_pass=True))
        else:
            # Just schedule for reanalysis
            ida_auto.auto_mark_range(start, end, ida_auto.AU_USED)
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

    def schedule(self, ea: ea_t, what: str = "reanalysis") -> None:
        """
        Schedule analysis at address (LLM-friendly unified scheduling method).

        This is an LLM-friendly unified interface for scheduling different types
        of analysis. It dispatches to the appropriate schedule_*_analysis() method
        based on the 'what' parameter.

        Args:
            ea: Address to schedule for analysis.
            what: Type of analysis. One of:
                - "code": Create instruction (schedule_code_analysis)
                - "function": Create function (schedule_function_analysis)
                - "reanalysis": Reanalyze address (schedule_reanalysis)

        Raises:
            InvalidEAError: If address is invalid.
            InvalidParameterError: If what is not a valid option.

        Example:
            >>> db = Database.open_current()
            >>> # Schedule code creation
            >>> db.analysis.schedule(0x401000, "code")
            >>> # Schedule function creation
            >>> db.analysis.schedule(0x401000, "function")
            >>> # Schedule reanalysis (default)
            >>> db.analysis.schedule(0x401000)
            >>> db.analysis.wait()

        Note:
            This method provides a simpler API for LLMs that don't need to
            remember the specific method names for each scheduling type.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        what_lower = what.lower()
        if what_lower == "code":
            self.schedule_code_analysis(ea)
        elif what_lower == "function":
            self.schedule_function_analysis(ea)
        elif what_lower == "reanalysis":
            self.schedule_reanalysis(ea)
        else:
            raise InvalidParameterError(
                'what', what, 'must be one of: "code", "function", "reanalysis"'
            )

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

    def schedule_range_analysis(
        self, start: ea_t, end: ea_t, queue_type: AnalysisQueueType
    ) -> None:
        """
        Schedule address range for analysis in specific queue.

        Low-level queue control - adds a range to a specific analysis queue.
        Most users should use the convenience methods (schedule_code_analysis(),
        etc.) instead.

        Args:
            start: Start address of range
            end: End address of range (exclusive)
            queue_type: Which queue to add the range to

        Raises:
            InvalidEAError: If start or end address is invalid
            InvalidParameterError: If start >= end or queue_type is invalid

        Example:
            >>> db = Database.open_current()
            >>> # Add range to CODE queue
            >>> db.analysis.schedule_range_analysis(
            ...     0x401000,
            ...     0x402000,
            ...     AnalysisQueueType.CODE
            ... )
        """
        # Validate inputs
        if not self.database.is_valid_ea(start):
            raise InvalidEAError(start)
        if not self.database.is_valid_ea(end):
            raise InvalidEAError(end)
        if start >= end:
            raise InvalidParameterError('start', start, 'must be less than end')

        # Add range to specified queue
        ida_auto.auto_mark_range(start, end, queue_type.value)

    def wait_for_range(self, start: ea_t, end: ea_t) -> int:
        """
        Wait for analysis completion for specific address range only.

        More targeted than wait_for_completion() - only processes items within
        the specified range. Use this when you need to ensure a specific region
        is analyzed but don't care about other pending analysis.

        Args:
            start: Start address of range
            end: End address of range (exclusive)

        Returns:
            Number of addresses processed in range

        Raises:
            InvalidEAError: If start or end address is invalid
            InvalidParameterError: If start >= end

        Example:
            >>> db = Database.open_current()
            >>> # Wait for specific range only
            >>> db.analysis.wait_for_range(0x401000, 0x402000)
        """
        # Validate inputs
        if not self.database.is_valid_ea(start):
            raise InvalidEAError(start)
        if not self.database.is_valid_ea(end):
            raise InvalidEAError(end)
        if start >= end:
            raise InvalidParameterError('start', start, 'must be less than end')

        # auto_wait_range returns number of addresses processed
        result = ida_auto.auto_wait_range(start, end)
        return result if result >= 0 else 0

    def analyze_range_until_stable(self, start: ea_t, end: ea_t) -> int:
        """
        Analyze range with final pass to ensure all analysis is complete.

        Similar to analyze_range() but includes a final analysis pass to ensure
        everything is fully analyzed. This is more thorough than the standard
        analyze_range().

        Args:
            start: Start address of range to analyze
            end: End address of range (exclusive)

        Returns:
            Number of addresses processed

        Raises:
            InvalidEAError: If start or end address is invalid
            InvalidParameterError: If start >= end

        Example:
            >>> db = Database.open_current()
            >>> # Thorough analysis with final pass
            >>> db.analysis.analyze_range_until_stable(0x401000, 0x410000)
        """
        # Validate inputs
        if not self.database.is_valid_ea(start):
            raise InvalidEAError(start)
        if not self.database.is_valid_ea(end):
            raise InvalidEAError(end)
        if start >= end:
            raise InvalidParameterError('start', start, 'must be less than end')

        # plan_and_wait with final_pass=True ensures stability
        return cast(int, ida_auto.plan_and_wait(start, end, final_pass=True))

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

    def cancel(self, start: ea_t, end: ea_t) -> None:
        """
        Cancel pending analysis for address range (LLM-friendly alias).

        This is an LLM-friendly alias for cancel_analysis(). It provides a
        shorter, more intuitive name that LLMs naturally suggest when
        canceling pending analysis.

        Args:
            start: Start address of range
            end: End address of range (exclusive)

        Raises:
            InvalidEAError: If start or end address is invalid
            InvalidParameterError: If start >= end

        Example:
            >>> db = Database.open_current()
            >>> # Cancel pending analysis for data section
            >>> db.analysis.cancel(0x403000, 0x404000)

        Note:
            This method is functionally identical to cancel_analysis().
            Use whichever name feels more natural for your workflow.
        """
        return self.cancel_analysis(start, end)

    def cancel_analysis(self, start: ea_t, end: ea_t) -> None:
        """
        Cancel pending analysis for address range.

        Removes the specified range from CODE, PROC, and USED queues. Use this
        to prevent IDA from analyzing a specific region.

        Args:
            start: Start address of range
            end: End address of range (exclusive)

        Raises:
            InvalidEAError: If start or end address is invalid
            InvalidParameterError: If start >= end

        Example:
            >>> db = Database.open_current()
            >>> # Cancel pending analysis for data section
            >>> db.analysis.cancel_analysis(0x403000, 0x404000)
        """
        # Validate inputs
        if not self.database.is_valid_ea(start):
            raise InvalidEAError(start)
        if not self.database.is_valid_ea(end):
            raise InvalidEAError(end)
        if start >= end:
            raise InvalidParameterError('start', start, 'must be less than end')

        # Cancel analysis for range
        ida_auto.auto_cancel(start, end)

    def cancel_queue(self, start: ea_t, end: ea_t, queue_type: AnalysisQueueType) -> None:
        """
        Remove address range from specific queue.

        More precise than cancel_analysis() - removes range from a single
        specific queue.

        Args:
            start: Start address of range
            end: End address of range (exclusive)
            queue_type: Which queue to remove the range from

        Raises:
            InvalidEAError: If start or end address is invalid
            InvalidParameterError: If start >= end or queue_type is invalid

        Example:
            >>> db = Database.open_current()
            >>> # Remove only from CODE queue
            >>> db.analysis.cancel_queue(
            ...     0x401000,
            ...     0x402000,
            ...     AnalysisQueueType.CODE
            ... )
        """
        # Validate inputs
        if not self.database.is_valid_ea(start):
            raise InvalidEAError(start)
        if not self.database.is_valid_ea(end):
            raise InvalidEAError(end)
        if start >= end:
            raise InvalidParameterError('start', start, 'must be less than end')

        # Remove from specified queue
        ida_auto.auto_unmark(start, end, queue_type.value)

    # ========================================================================
    # ADVANCED OPERATIONS
    # ========================================================================

    def show_addr(self, ea: ea_t) -> None:
        """
        Show an address on the autoanalysis indicator.

        This method updates the IDA UI auto-analysis indicator to display
        a specific address. The address is displayed in the form @:12345678.
        This is primarily for UI display purposes and is rarely needed in
        scripts.

        Args:
            ea: Address to display on indicator

        Raises:
            InvalidEAError: If address is invalid

        Example:
            >>> db = Database.open_current()
            >>> # Show address on UI indicator
            >>> db.analysis.show_addr(0x401000)

        Note:
            This is a UI-only function and does not affect analysis behavior.
            Most scripts should use show_auto() for more control.

        See Also:
            show_auto: More flexible method with queue type parameter
            noshow_auto: To hide the indicator
        """
        # Validate address
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Show address on UI indicator
        ida_auto.show_addr(ea)

    def reanalyze_function_callers(self, func_ea: ea_t, function_noreturn: bool = False) -> None:
        """
        Schedule reanalysis of all instructions that call the specified function.

        Use this after changing a function's prototype or attributes (such as
        marking it as noreturn) to ensure all call sites are updated with the
        new information. This adds all caller instructions to the AU_USED queue
        for reanalysis.

        Args:
            func_ea: Address of function whose callers should be reanalyzed
            function_noreturn: If True, indicates the function doesn't return,
                which affects control flow analysis at call sites

        Raises:
            InvalidEAError: If func_ea is invalid

        Example:
            >>> db = Database.open_current()
            >>> # Change function to noreturn
            >>> func = db.functions.get_at(0x401000)
            >>> # ... mark function as noreturn ...
            >>> # Reanalyze all callers to update flow analysis
            >>> db.analysis.reanalyze_function_callers(0x401000, function_noreturn=True)
            >>> db.analysis.wait_for_completion()

        Note:
            If function_noreturn is True, IDA will mark instructions after
            call sites for removal since the function doesn't return.
        """
        # Validate address
        if not self.database.is_valid_ea(func_ea):
            raise InvalidEAError(func_ea)

        # Reanalyze all callers
        ida_auto.reanalyze_callers(func_ea, function_noreturn)

    def recreate_instruction(self, ea: ea_t) -> bool:
        """
        Delete and recreate instruction at address.

        Forces IDA to discard the current instruction and re-decode it from
        scratch. This is useful when the instruction decoding is incorrect
        or after manually modifying the bytes at the address.

        Args:
            ea: Address of instruction to recreate

        Returns:
            True if instruction was successfully recreated (length > 0),
            False if instruction creation failed

        Raises:
            InvalidEAError: If address is invalid

        Example:
            >>> db = Database.open_current()
            >>> # Modify bytes manually
            >>> db.bytes.patch_byte(0x401000, 0x90)
            >>> # Force instruction recreation
            >>> if db.analysis.recreate_instruction(0x401000):
            ...     print("Instruction recreated successfully")
            >>> else:
            ...     print("Failed to recreate instruction")

        Note:
            This function calls auto_recreate_insn() which returns the new
            instruction length, or 0 if recreation failed.
        """
        # Validate address
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Recreate instruction - returns length (>0 on success, 0 on failure)
        result = ida_auto.auto_recreate_insn(ea)

        # Result > 0 means success
        return bool(result > 0)

    def revert_analysis(self, start: ea_t, end: ea_t) -> None:
        """
        Revert IDA's analysis decisions for an address range.

        Eliminates all analysis information that IDA generated for the
        specified range, effectively converting analyzed code/data back
        to unexplored bytes. This is useful when IDA's automatic analysis
        made incorrect decisions.

        Args:
            start: Start address of range
            end: End address of range (exclusive)

        Raises:
            InvalidEAError: If start or end address is invalid
            InvalidParameterError: If start >= end

        Example:
            >>> db = Database.open_current()
            >>> # Revert incorrect analysis
            >>> db.analysis.revert_analysis(0x401000, 0x402000)
            >>> # Now you can re-analyze the range manually
            >>> db.analysis.analyze_range(0x401000, 0x402000)

        Warning:
            This operation destroys all analysis information in the range,
            including functions, names, comments, and type information.
            Use with caution.

        Note:
            After reverting, you typically want to re-analyze the range
            with different parameters or manual intervention.
        """
        # Validate inputs
        if not self.database.is_valid_ea(start):
            raise InvalidEAError(start)
        if not self.database.is_valid_ea(end):
            raise InvalidEAError(end)
        if start >= end:
            raise InvalidParameterError('start', start, 'must be less than end')

        # Revert IDA decisions for the range
        ida_auto.revert_ida_decisions(start, end)
