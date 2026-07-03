"""Compatibility shims for IDA SDK functions that vary across IDA versions.

Each shim exposes a single, stable signature for use throughout ida_domain.
At import time, capability detection (``hasattr``) selects the most modern
SDK function available and falls back to the closest equivalent on older
IDA versions. Call sites import the shim and remain unchanged as IDA evolves.
"""

from __future__ import annotations

import warnings
from typing import Any, Iterator, List, Optional, Tuple

import ida_frame
import ida_funcs
import ida_gdl
import ida_hexrays
import ida_range
import ida_segment
from ida_idaapi import BADADDR, ea_t

# --- ida_funcs ---------------------------------------------------------------


def func_ea(func: Any) -> ea_t:
    """Normalize a function argument to an effective address.

    Accepts an address, any object with a ``start_ea`` attribute
    (``FunctionInfo``, ``FunctionChunk``), or a ``func_t`` - the deprecated
    handle type this module exists to migrate away from; passing one emits
    a ``DeprecationWarning``.
    """
    if isinstance(func, ida_funcs.func_t):
        warnings.warn(
            'passing func_t is deprecated; pass an ea or FunctionInfo instead',
            DeprecationWarning,
            stacklevel=3,
        )
        return func.start_ea
    return func if isinstance(func, int) else func.start_ea


if hasattr(ida_funcs, 'is_function_entry'):
    is_function_entry = ida_funcs.is_function_entry
else:

    def is_function_entry(ea: ea_t) -> bool:
        chunk = ida_funcs.get_fchunk(ea)
        return chunk is not None and ida_funcs.is_func_entry(chunk)


if hasattr(ida_funcs, 'is_function_tail'):
    is_function_tail = ida_funcs.is_function_tail
else:

    def is_function_tail(ea: ea_t) -> bool:
        chunk = ida_funcs.get_fchunk(ea)
        return chunk is not None and ida_funcs.is_func_tail(chunk)


if hasattr(ida_funcs, 'get_func_cmt_ea'):
    get_func_cmt_ea = ida_funcs.get_func_cmt_ea
else:

    def get_func_cmt_ea(ea: ea_t, repeatable: bool) -> Optional[str]:
        func = ida_funcs.get_func(ea)
        if func is None:
            return None
        return ida_funcs.get_func_cmt(func, repeatable)


if hasattr(ida_funcs, 'set_func_cmt_ea'):
    set_func_cmt_ea = ida_funcs.set_func_cmt_ea
else:

    def set_func_cmt_ea(ea: ea_t, cmt: str, repeatable: bool) -> bool:
        func = ida_funcs.get_func(ea)
        if func is None:
            return False
        return ida_funcs.set_func_cmt(func, cmt, repeatable)


if hasattr(ida_funcs, 'get_func_start'):
    get_func_start = ida_funcs.get_func_start
else:

    def get_func_start(ea: ea_t) -> ea_t:
        func = ida_funcs.get_func(ea)
        return BADADDR if func is None else func.start_ea


if hasattr(ida_funcs, 'get_func_flags'):
    get_func_flags = ida_funcs.get_func_flags
else:

    def get_func_flags(ea: ea_t) -> int:
        func = ida_funcs.get_func(ea)
        return 0 if func is None else func.flags


if hasattr(ida_funcs, 'get_func_ea_by_num'):
    get_func_ea_by_num = ida_funcs.get_func_ea_by_num
else:

    def get_func_ea_by_num(n: int) -> ea_t:
        func = ida_funcs.getn_func(n)
        return BADADDR if func is None else func.start_ea


if hasattr(ida_funcs, 'get_next_func_ea'):
    get_next_func_ea = ida_funcs.get_next_func_ea
else:

    def get_next_func_ea(ea: ea_t) -> ea_t:
        func = ida_funcs.get_next_func(ea)
        return BADADDR if func is None else func.start_ea


if hasattr(ida_funcs, 'get_tail_owner'):
    get_tail_owner = ida_funcs.get_tail_owner
else:

    def get_tail_owner(tail_ea: ea_t) -> ea_t:
        chunk = ida_funcs.get_fchunk(tail_ea)
        if chunk is None or not ida_funcs.is_func_tail(chunk):
            return BADADDR
        return chunk.owner


if hasattr(ida_funcs, 'get_fchunk_info'):

    def fchunk_at(ea: ea_t) -> Optional[Tuple[ea_t, ea_t, bool]]:
        """Return ``(start_ea, end_ea, is_tail)`` of the chunk at ``ea``."""
        info = ida_funcs.fchunk_info_t()
        if not ida_funcs.get_fchunk_info(info, ea):
            return None
        return info.start_ea, info.end_ea, info.is_tail()
else:

    def fchunk_at(ea: ea_t) -> Optional[Tuple[ea_t, ea_t, bool]]:
        """Return ``(start_ea, end_ea, is_tail)`` of the chunk at ``ea``."""
        chunk = ida_funcs.get_fchunk(ea)
        if chunk is None:
            return None
        return chunk.start_ea, chunk.end_ea, ida_funcs.is_func_tail(chunk)


if hasattr(ida_funcs, 'get_func_entry_info'):

    def func_entry_info_at(ea: ea_t) -> Optional[Tuple[ea_t, ea_t, int, str]]:
        """Return ``(start_ea, end_ea, flags, name)`` of the function at ``ea``."""
        info = ida_funcs.func_entry_info_t()
        if not ida_funcs.get_func_entry_info(info, ea, ida_funcs.GFI_NAME):
            return None
        return info.start_ea, info.end_ea, info.get_flags(), info.get_name() or ''
else:

    def func_entry_info_at(ea: ea_t) -> Optional[Tuple[ea_t, ea_t, int, str]]:
        """Return ``(start_ea, end_ea, flags, name)`` of the function at ``ea``."""
        func = ida_funcs.get_func(ea)
        if func is None:
            return None
        name = ida_funcs.get_func_name(func.start_ea) or ''
        return func.start_ea, func.end_ea, func.flags, name


def iter_func_tail_ranges(func_ea: ea_t) -> Iterator[Tuple[ea_t, ea_t]]:
    """Yield ``(start_ea, end_ea)`` for each chunk of the function at
    ``func_ea``, main chunk first. Yields nothing if there is no function.

    Hides the iterator-protocol differences between ``func_tail_iterator_t``
    (``__iter__`` yielding ``range_t``) and ``function_tail_iterator_t``
    (no ``__iter__``; ``chunk(out)`` fills an out parameter).
    """
    if hasattr(ida_funcs, 'function_tail_iterator_t'):
        it = ida_funcs.function_tail_iterator_t(func_ea)
        out = ida_range.range_t()
        ok = it.main()
        while ok:
            it.chunk(out)
            yield out.start_ea, out.end_ea
            ok = it.__next__()
    else:
        func = ida_funcs.get_func(func_ea)
        if func is None:
            return
        for tail in ida_funcs.func_tail_iterator_t(func):
            yield tail.start_ea, tail.end_ea


# --- ida_frame ---------------------------------------------------------------

if hasattr(ida_frame, 'get_func_stkpnts'):

    def get_func_stack_points(func_ea: ea_t) -> List[Tuple[ea_t, int]]:
        """Return ``(ea, spd)`` for each SP change point of the function."""
        out = ida_frame.stkpnts_t()
        if not ida_frame.get_func_stkpnts(out, func_ea):
            return []
        return [(out.at(i).ea, out.at(i).spd) for i in range(out.size())]
else:

    def get_func_stack_points(func_ea: ea_t) -> List[Tuple[ea_t, int]]:
        """Return ``(ea, spd)`` for each SP change point of the function."""
        func = ida_funcs.get_func(func_ea)
        if func is None:
            return []
        return [(func.points[i].ea, func.points[i].spd) for i in range(func.pntqty)]


# --- ida_gdl -----------------------------------------------------------------

if hasattr(ida_gdl, 'qflow_chart_ea_t'):

    def make_qflow_chart(func: Any, start: ea_t, end: ea_t, flags: int) -> Any:
        """Build a qflow chart for a function or an address range.

        ``func`` accepts anything :func:`func_ea` accepts, or ``None`` for
        a range-based chart.
        """
        ea = BADADDR if func is None else func_ea(func)
        return ida_gdl.qflow_chart_ea_t('', ea, start, end, flags)
else:

    def make_qflow_chart(func: Any, start: ea_t, end: ea_t, flags: int) -> Any:
        """Build a qflow chart for a function or an address range.

        ``func`` accepts anything :func:`func_ea` accepts, or ``None`` for
        a range-based chart.
        """
        pfn = None if func is None else ida_funcs.get_func(func_ea(func))
        return ida_gdl.qflow_chart_t('', pfn, start, end, flags)


# --- ida_segment ------------------------------------------------------------

if hasattr(ida_segment, 'get_segment_name'):

    def get_segment_name(ea: ea_t, flags: int = 0) -> str:
        return ida_segment.get_segment_name(ea, flags)
else:

    def get_segment_name(ea: ea_t, flags: int = 0) -> str:
        seg = ida_segment.getseg(ea)
        if seg is None:
            return ''
        return ida_segment.get_segm_name(seg, flags)


if hasattr(ida_segment, 'set_segment_name'):

    def set_segment_name(ea: ea_t, name: str, flags: int = 0) -> int:
        return ida_segment.set_segment_name(ea, name, flags)
else:

    def set_segment_name(ea: ea_t, name: str, flags: int = 0) -> int:
        seg = ida_segment.getseg(ea)
        if seg is None:
            return 0
        return ida_segment.set_segm_name(seg, name, flags)


if hasattr(ida_segment, 'set_segment_addressing'):

    def set_segment_addressing(ea: ea_t, bitness: int) -> bool:
        return ida_segment.set_segment_addressing(ea, bitness)
else:

    def set_segment_addressing(ea: ea_t, bitness: int) -> bool:
        seg = ida_segment.getseg(ea)
        if seg is None:
            return False
        return ida_segment.set_segm_addressing(seg, bitness)


if hasattr(ida_segment, 'get_segment_cmt_by_ea'):

    def get_segment_cmt_by_ea(ea: ea_t, repeatable: bool) -> Optional[str]:
        return ida_segment.get_segment_cmt_by_ea(ea, repeatable)
else:

    def get_segment_cmt_by_ea(ea: ea_t, repeatable: bool) -> Optional[str]:
        seg = ida_segment.getseg(ea)
        if seg is None:
            return None
        return ida_segment.get_segment_cmt(seg, repeatable)


if hasattr(ida_segment, 'set_segment_cmt_by_ea'):

    def set_segment_cmt_by_ea(ea: ea_t, cmt: str, repeatable: bool) -> None:
        ida_segment.set_segment_cmt_by_ea(ea, cmt, repeatable)
else:

    def set_segment_cmt_by_ea(ea: ea_t, cmt: str, repeatable: bool) -> None:
        seg = ida_segment.getseg(ea)
        if seg is None:
            return
        ida_segment.set_segment_cmt(seg, cmt, repeatable)


if hasattr(ida_segment, 'get_last_segment_ea'):

    def get_last_segment_end_ea() -> Optional[ea_t]:
        start_ea = ida_segment.get_last_segment_ea()
        if start_ea == BADADDR:
            return None
        info = ida_segment.segment_info_t()
        if not ida_segment.get_segment_info(info, start_ea):
            return None
        return info.end_ea
else:

    def get_last_segment_end_ea() -> Optional[ea_t]:
        seg = ida_segment.get_last_seg()
        return None if seg is None else seg.end_ea


if hasattr(ida_segment, 'get_segment_info'):

    def get_segment_permissions(ea: ea_t) -> Optional[int]:
        info = ida_segment.segment_info_t()
        if not ida_segment.get_segment_info(info, ea):
            return None
        return info.get_perm()

    def set_segment_permissions(ea: ea_t, perm: int) -> bool:
        info = ida_segment.segment_info_t()
        if not ida_segment.get_segment_info(info, ea):
            return False
        info.set_perm(perm)
        return ida_segment.set_segment_info(info)
else:

    def get_segment_permissions(ea: ea_t) -> Optional[int]:
        seg = ida_segment.getseg(ea)
        return None if seg is None else seg.perm

    def set_segment_permissions(ea: ea_t, perm: int) -> bool:
        seg = ida_segment.getseg(ea)
        if seg is None:
            return False
        seg.perm = perm
        return True


# --- ida_hexrays ------------------------------------------------------------


def make_decomp_ranges(func_ea: Optional[ea_t] = None) -> Any:
    """Build a ranges object for ``gen_microcode``.

    Pass ``func_ea`` (any address inside the function) for function mode.
    Omit it (or pass ``None``) for snippet mode and have the caller populate
    ``.ranges`` afterward. Returns ``decomp_ranges_t`` where available,
    falling back to ``mba_ranges_t``.
    """
    if hasattr(ida_hexrays, 'decomp_ranges_t'):
        ranges = ida_hexrays.decomp_ranges_t()
        if func_ea is not None:
            # decomp_ranges_t requires the entry address; resolve to match
            # the mba_ranges_t fallback, which accepts any ea via get_func
            ranges.func_ea = get_func_start(func_ea)
        return ranges
    if func_ea is not None:
        return ida_hexrays.mba_ranges_t(ida_funcs.get_func(func_ea))
    return ida_hexrays.mba_ranges_t()
