"""Compatibility shims for IDA SDK functions that vary across IDA versions.

Each shim exposes a single, stable signature for use throughout ida_domain.
At import time, capability detection (``hasattr``) selects the most modern
SDK function available and falls back to the closest equivalent on older
IDA versions. Call sites import the shim and remain unchanged as IDA evolves.

Scope: only functions whose direct SDK name differs across supported IDA
versions, or whose calling/iteration protocol has changed. Deprecated SDK
calls that still work uniformly across versions are kept at the call site
and migrated separately when the surrounding public API can be reshaped.
"""

from __future__ import annotations

from typing import Any, Iterator, Optional, Tuple

import ida_funcs
import ida_hexrays
import ida_range
import ida_segment
from ida_funcs import func_t
from ida_idaapi import ea_t


# --- ida_funcs ---------------------------------------------------------------

if hasattr(ida_funcs, 'is_function_entry'):
    def is_function_entry(ea: ea_t) -> bool:
        return ida_funcs.is_function_entry(ea)
else:
    def is_function_entry(ea: ea_t) -> bool:
        chunk = ida_funcs.get_func(ea)
        return chunk is not None and ida_funcs.is_func_entry(chunk)


if hasattr(ida_funcs, 'is_function_tail'):
    def is_function_tail(ea: ea_t) -> bool:
        return ida_funcs.is_function_tail(ea)
else:
    def is_function_tail(ea: ea_t) -> bool:
        chunk = ida_funcs.get_fchunk(ea)
        return chunk is not None and ida_funcs.is_func_tail(chunk)


if hasattr(ida_funcs, 'get_func_cmt_ea'):
    def get_func_cmt_ea(ea: ea_t, repeatable: bool) -> Optional[str]:
        return ida_funcs.get_func_cmt_ea(ea, repeatable)
else:
    def get_func_cmt_ea(ea: ea_t, repeatable: bool) -> Optional[str]:
        func = ida_funcs.get_func(ea)
        if func is None:
            return None
        return ida_funcs.get_func_cmt(func, repeatable)


if hasattr(ida_funcs, 'set_func_cmt_ea'):
    def set_func_cmt_ea(ea: ea_t, cmt: str, repeatable: bool) -> bool:
        return ida_funcs.set_func_cmt_ea(ea, cmt, repeatable)
else:
    def set_func_cmt_ea(ea: ea_t, cmt: str, repeatable: bool) -> bool:
        func = ida_funcs.get_func(ea)
        if func is None:
            return False
        return ida_funcs.set_func_cmt(func, cmt, repeatable)


def iter_func_tail_ranges(func: func_t) -> Iterator[Tuple[ea_t, ea_t]]:
    """Yield ``(start_ea, end_ea)`` for each tail chunk of ``func``.

    Hides the iterator-protocol differences between ``func_tail_iterator_t``
    (``__iter__`` yielding ``range_t``) and ``function_tail_iterator_t``
    (no ``__iter__``; ``chunk(out)`` fills an out parameter).
    """
    if hasattr(ida_funcs, 'function_tail_iterator_t'):
        it = ida_funcs.function_tail_iterator_t(func.start_ea)
        out = ida_range.range_t()
        ok = it.main()
        while ok:
            it.chunk(out)
            yield out.start_ea, out.end_ea
            ok = it.__next__()
    else:
        for tail in ida_funcs.func_tail_iterator_t(func):
            yield tail.start_ea, tail.end_ea


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


# --- ida_hexrays ------------------------------------------------------------

def make_decomp_ranges(func: Optional[func_t] = None) -> Any:
    """Build a ranges object for ``gen_microcode``.

    Pass ``func`` for function mode. Omit it (or pass ``None``) for snippet
    mode and have the caller populate ``.ranges`` afterward. Returns
    ``decomp_ranges_t`` where available, falling back to ``mba_ranges_t``.
    """
    if hasattr(ida_hexrays, 'decomp_ranges_t'):
        ranges = ida_hexrays.decomp_ranges_t()
        if func is not None:
            ranges.func_ea = func.start_ea
        return ranges
    if func is not None:
        return ida_hexrays.mba_ranges_t(func)
    return ida_hexrays.mba_ranges_t()
