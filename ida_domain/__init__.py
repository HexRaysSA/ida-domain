from __future__ import annotations

import logging
from logging import NullHandler


def _load_dependencies() -> None:
    """
    Load required dependencies

    This needs to work both inside and outside IDA. This module works on top of IDA Python.
    When running inside IDA, IDA Python is already available. When running outside IDA, we need
    to explicitly import idapro, which loads the IDA kernel libraries and IDA Python for us.
    """

    # Check if IDA Python is already loaded
    try:
        import ida_kernwin

        need_idapro = ida_kernwin.is_ida_library(None, 0, None)
    except ImportError:
        need_idapro = True

    if need_idapro:
        import idapro


__version__ = '0.1.0'

# Make sure all dependencies are loaded
_load_dependencies()


# Keep the ida kernel version as int, eg: 920
import ida_ida

__ida_version__: int = ida_ida.inf_get_version()

if __ida_version__ < 910:
    raise ImportError('IDA Domain requires IDA 9.1.0 or later')

# If we reach this point kernel libraries were successfully loaded
from .database import Database

logging.getLogger(__name__).addHandler(NullHandler())
