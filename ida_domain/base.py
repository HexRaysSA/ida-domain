from __future__ import annotations

import functools
import logging
import warnings
from collections.abc import Callable
from enum import EnumMeta

import ida_kernwin
from ida_idaapi import ea_t
from packaging.version import Version
from typing_extensions import TYPE_CHECKING, Any, Dict, Optional, ParamSpec, Tuple, TypeVar, cast

logger = logging.getLogger(__name__)

_ida_version = Version(ida_kernwin.get_kernel_version())


class NotSupportedWarning(Warning):
    """Warning for unsupported features in the underlying idapython API"""

    pass


_VERSION_SUPPORT_CHECK: Dict[Tuple[str, str], Callable[[], bool]] = {}


def _is_supported(type_name: str, attr: str, warn: bool = True) -> bool:
    checker = _VERSION_SUPPORT_CHECK.get((type_name, attr))
    supported = checker is None or checker()
    if not supported and warn:
        warnings.warn(
            f'{type_name}.{attr} is not supported in IDA version {_ida_version}',
            category=NotSupportedWarning,
            stacklevel=1,
        )
    return supported


class _GatedInt(int):
    """An int that carries a minimum IDA version requirement."""

    min_version: Version
    needs_placeholder: bool

    def __new__(
        cls, value: int, min_version: str, needs_placeholder: bool = False,
    ) -> _GatedInt:
        obj = super().__new__(cls, value)
        obj.min_version = Version(min_version)
        obj.needs_placeholder = needs_placeholder
        return obj


class _CheckAttrSupport(EnumMeta):
    def __new__(mcs, name: str, bases: Any, namespace: Any, **kwargs: Any) -> Any:
        # Capture _GatedInt values before super().__new__ converts them to int
        placeholder = -1
        for mname, mval in list(namespace.items()):
            if isinstance(mval, _GatedInt):
                req = mval.min_version

                def _check(v: Version = req) -> bool:
                    return _ida_version >= v

                _VERSION_SUPPORT_CHECK[(name, mname)] = _check

                if mval.needs_placeholder:
                    dict.__setitem__(
                        namespace, mname, _GatedInt(placeholder, str(req)),
                    )
                    placeholder -= 1

        cls = super().__new__(mcs, name, bases, namespace, **kwargs)
        return cls

    def __getattribute__(cls, name):  # type: ignore
        obj = super().__getattribute__(name)
        _is_supported(type(obj).__name__, name)
        return obj


def _since_ida(
    min_version: str,
    module: Optional[object] = None,
    attr: Optional[str] = None,
    *,
    value: Any = None,
) -> int:
    """Mark an enum member as requiring a minimum IDA version.

    The returned value is a :class:`_GatedInt` that
    :class:`_CheckAttrSupport` detects during enum class creation
    and auto-registers a version check for.

    Can be used in two ways::

        # Read a constant from an IDA module (placeholder if missing)
        EMULATOR = _since_ida('9.2', ida_hexrays, 'MERR_EMULATOR')

        # Wrap an existing value
        TUPLE = _since_ida('9.2', value=64)

    Args:
        min_version: Minimum IDA version (e.g. ``"9.2"``).
        module: The ``ida_*`` module to read the constant from.
        attr: Constant name in *module* (e.g. ``"MERR_EMULATOR"``).
        value: Direct value to wrap (mutually exclusive with module/attr).
    """
    if value is not None:
        return _GatedInt(value, min_version)
    if module is not None and attr is not None:
        resolved = getattr(module, attr, None)
        if resolved is not None:
            return _GatedInt(resolved, min_version)
        return _GatedInt(0, min_version, needs_placeholder=True)
    raise ValueError('_since_ida requires either (module, attr) or value=')


if TYPE_CHECKING:
    from .database import Database


class DatabaseEntity:
    """
    Base class for all Database entities.
    """

    def __init__(self, database: Optional[Database]):
        """
        Constructs a database entity for the given database.

        Args:
            database: Reference to the active IDA database.
        """
        self.m_database = database

    @property
    def database(self) -> Database:
        """
        Get the database reference, guaranteed to be non-None when called from
        methods decorated with @check_db_open.

        Returns:
            The active database instance.

        Note:
            This property should only be used in methods decorated with @check_db_open,
            which ensures m_database is not None.
        """
        if TYPE_CHECKING:
            from .database import Database

            return cast('Database', self.m_database)

        # Runtime assertion - should never fail if decorator is used correctly
        assert self.m_database is not None, (
            'Database is None - ensure method is decorated with @check_db_open'
        )
        return self.m_database


F = TypeVar('F', bound=Callable[..., Any])
C = TypeVar('C', bound=type)
P = ParamSpec('P')
R = TypeVar('R')


class IdaDomainError(Exception):
    """
    Base exception for all ida-domain errors.
    """

    pass


class InvalidEAError(IdaDomainError, LookupError):
    """
    Raised when an operation is attempted on an invalid effective address.
    """

    def __init__(self, ea: ea_t) -> None:
        super().__init__(f'Invalid effective address: 0x{ea:x}')


class InvalidParameterError(IdaDomainError, ValueError):
    """
    Raised when a function receives invalid arguments.
    """

    def __init__(self, parameter: str, value: object, message: str) -> None:
        super().__init__(f'Invalid parameter {parameter} value {str(value)}: {message}')


class DatabaseNotLoadedError(IdaDomainError, RuntimeError):
    """
    Raised when an operation is attempted on a closed database.
    """

    pass


class DatabaseError(IdaDomainError):
    """
    Raised when a database operation fails.
    """

    pass


class SerializationError(IdaDomainError):
    """
    Raised when packing or unpacking a typed object fails.
    """

    pass


class NoValueError(IdaDomainError, ValueError):
    """
    Raised when a read operation is attempted on an uninitialized address.
    """

    def __init__(self, ea: ea_t) -> None:
        super().__init__(f'The effective address: 0x{ea:x} has no value')


class UnsupportedValueError(IdaDomainError, ValueError):
    """
    Raised when a read operation is attempted on a value which has an unsupported format.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)


class DecompilerError(IdaDomainError):
    """
    Raised when a decompiler operation fails.
    """

    pass


def decorate_all_methods(decorator: Callable[[F], F]) -> Callable[[C], C]:
    """
    Class decorator factory that applies `decorator` to all methods
    of the class (excluding dunder methods and static methods).
    """

    def decorate(cls: C) -> C:
        for name, attr in cls.__dict__.items():
            if name.startswith('__'):
                continue
            # Skip static methods and class methods
            if isinstance(attr, (staticmethod, classmethod)):
                continue
            if callable(attr):
                setattr(cls, name, decorator(attr))
        return cls

    return decorate


def requires_ida(min_version: str) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorator that raises an error if the IDA version is below *min_version*."""
    _required = Version(min_version)

    def decorator(fn: Callable[P, R]) -> Callable[P, R]:
        if _ida_version >= _required:
            return fn

        @functools.wraps(fn)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            raise NotImplementedError(
                f'{fn.__qualname__} requires IDA {min_version}+, '
                f'current version is {_ida_version}'
            )

        return wrapper

    return decorator


def check_db_open(fn: Callable[P, R]) -> Callable[P, R]:
    """
    Decorator that checks that a database is open.
    """

    @functools.wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        # Check inside database class
        if args:
            self = args[0]

            # Check class name as string (avoid circular dependency)
            if self.__class__.__name__ == 'Database':
                if hasattr(self, 'is_open') and not self.is_open():
                    raise DatabaseNotLoadedError(
                        f'{fn.__qualname__}: Database is not loaded. Please open a database first.'
                    )

            # Check DatabaseEntity instances
            if isinstance(self, DatabaseEntity):
                if not self.m_database or not self.m_database.is_open():
                    raise DatabaseNotLoadedError(
                        f'{fn.__qualname__}: Database is not loaded. Please open a database first.'
                    )

        return fn(*args, **kwargs)

    return wrapper
