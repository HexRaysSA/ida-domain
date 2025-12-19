from __future__ import annotations

import functools
import logging
import warnings
from collections.abc import Callable

from ida_idaapi import ea_t
from typing_extensions import TYPE_CHECKING, Any, Optional, ParamSpec, TypeVar, cast

logger = logging.getLogger(__name__)

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


class InvalidEAError(LookupError):
    """
    Raised when an operation is attempted on an invalid effective address.
    """

    def __init__(self, ea: ea_t) -> None:
        super().__init__(f'Invalid effective address: 0x{ea:x}')


class InvalidParameterError(ValueError):
    """
    Raised when a function receives invalid arguments.
    """

    def __init__(self, parameter: str, value: object, message: str) -> None:
        super().__init__(f'Invalid parameter {parameter} value {str(value)}: {message}')


class DatabaseNotLoadedError(RuntimeError):
    """
    Raised when an operation is attempted on a closed database.
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


def deprecated(reason: str) -> Callable[[F], F]:
    """
    Decorator to mark functions as deprecated.

    Args:
        reason: Message explaining what to use instead.

    Example:
        @deprecated("Use get_in_range instead")
        def get_between(self, start, end):
            ...
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            warnings.warn(
                f"{func.__qualname__} is deprecated. {reason}",
                DeprecationWarning,
                stacklevel=2
            )
            return func(*args, **kwargs)
        return cast(F, wrapper)
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
