from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from packaging.version import Version
from typing_extensions import TYPE_CHECKING, List, Optional

from .base import InvalidParameterError, requires_ida

if TYPE_CHECKING:
    import ida_license
else:
    try:
        import ida_license
    except ImportError:
        ida_license = None

logger = logging.getLogger(__name__)


def _to_datetime(seconds: int) -> Optional[datetime]:
    return datetime.fromtimestamp(seconds, tz=timezone.utc) if seconds else None


def _to_version(encoded: int) -> Optional[Version]:
    return Version(f'{encoded // 100}.{encoded % 100}') if encoded else None


class License:
    """
    Provides access to and control over the active IDA license.

    A license may be not automatically selected until a database is loaded.

    Requires IDA 9.5 or later.
    """

    @requires_ida('9.5')
    def __init__(self) -> None:
        self._license = ida_license.License()

    @property
    def is_valid(self) -> bool:
        """
        Whether there is a usable active license.

        False if there is no license or its activation period is not in effect.
        A floating license is usable only while this IDA instance holds it
        (a checked out seat or an unexpired borrow).
        """
        return self._license.valid

    @property
    def is_floating(self) -> bool:
        """
        Whether the active license is a floating license, served by a license
        server, rather than a named license. False if there is no license.
        """
        return self._license.floating

    @property
    def is_decompiler_available(self) -> bool:
        """
        Whether a decompiler is available for the current database.

        False if no database is open, there is no decompiler for it, the
        decompiler add-on is not part of the license, or its activation
        period has not started or has expired.
        """
        return self._license.decompiler_available

    @property
    def id(self) -> Optional[str]:
        """
        The ID of the active license, in the "XX-XXXX-XXXX-XX" form,
        or None if there is no license selected.
        """
        return self._license.id or None

    @property
    def source_ids(self) -> List[str]:
        """
        The IDs of all licenses provided by the active license source.

        A license file may contain several licenses; for a license server,
        the licenses listed when the seat was acquired are reported.
        The list is not filtered by validity. Empty if there is no license source.
        """
        return self._license.source_ids

    @property
    def product(self) -> Optional[str]:
        """
        The product of the active license, e.g. "IDAPRO", "IDAHOME",
        or None if there is no license.
        """
        return self._license.product or None

    @property
    def edition(self) -> Optional[str]:
        """
        The edition of the active license, e.g. "ida-pro", "ida-home-arm",
        or None if there is no license.

        The value is informational, for display purposes; use `has_add_on()`
        and `has_feature()` to check what the license covers.
        """
        return self._license.edition or None

    @property
    def description(self) -> Optional[str]:
        """
        The description of the active license, or None if there is no license
        or the license has no description.
        """
        return self._license.description or None

    @property
    def product_version(self) -> Optional[Version]:
        """
        The product version the active license is bound to, e.g. Version("9.4"),
        or None if there is no license or the license is not bound to a version.
        """
        return _to_version(self._license.product_version)

    @property
    def start_date(self) -> Optional[datetime]:
        """The start of the activation period (UTC), or None if there is no license."""
        return _to_datetime(self._license.start)

    @property
    def end_date(self) -> Optional[datetime]:
        """
        The end of the activation period (UTC), or None if there is no license
        or the license never expires.

        The license remains usable during a grace period after this time.
        A borrowed floating license may stop being usable earlier,
        at the end of the borrow period.
        """
        return _to_datetime(self._license.end)

    @property
    def issued_on(self) -> Optional[datetime]:
        """The time the active license was issued (UTC), or None if there is no license."""
        return _to_datetime(self._license.issued_on)

    @property
    def add_ons(self) -> List[str]:
        """
        The product codes of all currently usable add-ons of the active license,
        e.g. ["HEXX64", "LUMINA"]. Empty if there is no usable license.
        """
        return self._license.add_ons

    @property
    def features(self) -> List[str]:
        """The features of the active license. Empty if there is no usable license."""
        return self._license.features

    def has_add_on(self, name: str) -> bool:
        """
        Check if the active license is usable, contains the given add-on,
        and the add-on activation period is in effect.

        Args:
            name: Add-on product code, e.g. "HEXX64", "LUMINA" (case sensitive).

        Returns:
            False if there is no usable license, the add-on is not part of the
            license, or its activation period has not started or has expired.
        """
        return self._license.has_add_on(name)

    def has_feature(self, name: str) -> bool:
        """
        Check if the active license is usable and includes the given feature.

        Args:
            name: Feature name (case sensitive).

        Returns:
            False if there is no usable license or the feature is not part of the license.
        """
        return self._license.has_feature(name)

    def add_on_end_date(self, name: str) -> Optional[datetime]:
        """
        Get the end of the activation period of an add-on of the active license.

        The add-on remains usable during a grace period after this time.

        Args:
            name: Add-on product code, e.g. "HEXX64", "LUMINA" (case sensitive).

        Returns:
            The end of the activation period (UTC), or None if there is no license,
            the add-on is not part of it, or the add-on never expires.
        """
        return _to_datetime(self._license.add_on_end(name))

    def set_file(self, path: str) -> bool:
        """
        Use a license file as the license source and activate its license.

        The choice is not saved as the preferred license.

        Args:
            path: Path of the license file.

        Returns:
            True if a license from the file was activated, False otherwise
            (e.g. the file does not exist, is not a valid license file,
            or holds no usable license for this IDA product).
        """
        return self._license.set_file(path)

    def set_server(self, host: str, port: int, use_tls: bool = True) -> bool:
        """
        Use a license server as the license source and check out a license from it.

        The choice is not saved as the preferred license.

        Args:
            host: Server host name or address.
            port: Server port.
            use_tls: Whether to connect over TLS.

        Returns:
            True if a license from the server was activated, False otherwise
            (e.g. the server cannot be reached, or no license could be checked out from it).

        Raises:
            InvalidParameterError: If `port` is outside the valid range.
        """
        if port < 0 or port > 65535:
            raise InvalidParameterError('port', port, 'must be between 0 and 65535')
        return self._license.set_server(host, port, use_tls)

    def checkout(self, license_id: str) -> bool:
        """
        Activate the given license of the current license source.

        With a license server, the current seat is checked in first.

        Args:
            license_id: License ID in the "XX-XXXX-XXXX-XX" form.

        Returns:
            True if the license was activated, False otherwise
            (e.g. the current license source does not hold the license,
            or it could not be checked out).

        Raises:
            InvalidParameterError: If `license_id` is not in the "XX-XXXX-XXXX-XX" form.
        """
        if not re.fullmatch(r'[0-9A-F]{2}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{2}', license_id, re.I):
            raise InvalidParameterError(
                'license_id', license_id, 'must be in the XX-XXXX-XXXX-XX form'
            )
        return self._license.checkout(license_id)

    def checkin(self) -> bool:
        """
        Check the current seat back in to the license server.

        IDA keeps running without a license until one is activated again.

        Returns:
            True if the seat was checked in, False otherwise
            (e.g. the license source is a file, no seat is held,
            or the current license is borrowed).
        """
        return self._license.checkin()

    def borrow(self, until: datetime) -> bool:
        """
        Borrow the current license from the license server for offline use.

        Args:
            until: End of the borrow period. A datetime without a timezone is taken
                as local time.

        Returns:
            True if the license was borrowed, False otherwise
            (e.g. the license source is a file, no license is checked out,
            or the server refused the borrow).

        Raises:
            InvalidParameterError: If `until` is not in the future.
        """
        if until.astimezone() <= datetime.now(timezone.utc):
            raise InvalidParameterError('until', until, 'must be in the future')
        return self._license.borrow(int(until.timestamp()))

    def return_borrowed(self) -> bool:
        """
        Return the borrowed license to the license server and check out a seat of it instead.

        Returns:
            True if the license was returned, False otherwise
            (e.g. the current license is not borrowed, or the server cannot be reached).
        """
        return self._license.return_borrowed()
