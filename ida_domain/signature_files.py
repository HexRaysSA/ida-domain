from __future__ import annotations

import dataclasses
import logging
import os
from pathlib import Path

import ida_auto
import ida_diskio
import ida_funcs
import ida_idp
import ida_loader
import ida_undo
from ida_idaapi import ea_t
from typing_extensions import TYPE_CHECKING, List, Optional

from .base import DatabaseEntity, check_db_open, decorate_all_methods

if TYPE_CHECKING:
    from .database import Database


logger = logging.getLogger(__name__)


class _MatchCollector(ida_idp.IDB_Hooks):  # type: ignore[misc]
    def __init__(self, file_path: str):
        ida_idp.IDB_Hooks.__init__(self)
        self.results = FileInfo(path=file_path)

    def idasgn_matched_ea(self, ea: ea_t, name: str, lib_name: str) -> None:
        self.results.matches += 1
        self.results.functions.append(MatchInfo(addr=ea, name=name, lib=lib_name))


@dataclasses.dataclass
class MatchInfo:
    """
    Represents information about a single function matched by a FLIRT signature.
    """

    addr: ea_t
    name: str = ''
    lib: str = ''


@dataclasses.dataclass
class FileInfo:
    """
    Represents information about a FLIRT signature file application.
    Contains the signature file path, number of matches, and details of matched functions.
    """

    path: str = ''
    matches: int = 0
    functions: List[MatchInfo] = dataclasses.field(default_factory=list)


@decorate_all_methods(check_db_open)
class SignatureFiles(DatabaseEntity):
    """
    Provides access to FLIRT signature (.sig) files in the IDA database.

    Args:
        database: Reference to the active IDA database.
    """

    def __init__(self, database: Database):
        super().__init__(database)

    def apply(self, path: Path, probe_only: bool = False) -> List[FileInfo]:
        """
        Applies signature files to current database.

        Args:
            path: Path to the signature file or directory with sig files.
            probe_only: If true, signature files are only probed (apply operation is undone).

        Returns:
            A list of FileInfo objects containing application details.
        """

        info = []
        if path.is_dir():
            for sig_path in path.rglob('*.sig'):
                info.append(self._apply(sig_path, probe_only))
        elif path.suffix == '.sig':
            info.append(self._apply(path, probe_only))

        return info

    def create(self, pat_only: bool = False) -> List[str] | None:
        """
        Create signature files (.pat and .sig) from current database.

        Args:
            pat_only: If true, generate only PAT file.

        Returns:
            A list containing paths to the generated files.
            In case of failure, returns None.
        """
        if not ida_loader.load_and_run_plugin('makesig', 1 if pat_only else 0):
            logger.warning('Failed to generate sig/pat files')
            return None

        # Output files are generated next to the input binary
        produced_files = []
        if not pat_only:
            sig_path = f'{self.database.path}.sig'
            if os.path.exists(sig_path):
                produced_files.append(sig_path)
            else:
                logger.warning(f'create: Cannot locate {sig_path} file')

        pat_path = f'{self.database.path}.pat'
        if os.path.exists(pat_path):
            produced_files.append(pat_path)
        else:
            logger.warning(f'create: Cannot locate {pat_path} file')

        return produced_files if len(produced_files) > 0 else None

    def get_index(self, path: Path) -> int:
        """
        Get index of applied signature file.

        Args:
            path: Path to the signature file.

        Returns:
            Index of applied signature file, -1 if not found.
        """
        for index in range(0, ida_funcs.get_idasgn_qty()):
            name, _, _ = ida_funcs.get_idasgn_desc_with_matches(index)
            if name == str(path):
                return index
        return -1

    def get_files(self, directories: Optional[List[Path]] = None) -> List[Path]:
        """
        Retrieves a list of available FLIRT signature (.sig) files.

        Args:
            directories: Optional list of paths to directories containing FLIRT signature files.
            If the parameter is missing, IDA signature folders will be used.

        Returns:
            A list of available signature file paths.
        """
        dir_list = [
            Path(ida_diskio.idadir(ida_diskio.SIG_SUBDIR)),
            Path(ida_diskio.idadir(ida_diskio.IDP_SUBDIR)),
        ]
        if directories:
            dir_list = dir_list + directories

        sig_files: List[Path] = []
        for directory in dir_list:
            if directory.is_dir():
                sig_files.extend(p.resolve() for p in directory.rglob('*.sig'))
        return sig_files

    def _apply(self, path: Path, probe_only: bool = False) -> FileInfo:
        hooks = _MatchCollector(str(path))
        hooks.hook()
        if probe_only:
            ida_undo.create_undo_point('ida_domain_flirt', 'undo_point')
        ida_funcs.plan_to_apply_idasgn(str(path))
        ida_auto.auto_wait()
        hooks.unhook()
        results = hooks.results
        if probe_only:
            ida_undo.perform_undo()

        return results
