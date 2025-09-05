from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from types import TracebackType

import ida_bytes
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_nalt
import ida_typeinf
from ida_idaapi import ea_t
from typing_extensions import TYPE_CHECKING, List, Literal, Optional, Tuple, Type, Union

from .base import check_db_open
from .bytes import Bytes
from .comments import Comments
from .entries import Entries
from .functions import Functions
from .heads import Heads
from .hooks import HooksList  # type: ignore
from .instructions import Instructions
from .names import Names
from .segments import Segments
from .signature_files import SignatureFiles
from .strings import Strings
from .types import Types
from .xrefs import Xrefs

if TYPE_CHECKING:
    from .instructions import Instructions


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DatabaseMetadata:
    """
    Metadata information about the current database.
    """

    path: Optional[str] = None
    module: Optional[str] = None
    base_address: Optional[ea_t] = None
    filesize: Optional[int] = None
    md5: Optional[str] = None
    sha256: Optional[str] = None
    crc32: Optional[int] = None
    architecture: Optional[str] = None
    bitness: Optional[int] = None
    format: Optional[str] = None
    load_time: Optional[str] = None
    compiler_information: Optional[str] = None
    execution_mode: Optional[str] = None


@dataclass(frozen=True)
class CompilerInformation:
    """
    Compiler information for the current database.
    """

    name: str
    byte_size_bits: int
    short_size_bits: int
    enum_size_bits: int
    int_size_bits: int
    long_size_bits: int
    double_size_bits: int
    long_long_size_bits: int

    def __str__(self) -> str:
        size_fields = [
            field for field in self.__dataclass_fields__ if field.endswith('_size_bits')
        ]
        sizes = [
            f'{field.replace("_size_bits", "")}: {getattr(self, field)}' for field in size_fields
        ]
        sizes_str = ', '.join(sizes)
        return f'Name: {self.name}, sizes in bits: ({sizes_str})'


class ExecutionMode(Enum):
    """Enumeration Execution Modes"""

    User = 'User Mode'
    Kernel = 'Kernel Mode'

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class IdaCommandOptions:
    """
    Configuration for building IDA command line arguments.

    Set the desired options as attributes, then call `build_args()` to generate
    the command line string. Attributes correspond to IDA switches.

    Example:
        ```python
        opts = IdaCommandOptions(
            auto_analysis=False,
            processor="arm",
            script_file="myscript.py",
            script_args=["arg1", "arg2"],
            debug_flags=["queue", "debugger"]
        )
        args = opts.build_args()
        ```

    Attributes:
        auto_analysis (bool): If False, disables auto analysis (-a).
            Default: True (auto analysis enabled).
        loading_address (Optional[int]): Address (in paragraphs, 16 bytes each)
            to load the file at (-b).
            Default: None (not set).
        new_database (bool): If True, deletes the old database and creates a new one (-c).
            Default: False.
        compiler (Optional[str]): Compiler identifier string for the database (-C).
            Default: None.
        first_pass_directives (List[str]): Directives for first pass configuration (-d).
            Default: [].
        second_pass_directives (List[str]): Directives for second pass configuration (-D).
            Default: [].
        disable_fpp (bool): If True, disables FPP instructions (IBM PC only) (-f).
            Default: False.
        entry_point (Optional[int]): Entry point address (-i).
            Default: None (not set).
        jit_debugger (Optional[bool]): If set, enables/disables IDA as just-in-time debugger (-I).
            Default: None.
        log_file (Optional[str]): Path to the log file (-L).
            Default: None.
        disable_mouse (bool): If True, disables mouse support in text mode (-M).
            Default: False.
        plugin_options (Optional[str]): Options to pass to plugins (-O).
            Default: None.
        output_database (Optional[str]): Output database path (-o). Implies new_database.
            Default: None.
        processor (Optional[str]): Processor type identifier (-p).
            Default: None.
        db_compression (Optional[str]): Database compression ('compress', 'pack', 'no_pack') (-P).
            Default: None.
        run_debugger (Optional[str]): Debugger options string to run immediately (-r).
            Default: None.
        load_resources (bool): If True, loads MS Windows exe resources (-R).
            Default: False.
        script_file (Optional[str]): Script file to execute on database open (-S).
            Default: None.
        script_args (List[str]): Arguments to pass to the script (-S).
            Default: [].
        file_type (Optional[str]): File type prefix for input (-T).
            Default: None.
        file_member (Optional[str]): Archive member name, used with file_type (-T).
            Default: None.
        empty_database (bool): If True, creates an empty database (-t).
            Default: False.
        windows_dir (Optional[str]): MS Windows directory path (-W).
            Default: None.
        no_segmentation (bool): If True, disables segmentation (-x).
            Default: False.
        debug_flags (Union[int, List[str]]): Debug flags as integer or list of names (-z).
            Default: 0.
    """

    auto_analysis: bool = True
    """If False, disables auto analysis (-a). Default: True (enabled)."""

    loading_address: Optional[int] = None
    """Address (in paragraphs, 16 bytes each) to load the file at (-b)."""

    new_database: bool = False
    """If True, deletes the old database and creates a new one (-c)."""

    compiler: Optional[str] = None
    """Compiler identifier string for the database (-C)."""

    first_pass_directives: List[str] = field(default_factory=list)
    """Directives for first pass configuration (-d)."""

    second_pass_directives: List[str] = field(default_factory=list)
    """Directives for second pass configuration (-D)."""

    disable_fpp: bool = False
    """If True, disables FPP instructions (IBM PC only) (-f)."""

    entry_point: Optional[int] = None
    """Entry point address (-i)."""

    jit_debugger: Optional[bool] = None
    """If set, enables/disables IDA as just-in-time debugger (-I)."""

    log_file: Optional[str] = None
    """Path to the log file (-L)."""

    disable_mouse: bool = False
    """If True, disables mouse support in text mode (-M)."""

    plugin_options: Optional[str] = None
    """Options to pass to plugins (-O)."""

    output_database: Optional[str] = None
    """Output database path (-o). Implies new_database."""

    processor: Optional[str] = None
    """Processor type identifier (-p)."""

    db_compression: Optional[str] = None
    """Database compression: 'compress', 'pack', or 'no_pack' (-P)."""

    run_debugger: Optional[str] = None
    """Debugger options string to run immediately (-r)."""

    load_resources: bool = False
    """If True, loads MS Windows exe resources (-R)."""

    script_file: Optional[str] = None
    """Script file to execute when database opens (-S)."""

    script_args: List[str] = field(default_factory=list)
    """Arguments to pass to the script file (-S)."""

    file_type: Optional[str] = None
    """File type prefix for input (-T)."""

    file_member: Optional[str] = None
    """Archive member name, used with file_type (-T)."""

    empty_database: bool = False
    """If True, creates an empty database (-t)."""

    windows_dir: Optional[str] = None
    """MS Windows directory path (-W)."""

    no_segmentation: bool = False
    """If True, disables segmentation (-x)."""

    debug_flags: Union[int, List[str]] = 0
    """Debug flags as integer value or list of flag names (-z)."""

    def build_args(self) -> str:
        """
        Construct the command line arguments string from the configured options.

        Returns:
            str: All command line arguments for IDA, separated by spaces.
        """
        args = []

        if not self.auto_analysis:
            args.append('-a')
        if self.loading_address is not None:
            args.append(f'-b{self.loading_address:X}')
        if self.new_database or self.output_database:
            args.append('-c')
        if self.compiler:
            args.append(f'-C{self.compiler}')
        args += [f'-d{d}' for d in self.first_pass_directives]
        args += [f'-D{d}' for d in self.second_pass_directives]
        if self.disable_fpp:
            args.append('-f')
        if self.entry_point is not None:
            args.append(f'-i{self.entry_point:X}')
        if self.jit_debugger is not None:
            args.append(f'-I{int(self.jit_debugger)}')
        if self.log_file:
            args.append(f'-L{self.log_file}')
        if self.disable_mouse:
            args.append('-M')
        if self.output_database:
            args.append(f'-o{self.output_database}')
        if self.plugin_options:
            args.append(f'-O{self.plugin_options}')
        if self.processor:
            args.append(f'-p{self.processor}')
        if self.db_compression:
            comp_map = {'compress': '-P+', 'pack': '-P', 'no_pack': '-P-'}
            val = comp_map.get(self.db_compression)
            if val:
                args.append(val)
            else:
                logger.error(f'Unknown db_compression: {self.db_compression}')
        if self.run_debugger:
            args.append(f'-r{self.run_debugger}')
        if self.load_resources:
            args.append('-R')
        if self.script_file:
            full = self.script_file + ''.join(
                f' {self._quote_if_needed(arg)}' for arg in self.script_args
            )
            if self.script_args:
                args.append(f'-S"{full}"')
            else:
                args.append(f'-S{self.script_file}')
        if self.empty_database:
            args.append('-t')
        if self.file_type:
            type_spec = f'-T{self.file_type}'
            if self.file_member:
                type_spec += f':{self.file_member}'
            args.append(type_spec)
        if self.windows_dir:
            args.append(f'-W{self.windows_dir}')
        if self.no_segmentation:
            args.append('-x')
        if self.debug_flags:
            debug_val = self._parse_debug_flags(self.debug_flags)
            if debug_val != 0:
                args.append(f'-z{debug_val:X}')

        return ' '.join(args)

    @staticmethod
    def _quote_if_needed(s: str) -> str:
        """Quote a string if it contains spaces."""
        return f'"{s}"' if ' ' in s else s

    @staticmethod
    def _parse_debug_flags(flags: Union[int, List[str]]) -> int:
        """
        Convert debug flags to integer if a list of names is given.

        Args:
            flags: Either an integer or a list of debug flag names.

        Returns:
            Integer value representing all the flags.
        """
        if isinstance(flags, int):
            return flags
        flag_map = {
            'drefs': 0x00000001,
            'offsets': 0x00000002,
            'flirt': 0x00000004,
            'idp': 0x00000008,
            'ldr': 0x00000010,
            'plugin': 0x00000020,
            'ids': 0x00000040,
            'config': 0x00000080,
            'heap': 0x00000100,
            'licensing': 0x00000200,
            'demangler': 0x00000400,
            'queue': 0x00000800,
            'rollback': 0x00001000,
            'already_data_or_code': 0x00002000,
            'type_system': 0x00004000,
            'notifications': 0x00008000,
            'debugger': 0x00010000,
            'debugger_appcall': 0x00020000,
            'source_debugger': 0x00040000,
            'accessibility': 0x00080000,
            'network': 0x00100000,
            'stack_analysis': 0x00200000,
            'debug_info': 0x00400000,
            'lumina': 0x00800000,
        }
        value = 0
        for name in flags:
            if name in flag_map:
                value |= flag_map[name]
            else:
                logger.error(f"Unknown debug flag '{name}'")
        return value


class DatabaseError(Exception):
    """Exception for database operations."""

    pass


class Database:
    """
    Provides access and control over the loaded IDA database.

    Can be used as a context manager for automatic resource cleanup.

    Args:
        hooks (HooksList, optional): A list of hook instances to associate with this database.
            Defaults to an empty list.

    Note:
        Direct instantiation of this class is discouraged.
        Use the `Database.open()` class method to create and initialize a database instance.

    Example:
        ```python
        # Open and automatically close a database
        with Database.open("path/to/file.exe", save_on_close=True) as db:
            # Work with the database
            print(f"Loaded: {db.path}")
        # Database is automatically closed here

        # Or use without context manager
        db = Database.open("path/to/file.exe", save_on_close=True)
        # Work with database
        db.close()  # Uses save_on_close=True automatically
        ```
    """

    def __init__(self, hooks: Optional[HooksList] = None) -> None:
        self.save_on_close = False
        self._hooks = hooks if hooks is not None else []

    def __enter__(self) -> Database:
        """
        Enter the context manager.

        Returns:
            The Database instance for use in the with statement.
        """
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> Literal[False]:
        """
        Exit the context manager.

        Automatically closes the database if running as a library and save_on_close is enabled.

        Args:
            exc_type: Exception type if an exception occurred, None otherwise.
            exc_value: Exception instance if an exception occurred, None otherwise.
            traceback: Traceback object if an exception occurred, None otherwise.

        Returns:
            False to allow exceptions to propagate (does not suppress exceptions).
        """
        if self.is_open() and ida_kernwin.is_ida_library(None, 0, None):
            self.close(save=self.save_on_close)

        self.unhook()

        return False

    @classmethod
    def open(
        cls,
        path: str = '',
        args: Optional[IdaCommandOptions] = None,
        save_on_close: bool = False,
        hooks: Optional[HooksList] = None,
    ) -> Database:
        """
        Database factory, opens a database from the specified file path.

        Args:
            path: Path to the input file, pass None when running inside IDA GUI
            args: Command builder responsible for passing arguments to IDA kernel.
            save_on_close: Default behavior for saving changes on close. Used automatically
            when exiting context manager, but can be overridden in explicit close() calls.
            hooks: List of hook instances to associated with the database. Hooks are
            automatically enabled before opening the database and disabled after closing.

        Returns:
            Database: A new Database instance on success

        Raises:
            DatabaseError: If the Database instance cannot be created

        Note:
            The user is allowed to open a new file only when running IDA as a library.
            When running inside the IDA GUI, the db_path needs to be set to None
            to refer to the currently open database in IDA.
        """
        db = Database(hooks=hooks)
        db.save_on_close = save_on_close
        db.hook()  # hook before load to catch potential preload events

        try:
            is_library_mode = ida_kernwin.is_ida_library(None, 0, None)

            if is_library_mode and path:
                cls._open_new_database(path, args)
            else:
                cls._use_current_database(path, is_library_mode)

        except Exception:
            db.unhook()
            raise

        db.hook()  # decompiler hooks need to be installed after database open
        return db

    @classmethod
    def _open_new_database(cls, path: str, args: Optional[IdaCommandOptions]) -> None:
        """Open a new database file in library mode."""
        if args is None:
            args = IdaCommandOptions()

        import idapro

        result = idapro.open_database(path, args.auto_analysis, args.build_args())
        if result != 0:
            raise DatabaseError(f'Failed to open database {path}')

    @classmethod
    def _use_current_database(cls, path: str, is_library_mode: bool) -> None:
        """Use the currently loaded database."""
        if not is_library_mode and path:
            raise DatabaseError('Opening a new database is not available in IDA GUI')

        loaded_idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if not loaded_idb:
            raise DatabaseError('There is no database currently loaded.')

    def is_open(self) -> bool:
        """
        Checks if the database is loaded.

        Returns:
            True if a database is open, false otherwise.
        """
        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        return bool(idb_path and idb_path.strip())

    @check_db_open
    def close(self, save: Optional[bool] = None) -> None:
        """
        Closes the currently open database.

        Args:
            save: If provided, saves/discards changes accordingly.
                  If None, uses the save_on_close setting from open().

        Note:
            This function is available only when running IDA as a library.
            When running inside the IDA GUI, we have no control on the database lifecycle.
        """
        # Use save_on_close as default if save parameter is not explicitly provided
        save_flag = save if save is not None else self.save_on_close

        if ida_kernwin.is_ida_library(None, 0, None):
            import idapro

            idapro.close_database(save_flag)
        else:
            logger.error('Close is available only when running as a library.')

        self.unhook()

    @check_db_open
    def execute_script(self, file_path: str) -> None:
        """
        Execute the specified python script

        Args:
            file_path: The script file path

        Raises:
            RuntimeError: If script execution fails.
        """
        compiler_error = ida_idaapi.IDAPython_ExecScript(file_path, globals())
        if compiler_error is not None:
            raise RuntimeError(f'script execution {str} failed with error {compiler_error}')

    def is_valid_ea(self, ea: ea_t, strict_check: bool = True) -> bool:
        """
        Check if the specified address is valid.

        Args:
            ea: The effective address to validate.
            strict_check: If True, validates ea is mapped (ida_bytes.is_mapped).
                          If False, only validates ea is within database range.

        Returns:
            True if address is valid according to the check level.
        """
        if strict_check:
            return ida_bytes.is_mapped(ea)
        else:
            return self.minimum_ea <= ea <= self.maximum_ea

    def hook(self) -> None:
        """
        Activate (hook) all registered event handler instances.

        This method associates each hook instance with the current database
        instance and calls their `hook()` method. Hooks are
        automatically hooked when the database is opened (including when used as a
        context manager).

        Typically, you do not need to call this method manually—hooks are managed
        automatically upon database entry.
        """
        for h in self._hooks:
            h.m_database = self
            h.hook()

    def unhook(self) -> None:
        """
        Deactivate (unhook) all registered event handler instances.

        This method calls `unhook()` on each registered hook and
        disassociates them from the database instance. Hooks are automatically
        unhooked when the database is closed, including when used with the database
        as a context manager.

        Typically, you do not need to call this method manually—hooks are managed
        automatically upon database exit.
        """
        for h in self._hooks:
            h.unhook()
            h.m_database = None

    @property
    @check_db_open
    def current_ea(self) -> ea_t:
        """
        The current effective address (equivalent to the "screen EA" in IDA GUI).
        """
        return ida_kernwin.get_screen_ea()

    @current_ea.setter
    @check_db_open
    def current_ea(self, ea: ea_t) -> None:
        """
        Sets the current effective address (equivalent to the "screen EA" in IDA GUI).
        """
        if ida_kernwin.is_ida_library(None, 0, None):
            import idapro

            idapro.set_screen_ea(ea)
        else:
            ida_kernwin.jumpto(ea)

    @property
    @check_db_open
    def start_ip(self) -> ea_t:
        """
        The start instruction pointer value
        """
        return ida_ida.inf_get_start_ip()

    @start_ip.setter
    @check_db_open
    def start_ip(self, ea: ea_t) -> None:
        """
        Sets the instruction pointer value
        """
        ida_ida.inf_set_start_ip(ea)

    @property
    @check_db_open
    def minimum_ea(self) -> ea_t:
        """
        The minimum effective address from this database.
        """
        return ida_ida.inf_get_min_ea()

    @property
    @check_db_open
    def maximum_ea(self) -> ea_t:
        """
        The maximum effective address from this database.
        """
        return ida_ida.inf_get_max_ea()

    @property
    @check_db_open
    def base_address(self) -> Optional[ea_t]:
        """
        The image base address of this database.
        """
        base_addr = ida_nalt.get_imagebase()
        return base_addr if base_addr != ida_idaapi.BADADDR else None

    # Individual metadata properties
    @property
    @check_db_open
    def path(self) -> Optional[str]:
        """The input file path."""
        input_path = ida_nalt.get_input_file_path()
        return input_path if input_path else None

    @property
    @check_db_open
    def module(self) -> Optional[str]:
        """The module name."""
        module_name = ida_nalt.get_root_filename()
        return module_name if module_name else None

    @property
    @check_db_open
    def filesize(self) -> Optional[int]:
        """The input file size."""
        file_size = ida_nalt.retrieve_input_file_size()
        return file_size if file_size > 0 else None

    @property
    @check_db_open
    def md5(self) -> Optional[str]:
        """The MD5 hash of the input file."""
        md5_hash = ida_nalt.retrieve_input_file_md5()
        return md5_hash.hex() if md5_hash else None

    @property
    @check_db_open
    def sha256(self) -> Optional[str]:
        """The SHA256 hash of the input file."""
        sha256_hash = ida_nalt.retrieve_input_file_sha256()
        return sha256_hash.hex() if sha256_hash else None

    @property
    @check_db_open
    def crc32(self) -> Optional[int]:
        """The CRC32 checksum of the input file."""
        crc32 = ida_nalt.retrieve_input_file_crc32()
        return crc32 if crc32 != 0 else None

    @property
    @check_db_open
    def architecture(self) -> Optional[str]:
        """The processor architecture."""
        arch = ida_ida.inf_get_procname()
        return arch if arch else None

    @property
    @check_db_open
    def bitness(self) -> Optional[int]:
        """The application bitness (32/64)."""
        bitness = ida_ida.inf_get_app_bitness()
        return bitness if bitness > 0 else None

    @property
    @check_db_open
    def format(self) -> Optional[str]:
        """The file format type."""
        file_format = ida_loader.get_file_type_name()
        return file_format if file_format else None

    @property
    @check_db_open
    def load_time(self) -> Optional[str]:
        """The database load time."""
        ctime = ida_nalt.get_idb_ctime()
        return datetime.fromtimestamp(ctime).strftime('%Y-%m-%d %H:%M:%S') if ctime else None

    @property
    @check_db_open
    def execution_mode(self) -> ExecutionMode:
        """The execution mode, user or kernel mode."""
        return ExecutionMode.Kernel if ida_ida.inf_is_kernel_mode() else ExecutionMode.User

    @property
    @check_db_open
    def compiler_information(self) -> CompilerInformation:
        """Compiler information for current database."""
        cc = ida_ida.compiler_info_t()
        ida_ida.inf_get_cc(cc)

        return CompilerInformation(
            name=ida_typeinf.get_compiler_name(cc.id),
            byte_size_bits=ida_ida.inf_get_cc_size_b() * 8,
            short_size_bits=ida_ida.inf_get_cc_size_s() * 8,
            enum_size_bits=ida_ida.inf_get_cc_size_e() * 8,
            int_size_bits=ida_ida.inf_get_cc_size_i() * 8,
            long_size_bits=ida_ida.inf_get_cc_size_l() * 8,
            double_size_bits=ida_ida.inf_get_cc_size_ldbl() * 8,
            long_long_size_bits=ida_ida.inf_get_cc_size_ll() * 8,
        )

    @property
    @check_db_open
    def metadata(self) -> DatabaseMetadata:
        """
        Map of key-value metadata about the current database.
        Dynamically built from DatabaseMetadata dataclass fields.
        Returns metadata with original property types preserved.
        """
        from dataclasses import fields

        metadata_values = {}

        # Use the dataclass fields as the source of truth for what properties to collect
        for field in fields(DatabaseMetadata):
            prop_name = field.name
            try:
                value = getattr(self, prop_name)
                if value is not None:
                    if not isinstance(value, (int, float)):
                        value = str(value)
                    # Store the original value with its original type
                    metadata_values[prop_name] = value
            except Exception:
                # Skip properties that might fail to access
                continue

        return DatabaseMetadata(**metadata_values)

    @property
    def segments(self) -> Segments:
        """Handler that provides access to memory segment-related operations."""
        return Segments(self)

    @property
    def functions(self) -> Functions:
        """Handler that provides access to function-related operations."""
        return Functions(self)

    @property
    def instructions(self) -> Instructions:
        """Handler that provides access to instruction-related operations."""
        return Instructions(self)

    @property
    def comments(self) -> Comments:
        """Handler that provides access to user comment-related operations."""
        return Comments(self)

    @property
    def entries(self) -> Entries:
        """Handler that provides access to entries operations."""
        return Entries(self)

    @property
    def heads(self) -> Heads:
        """Handler that provides access to user heads operations."""
        return Heads(self)

    @property
    def strings(self) -> Strings:
        """Handler that provides access to string-related operations."""
        return Strings(self)

    @property
    def names(self) -> Names:
        """Handler that provides access to name-related operations."""
        return Names(self)

    @property
    def types(self) -> Types:
        """Handler that provides access to type-related operations."""
        return Types(self)

    @property
    def bytes(self) -> Bytes:
        """Handler that provides access to byte-level memory operations."""
        return Bytes(self)

    @property
    def signature_files(self) -> SignatureFiles:
        """Handler that provides access to signature file operations."""
        return SignatureFiles(self)

    @property
    def xrefs(self) -> Xrefs:
        """Handler that provides access to cross-reference (xref) operations."""
        return Xrefs(self)

    @property
    def hooks(self) -> HooksList:
        """Returns the list of associated hook instances."""
        return self._hooks
