# IDA Domain API Handlers Reference

Auto-generated from source code. Do not edit manually.

---

## Analysis

`db.analysis` - Provides access to auto-analysis control and queue management

| Method | Returns | Description |
|--------|---------|-------------|
| `analyze(start_ea: ea_t, end_ea: ea_t, wait: bool=True)` | `int` | Analyze address range (LLM-friendly alias for analyze_range) |
| `analyze_range(start_ea: ea_t, end_ea: ea_t, wait: bool=True)` | `int` | Analyze address range and optionally wait for completion. |
| `cancel(start_ea: ea_t, end_ea: ea_t)` | `None` | Cancel pending analysis for address range (LLM-friendly alia |
| `cancel_analysis(start_ea: ea_t, end_ea: ea_t)` | `None` | Cancel pending analysis for address range. |
| `is_complete` (property) | `bool` | Check if all analysis queues are empty (non-blocking). |
| `is_enabled` (property) | `bool` | Check if auto-analysis is currently enabled. |
| `schedule(ea: ea_t, what: Union[AnalysisType, str]=AnalysisType.REANALYSIS)` | `None` | Schedule analysis at address (LLM-friendly unified schedulin |
| `schedule_code_analysis(ea: ea_t)` | `None` | Schedule instruction creation at address (adds to CODE queue |
| `schedule_function_analysis(ea: ea_t)` | `None` | Schedule function creation at address (adds to PROC queue). |
| `schedule_reanalysis(ea: ea_t)` | `None` | Schedule reanalysis of single address (adds to USED queue). |
| `set_enabled(enabled: bool)` | `bool` | Enable or disable auto-analysis at runtime. |
| `wait()` | `bool` | Wait until all analysis queues are empty (LLM-friendly alias |
| `wait_for_completion()` | `bool` | Wait until all analysis queues are empty (blocks execution). |

---

## Callgraph

`db.callgraph` - Inter-procedural call graph traversal

| Method | Returns | Description |
|--------|---------|-------------|
| `callees_of(ea: ea_t, max_depth: int=1)` | `Iterator[ea_t]` | Get transitive callees (functions called by) a function. |
| `callers_of(ea: ea_t, max_depth: int=1)` | `Iterator[ea_t]` | Get transitive callers of a function. |
| `paths_between(src_ea: ea_t, dst_ea: ea_t, max_depth: int=10)` | `Iterator[CallPath]` | Find call paths from source function to destination function |
| `reachable_from(ea: ea_t, max_depth: int=100)` | `Set[ea_t]` | Get all functions reachable from the given function. |
| `reaches(ea: ea_t, max_depth: int=100)` | `Set[ea_t]` | Get all functions that can reach the given function. |

---

## Comments

`db.comments` - Provides access to user-defined comments in the IDA database

**Iteration**: `for item in db.comments`

| Method | Returns | Description |
|--------|---------|-------------|
| `add_sourcefile(start_ea: ea_t, end_ea: ea_t, filename: str)` | `bool` | Map an address range to a source file. |
| `advance_in_colored_string(text: str, count: int, start_offset: int=0)` | `int` | Advance a position in a colored string by a given number of  |
| `calculate_visual_length(text: str)` | `int` | Calculate the visual (display) length of a string, excluding |
| `colorize(text: str, color_code: int)` | `str` | Create a colored string by wrapping text with color tags. |
| `delete_all_extra_at(ea: ea_t, kind: ExtraCommentKind)` | `int` | Delete all extra comments of a specific kind at an address. |
| `delete_at(ea: ea_t, comment_kind: CommentKind=CommentKind.REGULAR)` | `bool` | Deletes a comment at the specified address. |
| `delete_extra_at(ea: ea_t, index: int, kind: ExtraCommentKind)` | `bool` | Deletes a specific extra comment. |
| `delete_sourcefile(ea: ea_t)` | `bool` | Delete the source file mapping containing the specified addr |
| `generate_disasm_line(ea: ea_t, remove_tags: bool=False)` | `str` | Generate a single disassembly line for the specified address |
| `generate_disassembly(ea: ea_t, max_lines: int, as_stack: bool=False, remove_tags: bool=False)` | `tuple[int, list[str]]` | Generate multiple disassembly lines with importance ranking. |
| `get_all(comment_kind: CommentKind=CommentKind.REGULAR)` | `Iterator[CommentInfo]` | Creates an iterator for comments in the database. |
| `get_all_extra_at(ea: ea_t, kind: ExtraCommentKind)` | `Iterator[str]` | Gets all extra comments of a specific kind. |
| `get_at(ea: ea_t, comment_kind: CommentKind=CommentKind.REGULAR)` | `Optional[CommentInfo]` | Retrieves the comment at the specified address. |
| `get_background_color(ea: ea_t)` | `int` | Get the background color for an address. |
| `get_extra_at(ea: ea_t, index: int, kind: ExtraCommentKind)` | `Optional[str]` | Gets a specific extra comment. |
| `get_first_free_extra_index(ea: ea_t, kind: ExtraCommentKind, start_index: int=0)` | `int` | Find the first available (unused) extra comment index at an  |
| `get_prefix_color(ea: ea_t)` | `int` | Get the line prefix color for an address. |
| `get_sourcefile(ea: ea_t)` | `Optional[tuple[str, int, int]]` | Get the source file mapping for an address. |
| `requires_color_escape(char: str)` | `bool` | Check if a character requires escaping in colored strings. |
| `set_at(ea: ea_t, comment: str, comment_kind: CommentKind=CommentKind.REGULAR)` | `bool` | Sets a comment at the specified address. |
| `set_extra_at(ea: ea_t, index: int, comment: str, kind: ExtraCommentKind)` | `bool` | Sets an extra comment at the specified address and index. |
| `skip_color_tags(text: str, start_offset: int=0)` | `int` | Skip past all color tags starting at the given offset. |
| `strip_color_tags(text: str)` | `str` | Remove all color tags from a string. |

---

## Decompiler

`db.decompiler` - Provides access to Hex-Rays decompiler functionality

| Method | Returns | Description |
|--------|---------|-------------|
| `decompile(ea: ea_t, remove_tags: bool=True)` | `Optional[List[str]]` | Decompile binary code at the specified address and return ps |
| `is_available` (property) | `bool` | Check if the Hex-Rays decompiler is available and loaded. |

---

## Entries

`db.entries` - Provides access to entries in the IDA database

**Iteration**: `for item in db.entries`

| Method | Returns | Description |
|--------|---------|-------------|
| `add(address: ea_t, name: str, ordinal: Optional[int]=None, make_code: bool=True)` | `bool` | Add a new entry point. |
| `exists(ordinal: int)` | `bool` | Check if an entry point with the given ordinal exists. |
| `get_addresses()` | `Iterator[ea_t]` | Get all entry point addresses. |
| `get_all()` | `Iterator[EntryInfo]` | Get all entry points. |
| `get_at(ea: ea_t)` | `Optional[EntryInfo]` | Get entry point by its address. |
| `get_at_index(index: int)` | `EntryInfo` | Deprecated: Use get_by_index() instead. |
| `get_by_index(index: int)` | `Optional[EntryInfo]` | Get entry point by its index in the entry table. |
| `get_by_name(name: str)` | `Optional[EntryInfo]` | Find entry point by name. |
| `get_by_ordinal(ordinal: int)` | `Optional[EntryInfo]` | Get entry point by its ordinal number. |
| `get_count()` | `int` | Get the total number of entry points. |
| `get_forwarders()` | `Iterator[ForwarderInfo]` | Get all entry points that have forwarders. |
| `get_names()` | `Iterator[str]` | Get all entry point names. |
| `get_ordinals()` | `Iterator[int]` | Get all ordinal numbers. |
| `rename(ordinal: int, new_name: str)` | `bool` | Rename an existing entry point. |
| `set_forwarder(ordinal: int, forwarder_name: str)` | `bool` | Set forwarder name for an entry point. |

---

## Exporter

`db.exporter` - Provides file export operations for IDA databases

| Method | Returns | Description |
|--------|---------|-------------|
| `export(output_path: str, format: Union[ExportFormat, str], start_ea: Optional[ea_t]=None, end_ea: Optional[ea_t]=None)` | `bool` | Export database contents to a file (LLM-friendly unified exp |
| `export_bytes(output_path: str, start_ea: ea_t, end_ea: ea_t)` | `int` | Export raw bytes from a database address range to a binary f |
| `export_range(output_path: str, start_ea: ea_t, end_ea: ea_t, format: ExportFormat, flags: ExportFlags=ExportFlags.NONE)` | `bool` | Export a specific address range in the specified format. |
| `generate_assembly(output_path: str, start_ea: Optional[ea_t]=None, end_ea: Optional[ea_t]=None, flags: ExportFlags=ExportFlags.NONE)` | `bool` | Generate an assembly listing file with disassembled code and |
| `generate_diff(output_path: str, start_ea: Optional[ea_t]=None, end_ea: Optional[ea_t]=None)` | `bool` | Generate a difference file showing changes from the original |
| `generate_executable(output_path: str)` | `bool` | Reconstruct an executable file from the database. |
| `generate_idc_script(output_path: str, start_ea: Optional[ea_t]=None, end_ea: Optional[ea_t]=None)` | `bool` | Generate an IDC script that can recreate the current analysi |
| `generate_listing(output_path: str, start_ea: Optional[ea_t]=None, end_ea: Optional[ea_t]=None, flags: ExportFlags=ExportFlags.NONE)` | `bool` | Generate a listing file with formatted disassembly output. |
| `generate_map_file(output_path: str, start_ea: Optional[ea_t]=None, end_ea: Optional[ea_t]=None)` | `bool` | Generate a MAP file containing address mappings for symbols. |
| `import_bytes(input_path: str, dest_ea: ea_t, file_offset: int=0, size: Optional[int]=None)` | `int` | Import raw bytes from a binary file into the database. |

---

## Fixups

`db.fixups` - Manages fixup (relocation) information in the IDA database

**Iteration**: `for item in db.fixups`

| Method | Returns | Description |
|--------|---------|-------------|
| `add(ea: ea_t, fixup_type: FixupType, target_offset: ea_t, displacement: int=0, is_relative: bool=False, is_extdef: bool=True)` | `bool` | Add a new fixup at the specified address. |
| `contains_fixups(start_ea: ea_t, size: int)` | `bool` | Check if an address range contains any fixups. |
| `count` (property) | `int` | Get the total number of fixups in the database. |
| `delete(ea: ea_t)` | `bool` | Delete the fixup at the specified address. |
| `delete_at(ea: ea_t)` | `bool` | Delete the fixup at the specified address. |
| `get_all()` | `Iterator[FixupInfo]` | Get all fixups in the database. |
| `get_at(ea: ea_t)` | `Optional[FixupInfo]` | Get fixup information at a specific address. |
| `get_between(start_ea: ea_t, end_ea: ea_t)` | `Iterator[FixupInfo]` | Get all fixups within an address range. |
| `get_description(ea: ea_t)` | `str` | Get a human-readable description of the fixup at address. |
| `has_fixup(ea: ea_t)` | `bool` | Check if a fixup exists at the given address. |
| `patch_value(ea: ea_t)` | `bool` | Apply the fixup at address to the database bytes. |
| `remove(ea: ea_t)` | `bool` | Remove the fixup at the specified address. |

---

## Flowchart

`db.flowchart` - Provides access to basic block properties and navigation
    between connected blocks within a control flow graph

| Method | Returns | Description |
|--------|---------|-------------|
| `count_predecessors()` | `int` | Count the number of predecessor blocks. |
| `count_successors()` | `int` | Count the number of successor blocks. |
| `get_instructions()` | `Iterator[insn_t]` | Retrieves all instructions within this basic block. |
| `get_predecessors()` | `Iterator[BasicBlock]` | Iterator over predecessor blocks. |
| `get_successors()` | `Iterator[BasicBlock]` | Iterator over successor blocks. |

---

## Functions

`db.functions` - Provides access to function-related operations within the IDA database

**Iteration**: `for item in db.functions`

| Method | Returns | Description |
|--------|---------|-------------|
| `count()` | `int` | Get the total number of functions in the database. |
| `create(ea: ea_t)` | `bool` | Deprecated: Use create_at() instead. |
| `create_at(ea: ea_t)` | `bool` | Creates a new function at the specified address. |
| `delete(ea: ea_t)` | `bool` | Deletes the function at the specified address. |
| `does_return(func: func_t)` | `bool` | Check if function returns. |
| `exists_at(ea: ea_t)` | `bool` | Check if a function exists at the given address. |
| `get_all()` | `Iterator[func_t]` | Retrieves all functions in the database. |
| `get_at(ea: ea_t)` | `Optional[func_t]` | Retrieves the function that contains the given address. |
| `get_between(start_ea: ea_t, end_ea: ea_t)` | `Iterator[func_t]` | Retrieves functions within the specified address range. |
| `get_by_name(name: str)` | `Optional[func_t]` | Find a function by its name. |
| `get_callees(func: func_t)` | `List[func_t]` | Gets all functions called by this function. |
| `get_callers(func: func_t)` | `List[func_t]` | Gets all functions that call this function. |
| `get_chunk_at(ea: ea_t)` | `Optional[func_t]` | Get function chunk at exact address. |
| `get_chunked(chunk_size: int=1000)` | `Iterator[List[func_t]]` | Yield functions in chunks for batch processing. |
| `get_chunks(func: func_t)` | `Iterator[FunctionChunk]` | Get all chunks (main and tail) of a function. |
| `get_comment(func: func_t, repeatable: bool=False)` | `str` | Get comment for function. |
| `get_data_items(func: func_t)` | `Iterator[ea_t]` | Iterate over data items within the function. |
| `get_disassembly(func: func_t, remove_tags: bool=True)` | `List[str]` | Retrieves the disassembly lines for the given function. |
| `get_flags(func: func_t)` | `FunctionFlags` | Get function attribute flags. |
| `get_flowchart(func: func_t, flags: FlowChartFlags=FlowChartFlags.NONE)` | `Optional[FlowChart]` | Retrieves the flowchart of the specified function, |
| `get_in_range(start: ea_t, end: ea_t)` | `Iterator[func_t]` | Get functions in the specified address range. |
| `get_instructions(func: func_t)` | `Optional[Iterator[insn_t]]` | Retrieves all instructions within the given function. |
| `get_local_variable_by_name(func: func_t, name: str)` | `Optional[LocalVariable]` | Find a local variable by name. |
| `get_local_variable_references(func: func_t, lvar: LocalVariable)` | `List[LocalVariableReference]` | Get all references to a specific local variable. |
| `get_local_variables(func: func_t)` | `List[LocalVariable]` | Get all local variables for a function. |
| `get_microcode(func: func_t, remove_tags: bool=True)` | `List[str]` | Retrieves the microcode of the given function. |
| `get_name(func: func_t)` | `str` | Retrieves the function's name. |
| `get_next(ea: ea_t)` | `Optional[func_t]` | Get the next function after the given address. |
| `get_page(offset: int=0, limit: int=100)` | `List[func_t]` | Get a page of functions for random access patterns. |
| `get_previous(ea: ea_t)` | `Optional[func_t]` | Get the previous function before the given address. |
| `get_pseudocode(func: func_t, remove_tags: bool=True)` | `List[str]` | Retrieves the decompiled pseudocode of the given function. |
| `get_signature(func: func_t)` | `str` | Retrieves the function's type signature. |
| `get_stack_points(func: func_t)` | `List[StackPoint]` | Get function stack points for SP tracking. |
| `get_tail_info(chunk: func_t)` | `Optional[TailInfo]` | Get information about tail chunk's owner function. |
| `get_tails(func: func_t)` | `List[func_t]` | Get all tail chunks of a function. |
| `is_chunk_at(ea: ea_t)` | `bool` | Check if the given address belongs to a function chunk. |
| `is_entry_chunk(chunk: func_t)` | `bool` | Check if chunk is entry chunk. |
| `is_far(func: func_t)` | `bool` | Check if function is far. |
| `is_tail_chunk(chunk: func_t)` | `bool` | Check if chunk is tail chunk. |
| `reanalyze(func: func_t)` | `bool` | Force function re-analysis. |
| `remove(ea: ea_t)` | `bool` | Removes the function at the specified address. |
| `set_comment(func: func_t, comment: str, repeatable: bool=False)` | `bool` | Set comment for function. |
| `set_name(func: func_t, name: str, auto_correct: bool=True)` | `bool` | Renames the given function. |

---

## Heads

`db.heads` - Provides access to heads (instructions or data items) in the IDA database

**Iteration**: `for item in db.heads`

| Method | Returns | Description |
|--------|---------|-------------|
| `bounds(ea: ea_t)` | `Tuple[ea_t, ea_t]` | Deprecated: Use get_bounds() instead. |
| `get_all()` | `Iterator[ea_t]` | Retrieves an iterator over all heads in the database. |
| `get_between(start_ea: ea_t, end_ea: ea_t)` | `Iterator[ea_t]` | Retrieves all basic heads between two addresses. |
| `get_bounds(ea: ea_t)` | `Tuple[ea_t, ea_t]` | Get the bounds (start and end addresses) of the item contain |
| `get_next(ea: ea_t)` | `Optional[ea_t]` | Get the next head address. |
| `get_previous(ea: ea_t)` | `Optional[ea_t]` | Get the previous head address. |
| `get_size(ea: ea_t)` | `int` | Get the size of the item at the given address. |
| `is_code(ea: ea_t)` | `bool` | Check if the item at the given address is code. |
| `is_data(ea: ea_t)` | `bool` | Check if the item at the given address is data. |
| `is_head(ea: ea_t)` | `bool` | Check if the given address is a head (start of an item). |
| `is_tail(ea: ea_t)` | `bool` | Check if the given address is a tail (part of an item but no |
| `is_unknown(ea: ea_t)` | `bool` | Check if the item at the given address is unknown. |
| `size(ea: ea_t)` | `int` | Deprecated: Use get_size() instead. |

---

## Hooks

`db.hooks` - Handler

| Method | Returns | Description |
|--------|---------|-------------|
| `is_hooked` (property) | `bool` |  |
| `log(msg: str='')` | `None` | Utility method to optionally log called hooks and their para |

---

## Imports

`db.imports` - Provides access to import table operations in the IDA database

**Iteration**: `for item in db.imports`

| Method | Returns | Description |
|--------|---------|-------------|
| `filter_entries(predicate: Callable[[ImportEntry], bool])` | `Iterator[ImportEntry]` | Filters import entries using a custom predicate function. |
| `find_all_by_name(name: str, module_name: Optional[str]=None)` | `Iterator[ImportEntry]` | Finds all import entries matching the given name (handles du |
| `find_by_name(name: str, module_name: Optional[str]=None)` | `Optional[ImportEntry]` | Deprecated: Use get_by_name() instead. |
| `get_all()` | `Iterator[ImportModule]` | Retrieves all import modules in the database. |
| `get_all_entries()` | `Iterator[ImportEntry]` | Retrieves all import entries across all modules (flattened v |
| `get_at(ea: ea_t)` | `Optional[ImportEntry]` | Retrieves the import entry at the specified address (IAT ent |
| `get_by_name(name: str, module_name: Optional[str]=None)` | `Optional[ImportEntry]` | Get import entry by name, optionally filtering by module. |
| `get_entries_by_module(module: Union[str, int, ImportModule])` | `Iterator[ImportEntry]` | Retrieves all import entries from a specific module. |
| `get_module(index: int)` | `Optional[ImportModule]` | Retrieves an import module by its index. |
| `get_module_by_name(name: str)` | `Optional[ImportModule]` | Retrieves an import module by its name. |
| `get_module_names()` | `List[str]` | Retrieves a list of all import module names. |
| `get_statistics()` | `ImportStatistics` | Retrieves statistical information about imports in the datab |
| `has_imports()` | `bool` | Checks whether the database contains any import information. |
| `is_import(ea: ea_t)` | `bool` | Checks whether the specified address is an import entry. |
| `search_by_pattern(pattern: str, case_sensitive: bool=False)` | `Iterator[ImportEntry]` | Searches import names using a regular expression pattern. |

---

## Instructions

`db.instructions` - Provides access to instruction-related operations using structured operand hierarchy

**Iteration**: `for item in db.instructions`

| Method | Returns | Description |
|--------|---------|-------------|
| `add_code_reference(from_ea: ea_t, to_ea: ea_t, reference_type: int)` | `None` | Add a code cross-reference from one instruction to another. |
| `add_data_reference(from_ea: ea_t, to_ea: ea_t, reference_type: int)` | `None` | Add a data cross-reference from an instruction to a data add |
| `breaks_sequential_flow(insn: insn_t)` | `bool` | Check if the instruction stops sequential control flow. |
| `calculate_data_segment(insn: insn_t, operand_index: int=-1, reg_num: int=-1)` | `ea_t` | Calculate data segment base address for instruction operand. |
| `calculate_offset_base(ea: ea_t, operand_n: int)` | `Optional[ea_t]` | Calculate offset base considering fixup information and segm |
| `can_decode(ea: ea_t)` | `bool` | Check if bytes at address can be decoded as a valid instruct |
| `create_at(ea: ea_t)` | `bool` | Create (analyze and decode) an instruction at the specified  |
| `decode_at(ea: ea_t, out: insn_t)` | `int` | Decode instruction at address, filling the provided insn_t s |
| `format_offset_expression(ea: ea_t, operand_n: int, include_displacement: bool=True)` | `Optional[str]` | Get a formatted offset expression for display. |
| `format_operand(ea: ea_t, operand_index: int, flags: int=0)` | `str` | Format a single operand as text with fine-grained control. |
| `get_all()` | `Iterator[insn_t]` | Retrieves an iterator over all instructions in the database. |
| `get_at(ea: ea_t)` | `Optional[insn_t]` | Decodes the instruction at the specified address. |
| `get_between(start_ea: ea_t, end_ea: ea_t)` | `Iterator[insn_t]` | Retrieves instructions between the specified addresses. |
| `get_chunked(chunk_size: int=1000)` | `Iterator[List[insn_t]]` | Yield instructions in chunks for batch processing. |
| `get_data_type_by_size(size: int)` | `int` | Get the appropriate operand data type for a given size. |
| `get_data_type_flag(dtype: int)` | `int` | Get the flags representation of an operand data type. |
| `get_data_type_size(dtype: int)` | `int` | Get the size in bytes of an operand data type. |
| `get_disassembly(insn: insn_t, remove_tags: bool=True)` | `Optional[str]` | Retrieves the disassembled string representation of the give |
| `get_mnemonic(insn: insn_t)` | `Optional[str]` | Retrieves the mnemonic of the given instruction. |
| `get_next(ea: ea_t)` | `Optional[insn_t]` | Get the instruction immediately following the specified addr |
| `get_operand(insn: insn_t, index: int)` | `Optional[Operand]` | Get a specific operand from the instruction. |
| `get_operand_offset_base(ea: ea_t, operand_n: int)` | `Optional[ea_t]` | Get the offset base address for an operand. |
| `get_operand_offset_target(ea: ea_t, operand_n: int)` | `Optional[ea_t]` | Calculate the target address for an offset operand. |
| `get_operands(insn: insn_t)` | `List[Operand]` | Get all operands from the instruction. |
| `get_operands_count(insn: insn_t)` | `int` | Retrieve the operands number of the given instruction. |
| `get_page(offset: int=0, limit: int=100)` | `List[insn_t]` | Get a page of instructions for random access patterns. |
| `get_preceding(ea: ea_t)` | `Tuple[Optional[insn_t], Optional[bool]]` | Get the instruction preceding the given address, following e |
| `get_previous(ea: ea_t)` | `Optional[insn_t]` | Decodes previous instruction of the one at specified address |
| `get_size(ea: ea_t)` | `int` | Get the size of the instruction at the specified address. |
| `is_call_instruction(insn: insn_t)` | `bool` | Check if the instruction is a call instruction. |
| `is_floating_data_type(dtype: int)` | `bool` | Check if an operand data type represents a floating-point va |
| `is_indirect_jump_or_call(insn: insn_t)` | `bool` | Check if the instruction passes execution using indirect jum |
| `is_valid(insn: insn_t)` | `bool` | Checks if the given instruction is valid. |
| `map_operand_address(insn: insn_t, operand: op_t, is_code: bool)` | `ea_t` | Map operand address to actual effective address (handle segm |
| `set_operand_offset(ea: ea_t, operand_n: int, base: ea_t, target: Optional[ea_t]=None, ref_type: Optional[int]=None)` | `bool` | Convert an operand to an offset reference. |
| `set_operand_offset_ex(ea: ea_t, operand_n: int, ref_info: ida_nalt.refinfo_t)` | `bool` | Convert an operand to offset using detailed reference inform |

---

## Names

`db.names` - Provides access to symbol and label management in the IDA database

**Iteration**: `for item in db.names`

| Method | Returns | Description |
|--------|---------|-------------|
| `create_dummy(from_ea: ea_t, ea: ea_t)` | `bool` | Create an autogenerated dummy name at the specified address. |
| `delete(ea: ea_t)` | `bool` | Delete name at the specified address. |
| `delete_at(ea: ea_t)` | `bool` | Delete name at the specified address. |
| `delete_local(ea: ea_t)` | `bool` | Delete a local name at the specified address. |
| `demangle_name(name: str, disable_mask: Union[int, DemangleFlags]=0)` | `str` | Demangle a mangled name. |
| `force_name(ea: ea_t, name: str, flags: Union[int, SetNameFlags]=SetNameFlags.NOCHECK)` | `bool` | Force set a name, trying variations if the name already exis |
| `format_expression(from_ea: ea_t, n: int, ea: ea_t, offset: int, include_struct_fields: bool=True)` | `Optional[str]` | Convert address to name expression with displacement. |
| `get_all()` | `Iterator[Tuple[ea_t, str]]` | Returns an iterator over all named elements in the database. |
| `get_at(ea: ea_t)` | `Optional[str]` | Retrieves the name at the specified address. |
| `get_at_index(index: int)` | `Optional[Tuple[ea_t, str]]` | Retrieves the named element at the specified index. |
| `get_colored_name(ea: ea_t, local: bool=False)` | `Optional[str]` | Get name with IDA color tags for syntax highlighting. |
| `get_count()` | `int` | Retrieves the total number of named elements in the database |
| `get_demangled_name(ea: ea_t, inhibitor: Union[int, DemangleFlags]=0, demform: int=0)` | `Optional[str]` | Get demangled name at address. |
| `get_visible_name(ea: ea_t, local: bool=False)` | `Optional[str]` | Get the visible name at an address. |
| `is_public_name(ea: ea_t)` | `bool` | Check if name at address is public. |
| `is_valid_name(name: str)` | `bool` | Check if a name is a valid user defined name. |
| `is_weak_name(ea: ea_t)` | `bool` | Check if name at address is weak. |
| `make_name_non_public(ea: ea_t)` | `None` | Make name at address non-public. |
| `make_name_non_weak(ea: ea_t)` | `None` | Make name at address non-weak. |
| `make_name_public(ea: ea_t)` | `None` | Make name at address public. |
| `make_name_weak(ea: ea_t)` | `None` | Make name at address weak. |
| `resolve_name(name: str, from_ea: ea_t=BADADDR)` | `Optional[ea_t]` | Resolve a name to its address. |
| `resolve_value(name: str, from_ea: ea_t=BADADDR)` | `Tuple[Optional[int], int]` | Get the numeric value and type of a name. |
| `set_name(ea: ea_t, name: str, flags: Union[int, SetNameFlags]=SetNameFlags.NOCHECK)` | `bool` | Set or delete name of an item at the specified address. |
| `validate(name: str, strict: bool=False)` | `Tuple[bool, str]` | Validate a name and return validation result with cleaned na |

---

## Problems

`db.problems` - Provides access to IDA's problem list operations

**Iteration**: `for item in db.problems`

| Method | Returns | Description |
|--------|---------|-------------|
| `add(ea: ea_t, problem_type: ProblemType, description: Optional[str]=None)` | `None` | Add a problem to the list. |
| `clear(problem_type: ProblemType)` | `int` | Clear all problems of a specific type. |
| `clear_all()` | `int` | Clear all problems of all types. |
| `count()` | `int` | Get the total number of problems across all types. |
| `count_by_type(problem_type: ProblemType)` | `int` | Get the count of problems of a specific type. |
| `delete(ea: ea_t, problem_type: ProblemType)` | `bool` | Delete a problem from the list. |
| `delete_at(ea: ea_t)` | `int` | Delete all problems at a specific address. |
| `get_all(problem_type: Optional[ProblemType]=None)` | `Iterator[Problem]` | Get all problems, optionally filtered by type. |
| `get_at(ea: ea_t)` | `Iterator[Problem]` | Get all problems at a specific address. |
| `get_between(start: ea_t, end: ea_t, problem_type: Optional[ProblemType]=None)` | `Iterator[Problem]` | Get problems within a specific address range. |
| `get_next(ea: ea_t, problem_type: Optional[ProblemType]=None)` | `Optional[Problem]` | Get the next problem at or after the specified address. |
| `has_problem(ea: ea_t, problem_type: Optional[ProblemType]=None)` | `bool` | Check if an address has a problem. |
| `remove(ea: ea_t, problem_type: ProblemType)` | `bool` | Remove a problem from the list. |
| `remove_at(ea: ea_t)` | `int` | Remove all problems at a specific address. |
| `was_auto_decision(ea: ea_t)` | `bool` | Check if IDA made an automatic decision at this address. |

---

## Search

`db.search` - Provides search operations for finding addresses by various criteria

| Method | Returns | Description |
|--------|---------|-------------|
| `all_code(start_ea: Optional[ea_t]=None, end_ea: Optional[ea_t]=None)` | `Iterator[ea_t]` | Iterate over all code addresses in a range. |
| `all_code_outside_functions(start_ea: Optional[ea_t]=None, end_ea: Optional[ea_t]=None)` | `Iterator[ea_t]` | Iterate over all code addresses not belonging to functions. |
| `all_data(start_ea: Optional[ea_t]=None, end_ea: Optional[ea_t]=None)` | `Iterator[ea_t]` | Iterate over all data addresses in a range. |
| `all_defined(start_ea: Optional[ea_t]=None, end_ea: Optional[ea_t]=None)` | `Iterator[ea_t]` | Iterate over all defined addresses in a range. |
| `all_errors(start_ea: Optional[ea_t]=None, end_ea: Optional[ea_t]=None)` | `Iterator[tuple[ea_t, int]]` | Iterate over all error addresses in a range. |
| `all_undefined(start_ea: Optional[ea_t]=None, end_ea: Optional[ea_t]=None)` | `Iterator[ea_t]` | Iterate over all undefined addresses in a range. |
| `all_untyped_operands(start_ea: Optional[ea_t]=None, end_ea: Optional[ea_t]=None)` | `Iterator[tuple[ea_t, int]]` | Iterate over all operands without type information. |
| `find_all(start_ea: ea_t, end_ea: ea_t, what: Union[SearchTarget, str])` | `Iterator[ea_t]` | Iterate over all addresses of specified type (LLM-friendly u |
| `find_next(ea: ea_t, what: Union[SearchTarget, str], direction: Union[SearchDirection, str]=SearchDirection.DOWN)` | `Optional[ea_t]` | Find next address of specified type (LLM-friendly unified se |
| `next_code(start_ea: ea_t, direction: SearchDirection=SearchDirection.DOWN)` | `Optional[ea_t]` | Find the next code address. |
| `next_code_outside_function(start_ea: ea_t, direction: SearchDirection=SearchDirection.DOWN)` | `Optional[ea_t]` | Find the next code address that does not belong to a functio |
| `next_data(start_ea: ea_t, direction: SearchDirection=SearchDirection.DOWN)` | `Optional[ea_t]` | Find the next data address. |
| `next_defined(start_ea: ea_t, direction: SearchDirection=SearchDirection.DOWN)` | `Optional[ea_t]` | Find the next defined address (start of instruction or data) |
| `next_error(start_ea: ea_t, direction: SearchDirection=SearchDirection.DOWN)` | `tuple[Optional[ea_t], Optional[int]]` | Find the next error or problem address. |
| `next_suspicious_operand(start_ea: ea_t, direction: SearchDirection=SearchDirection.DOWN)` | `tuple[Optional[ea_t], Optional[int]]` | Find the next suspicious operand. |
| `next_undefined(start_ea: ea_t, direction: SearchDirection=SearchDirection.DOWN)` | `Optional[ea_t]` | Find the next unexplored/undefined address. |
| `next_untyped_operand(start_ea: ea_t, direction: SearchDirection=SearchDirection.DOWN)` | `tuple[Optional[ea_t], Optional[int]]` | Find the next operand without type information. |

---

## Segments

`db.segments` - Provides access to segment-related operations in the IDA database

**Iteration**: `for item in db.segments`

| Method | Returns | Description |
|--------|---------|-------------|
| `add(seg_para: ea_t, start_ea: ea_t, end_ea: ea_t, seg_name: Optional[str]=None, seg_class: Optional[Union[str, PredefinedClass]]=None, flags: AddSegmentFlags=AddSegmentFlags.NONE)` | `Optional[segment_t]` | Adds a new segment to the IDA database. |
| `add_permissions(segment: segment_t, perms: SegmentPermissions)` | `bool` | OR the given permission bits into the existing segment permi |
| `append(seg_para: ea_t, seg_size: ea_t, seg_name: Optional[str]=None, seg_class: Optional[Union[str, PredefinedClass]]=None, flags: AddSegmentFlags=AddSegmentFlags.NONE)` | `Optional[segment_t]` | Append a new segment directly after the last segment in the  |
| `delete(segment: segment_t, keep_data: bool=False)` | `bool` | Delete a segment. |
| `get_all()` | `Iterator[segment_t]` | Retrieves an iterator over all segments in the database. |
| `get_at(ea: ea_t)` | `Optional[segment_t]` | Retrieves the segment that contains the given address. |
| `get_base(segment: segment_t)` | `ea_t` | Get segment base linear address. |
| `get_bitness(segment: segment_t)` | `int` | Get segment bitness (16/32/64). |
| `get_by_index(index: int)` | `Optional[segment_t]` | Get segment by its index (0-based). |
| `get_by_name(name: str)` | `Optional[segment_t]` | Find segment by name. |
| `get_chunked(chunk_size: int=1000)` | `Iterator[List[segment_t]]` | Yield segments in chunks for batch processing. |
| `get_class(segment: segment_t)` | `Optional[str]` | Get segment class name. |
| `get_comment(segment: segment_t, repeatable: bool=False)` | `str` | Get comment for segment. |
| `get_first()` | `Optional[segment_t]` | Get the first segment in the database. |
| `get_index(segment: segment_t)` | `int` | Get the index of a segment. |
| `get_last()` | `Optional[segment_t]` | Get the last segment in the database. |
| `get_name(segment: segment_t)` | `str` | Retrieves the name of the given segment. |
| `get_next(segment: segment_t)` | `Optional[segment_t]` | Get the next segment after the given segment. |
| `get_page(offset: int=0, limit: int=100)` | `List[segment_t]` | Get a page of segments for random access patterns. |
| `get_paragraph(segment: segment_t)` | `ea_t` | Get segment base paragraph. |
| `get_previous(segment: segment_t)` | `Optional[segment_t]` | Get the previous segment before the given segment. |
| `get_size(segment: segment_t)` | `int` | Calculate segment size in bytes. |
| `get_type(segment: segment_t)` | `SegmentType` | Get segment type (SEG_NORM, SEG_CODE, SEG_DATA, etc.). |
| `is_visible(segment: segment_t)` | `bool` | Check if segment is visible. |
| `move(segment: segment_t, to: ea_t, fix_relocations: bool=True)` | `MoveSegmentResult` | Move segment to a new address. |
| `rebase(delta: int, fix_once: bool=True)` | `MoveSegmentResult` | Rebase the entire program by delta bytes. |
| `remove_permissions(segment: segment_t, perms: SegmentPermissions)` | `bool` | Clear the given permission bits from the existing segment pe |
| `set_addressing_mode(segment: segment_t, mode: AddressingMode)` | `bool` | Sets the segment addressing mode (16-bit, 32-bit, or 64-bit) |
| `set_class(segment: segment_t, sclass: Union[str, PredefinedClass])` | `bool` | Set segment class. |
| `set_comment(segment: segment_t, comment: str, repeatable: bool=False)` | `bool` | Set comment for segment. |
| `set_end(segment: segment_t, new_end: ea_t, keep_data: bool=True)` | `bool` | Set segment end address. |
| `set_name(segment: segment_t, name: str)` | `bool` | Renames a segment. |
| `set_permissions(segment: segment_t, perms: SegmentPermissions)` | `bool` | Set the segment permissions exactly to `perms` (overwrites e |
| `set_start(segment: segment_t, new_start: ea_t, keep_data: bool=True)` | `bool` | Set segment start address. |
| `set_visible(segment: segment_t, visible: bool)` | `None` | Set segment visibility in the disassembly view. |
| `update(segment: segment_t)` | `bool` | Update segment information after modification. |

---

## Signature Files

`db.signature_files` - Provides access to FLIRT signature (

| Method | Returns | Description |
|--------|---------|-------------|
| `apply(path: Path, probe_only: bool=False)` | `List[FileInfo]` | Applies signature files to current database. |
| `create(pat_only: bool=False)` | `List[str] | None` | Create signature files (.pat and .sig) from current database |
| `get_files(directories: Optional[List[Path]]=None)` | `List[Path]` | Retrieves a list of available FLIRT signature (.sig) files. |
| `get_index(path: Path)` | `int` | Get index of applied signature file. |

---

## Stack Frames

`db.stack_frames` - Provides access to stack frame operations within the IDA database

| Method | Returns | Description |
|--------|---------|-------------|
| `add_sp_change_point(func_ea: ea_t, ea: ea_t, delta: int, automatic: bool=False)` | `bool` | Add a stack pointer change point. |
| `calc_frame_offset(func_ea: ea_t, runtime_offset: int, insn_ea: ea_t)` | `int` | Convert runtime SP/FP-relative offset to frame offset. |
| `calc_runtime_offset(func_ea: ea_t, frame_offset: int, insn_ea: ea_t)` | `int` | Convert frame offset to runtime SP/FP-relative offset at spe |
| `create(func_ea: ea_t, local_size: int, saved_regs_size: int=0, argument_size: int=0)` | `bool` | Create a new stack frame for a function. |
| `define_variable(func_ea: ea_t, name: str, offset: int, var_type: tinfo_t)` | `bool` | Define or redefine a stack variable at the specified offset. |
| `delete(func_ea: ea_t)` | `bool` | Delete the stack frame for a function. |
| `delete_sp_change_point(func_ea: ea_t, ea: ea_t)` | `bool` | Delete a stack pointer change point. |
| `delete_variable(func_ea: ea_t, offset: int)` | `bool` | Delete a stack variable at the specified offset. |
| `delete_variables_in_range(func_ea: ea_t, start_offset: int, end_offset: int)` | `int` | Delete all stack variables within an offset range. |
| `generate_auto_name(func_ea: ea_t, offset: int)` | `str` | Generate automatic variable name based on offset. |
| `get_arguments_section(func_ea: ea_t)` | `FrameSection` | Get the boundaries of the arguments section. |
| `get_as_struct(func_ea: ea_t)` | `tinfo_t` | Get the frame as a structured type (tinfo_t). |
| `get_at(func_ea: ea_t)` | `Optional[StackFrameInstance]` | Get stack frame instance at function address. |
| `get_locals_section(func_ea: ea_t)` | `FrameSection` | Get the boundaries of the local variables section. |
| `get_saved_regs_section(func_ea: ea_t)` | `FrameSection` | Get the boundaries of the saved registers section. |
| `get_sp_change(func_ea: ea_t, ea: ea_t)` | `int` | Get the SP modification made at a specific location. |
| `get_sp_delta(func_ea: ea_t, ea: ea_t)` | `int` | Get the cumulative SP delta at an instruction (before execut |
| `get_variable(func_ea: ea_t, offset: int)` | `Optional[StackVariable]` | Get the stack variable at the specified offset. |
| `get_variable_by_name(func_ea: ea_t, name: str)` | `Optional[StackVariable]` | Find a stack variable by name. |
| `get_variable_xrefs(func_ea: ea_t, offset: int)` | `Iterator[StackVarXref]` | Get all cross-references to a stack variable. |
| `rename_variable(func_ea: ea_t, offset: int, new_name: str)` | `bool` | Rename a stack variable. |
| `resize(func_ea: ea_t, local_size: int, saved_regs_size: Optional[int]=None, argument_size: Optional[int]=None)` | `bool` | Resize an existing stack frame. |
| `set_purged_bytes(func_ea: ea_t, nbytes: int, override: bool=True)` | `bool` | Set the number of bytes purged by the function upon return. |
| `set_variable_type(func_ea: ea_t, offset: int, var_type: tinfo_t)` | `bool` | Change the type of an existing stack variable. |

---

## Strings

`db.strings` - Provides access to string-related operations in the IDA database

**Iteration**: `for item in db.strings`

| Method | Returns | Description |
|--------|---------|-------------|
| `clear()` | `None` | Clear the string list, strings will not be saved in the data |
| `get_all()` | `Iterator[StringItem]` | Retrieves an iterator over all extracted strings in the data |
| `get_at(ea: ea_t)` | `Optional[StringItem]` | Retrieves detailed string information at the specified addre |
| `get_at_index(index: int)` | `StringItem` | Deprecated: Use get_by_index() instead. |
| `get_between(start_ea: ea_t, end_ea: ea_t)` | `Iterator[StringItem]` | Retrieves strings within the specified address range. |
| `get_by_index(index: int)` | `Optional[StringItem]` | Get string by index. |
| `get_chunked(chunk_size: int=1000)` | `Iterator[List[StringItem]]` | Yield strings in chunks for batch processing. |
| `get_page(offset: int=0, limit: int=100)` | `List[StringItem]` | Get a page of strings for random access patterns. |
| `rebuild(config: StringListConfig=StringListConfig())` | `None` | Rebuild the string list from scratch. |

---

## Switches

`db.switches` - Provides comprehensive access to switch statement analysis and manipulation

| Method | Returns | Description |
|--------|---------|-------------|
| `create(ea: ea_t, switch_info: SwitchInfo)` | `bool` | Creates switch statement information at the specified addres |
| `delete(ea: ea_t)` | `bool` | Deletes switch statement information at the specified addres |
| `delete_parent(ea: ea_t)` | `bool` | Delete the switch parent at the specified address. |
| `exists_at(ea: ea_t)` | `bool` | Checks whether switch information exists at the specified ad |
| `get_at(ea: ea_t)` | `Optional[SwitchInfo]` | Retrieves switch information at the specified address. |
| `get_case_count(ea: ea_t)` | `int` | Gets the number of cases for the switch at the specified add |
| `get_case_values(switch_info: SwitchInfo)` | `list[int]` | Gets the case values for a switch statement. |
| `get_jump_table_addresses(switch_info: SwitchInfo)` | `list[ea_t]` | Computes all jump target addresses from the switch's jump ta |
| `get_parent(ea: ea_t)` | `Optional[ea_t]` | Gets the address holding switch information for a jump targe |
| `remove(ea: ea_t)` | `bool` | Remove switch statement information at the specified address |
| `remove_parent(ea: ea_t)` | `bool` | Deprecated: Use delete_parent() instead. |
| `set_parent(ea: ea_t, parent_ea: ea_t)` | `bool` | Sets the parent switch address for a jump target or case. |
| `update(ea: ea_t, switch_info: SwitchInfo)` | `bool` | Updates existing switch statement information at the specifi |

---

## Try Blocks

`db.try_blocks` - Provides access to exception handling try/catch blocks

| Method | Returns | Description |
|--------|---------|-------------|
| `add(try_block: TryBlock)` | `bool` | Add a try block to the database. |
| `delete_in_range(start_ea: ea_t, end_ea: ea_t)` | `bool` | Delete all try blocks in the specified address range. |
| `entity_type` (property) | `str` | Returns 'try_blocks' as the entity type identifier. |
| `find_seh_region(ea: ea_t)` | `Optional[ea_t]` | Find the start address of the system exception handling regi |
| `get_at(ea: ea_t)` | `Optional[TryBlock]` | Get the innermost try block containing the specified address |
| `get_in_range(start_ea: ea_t, end_ea: ea_t)` | `Iterator[TryBlock]` | Retrieve all try blocks whose ranges intersect with the spec |
| `has_fallthrough_from_unwind(ea: ea_t)` | `bool` | Check if there is a fall-through path into the address from  |
| `is_catch_start(ea: ea_t)` | `bool` | Check if an address is the start of a C++ catch or cleanup b |
| `is_in_try_block(ea: ea_t, kind: Optional[TryBlockKind]=None)` | `bool` | Check if an address is within a try block, optionally filter |
| `is_seh_filter_start(ea: ea_t)` | `bool` | Check if an address is the start of a SEH filter callback. |
| `is_seh_handler_start(ea: ea_t)` | `bool` | Check if an address is the start of a SEH finally/except blo |
| `remove_in_range(start_ea: ea_t, end_ea: ea_t)` | `bool` | Remove all try blocks in the specified address range. |

---

## Types

`db.types` - Provides access to type information and manipulation in the IDA database

**Iteration**: `for item in db.types`

| Method | Returns | Description |
|--------|---------|-------------|
| `apply(ea: 'ea_t', type_source: 'str | tinfo_t', by: Union[TypeApplyMode, str]=TypeApplyMode.NAME, flags: TypeApplyFlags=TypeApplyFlags.DEFINITE)` | `bool` | Apply a type to an address (LLM-friendly unified interface). |
| `apply_at(ea: ea_t, type_info: tinfo_t, flags: TypeApplyFlags=TypeApplyFlags.DEFINITE)` | `bool` | Applies a type to the given address. |
| `apply_by_name(ea: ea_t, name: str, flags: TypeApplyFlags=TypeApplyFlags.DEFINITE)` | `bool` | Apply a named type to the given address. |
| `apply_declaration(ea: ea_t, decl: str, flags: TypeFormattingFlags=TypeFormattingFlags.HTI_DCL)` | `bool` | Parse a C declaration and apply it directly to an address. |
| `compare_types(type1: tinfo_t, type2: tinfo_t)` | `bool` | Check if two types are structurally equivalent. |
| `copy_type(source: til_t, destination: til_t, name: str)` | `int` | Copies a type and all dependent types from one library to an |
| `create_library(file: Path, description: str)` | `til_t` | Initializes a new type library. |
| `export_to_library(library: til_t)` | `None` | Export all types from local library to external library. |
| `export_type(destination: til_t, name: str)` | `int` | Exports a type and all dependent types from the local (datab |
| `format(source: 'ea_t | tinfo_t', flags: TypeFormattingFlags=TypeFormattingFlags(0))` | `Optional[str]` | Format a type as a C declaration string (LLM-friendly unifie |
| `format_type(type_info: tinfo_t, flags: TypeFormattingFlags=TypeFormattingFlags(0))` | `str` | Format a type as a C declaration string. |
| `format_type_at(ea: ea_t, flags: TypeFormattingFlags=TypeFormattingFlags(0))` | `Optional[str]` | Format the type at an address as a C declaration string. |
| `get(source: 'ea_t | str | int', by: Union[TypeLookupMode, str]=TypeLookupMode.NAME, library: Optional[til_t]=None)` | `Optional[tinfo_t]` | Retrieve a type (LLM-friendly unified interface). |
| `get_all(library: Optional[til_t]=None, type_kind: TypeKind=TypeKind.NAMED)` | `Iterator[ida_typeinf.tinfo_t]` | Retrieves an iterator over all types in the specified type l |
| `get_at(ea: ea_t)` | `Optional[tinfo_t]` | Retrieves the type information of the item at the given addr |
| `get_by_name(name: str, library: Optional[til_t]=None)` | `Optional[tinfo_t]` | Retrieve a type information object by name. |
| `get_by_ordinal(ordinal: int, library: Optional[til_t]=None)` | `Optional[tinfo_t]` | Retrieve a type information object by its ordinal number. |
| `get_comment(type_info: tinfo_t)` | `str` | Get comment for type. |
| `get_details(type_info: tinfo_t)` | `TypeDetails` | Get type details and attributes. |
| `get_ordinal(name: str, library: Optional[til_t]=None)` | `Optional[int]` | Get the ordinal number of a named type. |
| `guess(ea: 'ea_t')` | `Optional[tinfo_t]` | Guess the type at an address (LLM-friendly alias for guess_a |
| `guess_at(ea: ea_t)` | `Optional[tinfo_t]` | Leverage IDA's type inference to guess the type at an addres |
| `import_from_library(library: til_t)` | `None` | Imports the types from an external library to the local (dat |
| `import_type(source: til_t, name: str)` | `int` | Imports a type and all dependent types from an external (loa |
| `is_enum(type_info: tinfo_t)` | `bool` | Check if a type is an enumeration. |
| `is_struct(type_info: tinfo_t)` | `bool` | Check if a type is a structure. |
| `is_udt(type_info: tinfo_t)` | `bool` | Check if a type is a user-defined type (structure or union). |
| `is_union(type_info: tinfo_t)` | `bool` | Check if a type is a union. |
| `load_library(file: Path)` | `til_t` | Loads a type library file in memory. |
| `parse_declarations(library: til_t, decl: str, flags: TypeFormattingFlags=TypeFormattingFlags.HTI_DCL | TypeFormattingFlags.HTI_PAKDEF)` | `int` | Parse type declarations from string and store created types  |
| `parse_header_file(library: til_t, header: Path, flags: TypeFormattingFlags=TypeFormattingFlags.HTI_FIL | TypeFormattingFlags.HTI_PAKDEF)` | `int` | Parse type declarations from file and store created types in |
| `parse_one_declaration(library: til_t, decl: str, name: str, flags: TypeFormattingFlags=TypeFormattingFlags.HTI_DCL | TypeFormattingFlags.HTI_PAKDEF)` | `tinfo_t` | Parse one declaration from string and create a named type. |
| `remove_pointer(type_info: tinfo_t)` | `Optional[tinfo_t]` | Strip pointer/reference from a type to get the pointed-to ty |
| `resolve_typedef(type_info: tinfo_t)` | `tinfo_t` | Follow typedef chains to get the underlying concrete type. |
| `save_library(library: til_t, file: Path)` | `bool` | Stores the type library to a file. |
| `set_comment(type_info: tinfo_t, comment: str)` | `bool` | Set comment for type. |
| `traverse(type_info: tinfo_t, visitor: ida_typeinf.tinfo_visitor_t)` | `None` | Traverse the given type using the provided visitor class. |
| `unload_library(library: til_t)` | `None` | Unload library (free underlying object). |
| `validate_type(type_info: tinfo_t)` | `bool` | Validate that a type is well-formed and correct. |

---

## Xrefs

`db.xrefs` - Provides unified access to cross-reference (xref) analysis in the IDA database

| Method | Returns | Description |
|--------|---------|-------------|
| `add_code_xref(from_ea: ea_t, to_ea: ea_t, xref_type: XrefType)` | `None` | Add a code cross-reference between two addresses. |
| `add_data_xref(from_ea: ea_t, to_ea: ea_t, xref_type: XrefType)` | `None` | Add a data cross-reference between two addresses. |
| `calls_from_ea(ea: ea_t)` | `Iterator[ea_t]` | Get addresses called from this address. |
| `calls_to_ea(ea: ea_t)` | `Iterator[ea_t]` | Get addresses where calls to this address occur. |
| `code_refs_from_ea(ea: ea_t, flow: bool=True)` | `Iterator[ea_t]` | Get code reference addresses from ea. |
| `code_refs_to_ea(ea: ea_t, flow: bool=True)` | `Iterator[ea_t]` | Get code reference addresses to ea. |
| `count_refs_from(ea: ea_t, flags: XrefsFlags=XrefsFlags.ALL)` | `int` | Count cross-references from an address. |
| `count_refs_to(ea: ea_t, flags: XrefsFlags=XrefsFlags.ALL)` | `int` | Count cross-references to an address. |
| `data_refs_from_ea(ea: ea_t)` | `Iterator[ea_t]` | Get data reference addresses from ea. |
| `data_refs_to_ea(ea: ea_t)` | `Iterator[ea_t]` | Get data reference addresses to ea. |
| `delete_xref(from_ea: ea_t, to_ea: ea_t)` | `bool` | Delete a cross-reference between two addresses. |
| `from_ea(ea: ea_t, flags: XrefsFlags=XrefsFlags.ALL)` | `Iterator[XrefInfo]` | Get all cross-references from an address. |
| `get_callers(func_ea: ea_t)` | `Iterator[CallerInfo]` | Get detailed caller information for a function. |
| `get_refs_from(ea: ea_t, kind: Union[XrefKind, str]=XrefKind.ALL)` | `Iterator[Union[XrefInfo, ea_t]]` | Get cross-references from an address (LLM-friendly unified i |
| `get_refs_to(ea: ea_t, kind: Union[XrefKind, str]=XrefKind.ALL)` | `Iterator[Union[XrefInfo, ea_t]]` | Get cross-references to an address (LLM-friendly unified int |
| `has_any_refs_from(ea: ea_t)` | `bool` | Check if any references from this address exist. |
| `has_any_refs_to(ea: ea_t)` | `bool` | Check if any references to this address exist. |
| `has_code_refs_to(ea: ea_t)` | `bool` | Check if any code references to this address exist. |
| `has_data_refs_to(ea: ea_t)` | `bool` | Check if any data references to this address exist. |
| `has_refs_from(ea: ea_t, kind: Union[XrefKind, str]=XrefKind.ALL)` | `bool` | Check if references from an address exist (LLM-friendly unif |
| `has_refs_to(ea: ea_t, kind: Union[XrefKind, str]=XrefKind.ALL)` | `bool` | Check if references to an address exist (LLM-friendly unifie |
| `jumps_from_ea(ea: ea_t)` | `Iterator[ea_t]` | Get addresses jumped to from this address. |
| `jumps_to_ea(ea: ea_t)` | `Iterator[ea_t]` | Get addresses where jumps to this address occur. |
| `reads_of_ea(data_ea: ea_t)` | `Iterator[ea_t]` | Get addresses that read from this data location. |
| `to_ea(ea: ea_t, flags: XrefsFlags=XrefsFlags.ALL)` | `Iterator[XrefInfo]` | Get all cross-references to an address. |
| `writes_to_ea(data_ea: ea_t)` | `Iterator[ea_t]` | Get addresses that write to this data location. |

---
