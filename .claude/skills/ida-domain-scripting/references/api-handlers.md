# IDA Domain API Handlers Reference

Quick reference for all ida-domain handlers and their key methods.

## Table of Contents

1. [Functions](#functions)
2. [Instructions](#instructions)
3. [Cross-References (xrefs)](#cross-references-xrefs)
4. [Call Graph](#call-graph)
5. [Decompiler](#decompiler)
6. [Bytes](#bytes)
7. [Strings](#strings)
8. [Names](#names)
9. [Comments](#comments)
10. [Types](#types)
11. [Segments](#segments)
12. [Entries](#entries)
13. [Imports](#imports)
14. [Stack Frames](#stack-frames)
15. [Search](#search)
16. [Switches](#switches)
17. [Try Blocks](#try-blocks)
18. [Fixups](#fixups)
19. [Problems](#problems)
20. [Exporter](#exporter)
21. [Signature Files](#signature-files)
22. [Analysis](#analysis)
23. [Heads](#heads)
24. [Hooks](#hooks)

---

## Functions

`db.functions` - Function analysis, pseudocode, and local variables.

**Iteration**: `for func in db.functions`

| Method | Returns | Description |
|--------|---------|-------------|
| `get_at(ea)` | `Optional[func_t]` | Get function containing address |
| `get_by_name(name)` | `Optional[func_t]` | Get function by name |
| `get_name(func)` | `str` | Get function name |
| `get_signature(func)` | `Optional[str]` | Get function signature |
| `get_disassembly(func)` | `List[str]` | Get disassembly lines |
| `get_pseudocode(func)` | `List[str]` | Get decompiled pseudocode |
| `get_callers(func)` | `List[func_t]` | Get direct callers |
| `get_callees(func)` | `List[func_t]` | Get direct callees |
| `get_flowchart(func)` | `FlowChart` | Get basic block flowchart |
| `get_local_variables(func)` | `List[LocalVariable]` | Get local variables |
| `get_local_variable_references(func, lvar)` | `List[LocalVariableReference]` | Get variable references |
| `get_flags(func)` | `FunctionFlags` | Get function flags |
| `create(ea)` | `bool` | Create function at address |
| `delete(func)` | `bool` | Delete function |

---

## Instructions

`db.instructions` - Instruction decoding and operand access.

**Iteration**: `for insn in db.instructions`

| Method | Returns | Description |
|--------|---------|-------------|
| `get_at(ea)` | `Optional[insn_t]` | Decode instruction at address |
| `get_disassembly(insn)` | `Optional[str]` | Get disassembly text |
| `get_mnemonic(insn)` | `Optional[str]` | Get instruction mnemonic |
| `get_operands(insn)` | `List[Operand]` | Get all operands |
| `get_operand(insn, index)` | `Optional[Operand]` | Get specific operand |
| `get_operands_count(insn)` | `int` | Count operands |
| `get_previous(ea)` | `Optional[insn_t]` | Get previous instruction |
| `get_next(ea)` | `Optional[insn_t]` | Get next instruction |
| `get_between(start_ea, end_ea)` | `Iterator[insn_t]` | Iterate instructions in range |
| `is_call_instruction(insn)` | `bool` | Check if call instruction |
| `breaks_sequential_flow(insn)` | `bool` | Check if stops flow (ret, jmp) |
| `create_at(ea)` | `bool` | Create instruction at address |
| `get_size(ea)` | `int` | Get instruction size in bytes |

---

## Cross-References (xrefs)

`db.xrefs` - Cross-reference analysis.

| Method | Returns | Description |
|--------|---------|-------------|
| `to_ea(ea, flags)` | `Iterator[XrefInfo]` | Get all xrefs TO address |
| `from_ea(ea, flags)` | `Iterator[XrefInfo]` | Get all xrefs FROM address |
| `code_refs_to_ea(ea)` | `Iterator[ea_t]` | Code references to address |
| `code_refs_from_ea(ea)` | `Iterator[ea_t]` | Code references from address |
| `data_refs_to_ea(ea)` | `Iterator[ea_t]` | Data references to address |
| `data_refs_from_ea(ea)` | `Iterator[ea_t]` | Data references from address |
| `calls_to_ea(ea)` | `Iterator[ea_t]` | Call sites to address |
| `calls_from_ea(ea)` | `Iterator[ea_t]` | Call targets from address |
| `jumps_to_ea(ea)` | `Iterator[ea_t]` | Jump sources to address |
| `jumps_from_ea(ea)` | `Iterator[ea_t]` | Jump targets from address |
| `reads_of_ea(ea)` | `Iterator[ea_t]` | Read accesses to address |
| `writes_to_ea(ea)` | `Iterator[ea_t]` | Write accesses to address |
| `has_any_refs_to(ea)` | `bool` | Check if any refs exist |
| `count_refs_to(ea)` | `int` | Count references to address |
| `get_callers(func_ea)` | `Iterator[CallerInfo]` | Detailed caller info |

---

## Call Graph

`db.callgraph` - Multi-hop call graph traversal.

| Method | Returns | Description |
|--------|---------|-------------|
| `callers_of(ea, max_depth=1)` | `Iterator[ea_t]` | Transitive callers |
| `callees_of(ea, max_depth=1)` | `Iterator[ea_t]` | Transitive callees |
| `paths_between(src_ea, dst_ea, max_depth=10)` | `Iterator[CallPath]` | Find call paths |
| `reachable_from(ea, max_depth=100)` | `Set[ea_t]` | All reachable functions |
| `reaches(ea, max_depth=100)` | `Set[ea_t]` | All functions that reach target |

---

## Decompiler

`db.decompiler` - Hex-Rays decompiler access.

| Method | Returns | Description |
|--------|---------|-------------|
| `decompile_at(ea)` | `Optional[cfuncptr_t]` | Decompile function |
| `is_available()` | `bool` | Check if decompiler available |

---

## Bytes

`db.bytes` - Raw byte-level memory operations.

| Method | Returns | Description |
|--------|---------|-------------|
| `get_byte_at(ea)` | `int` | Get single byte |
| `get_word_at(ea)` | `int` | Get 2-byte word |
| `get_dword_at(ea)` | `int` | Get 4-byte dword |
| `get_qword_at(ea)` | `int` | Get 8-byte qword |
| `get_bytes_at(ea, size)` | `bytes` | Get multiple bytes |
| `set_byte_at(ea, val)` | `None` | Set byte (modifies DB) |
| `patch_byte_at(ea, val)` | `None` | Patch byte (tracks original) |
| `revert_byte_at(ea)` | `None` | Revert patched byte |
| `get_original_byte_at(ea)` | `int` | Get original byte value |
| `is_code_at(ea)` | `bool` | Check if code byte |
| `is_data_at(ea)` | `bool` | Check if data byte |
| `is_unknown_at(ea)` | `bool` | Check if undefined |
| `get_disassembly_at(ea)` | `str` | Get disassembly at address |
| `create_byte_at(ea)` | `bool` | Create byte data |
| `create_word_at(ea)` | `bool` | Create word data |
| `create_dword_at(ea)` | `bool` | Create dword data |

---

## Strings

`db.strings` - String discovery and iteration.

**Iteration**: `for s in db.strings`

| Property/Method | Returns | Description |
|-----------------|---------|-------------|
| `s.address` | `ea_t` | String address |
| `s.length` | `int` | String length |
| `str(s)` | `str` | String value |

---

## Names

`db.names` - Symbol naming operations.

| Method | Returns | Description |
|--------|---------|-------------|
| `get_at(ea)` | `Optional[str]` | Get name at address |
| `set_name(ea, name)` | `bool` | Set name at address |
| `resolve_name(name)` | `Optional[ea_t]` | Get address of name |
| `delete_name(ea)` | `bool` | Delete name at address |

---

## Comments

`db.comments` - User comment operations.

| Method | Returns | Description |
|--------|---------|-------------|
| `get_at(ea)` | `Optional[str]` | Get regular comment |
| `set_at(ea, text)` | `None` | Set regular comment |
| `get_repeatable_at(ea)` | `Optional[str]` | Get repeatable comment |
| `set_repeatable_at(ea, text)` | `None` | Set repeatable comment |
| `delete_at(ea)` | `None` | Delete comment |

---

## Types

`db.types` - Type information and TIL management.

| Method | Returns | Description |
|--------|---------|-------------|
| `get_by_name(name)` | `Optional[tinfo_t]` | Get type by name |
| `apply_by_name(ea, type_name)` | `bool` | Apply type to address |
| `parse_declarations(til, decl)` | `None` | Parse C declarations |
| `get_local_library()` | `til_t` | Get local type library |
| `create_library(path, name)` | `til_t` | Create new TIL |
| `load_library(path)` | `til_t` | Load existing TIL |
| `save_library(til, path)` | `None` | Save TIL to file |
| `unload_library(til)` | `None` | Unload TIL |
| `format_type(tinfo)` | `str` | Format type as string |

---

## Segments

`db.segments` - Memory segment operations.

**Iteration**: `for seg in db.segments`

| Method | Returns | Description |
|--------|---------|-------------|
| `get_at(ea)` | `Optional[segment_t]` | Get segment at address |
| `get_by_name(name)` | `Optional[segment_t]` | Get segment by name |
| `get_all()` | `List[segment_t]` | Get all segments |

---

## Entries

`db.entries` - Entry point operations.

| Method | Returns | Description |
|--------|---------|-------------|
| `get_all()` | `List[entry]` | Get all entry points |
| `get_at(index)` | `Optional[entry]` | Get entry by index |

---

## Imports

`db.imports` - Import table access.

| Method | Returns | Description |
|--------|---------|-------------|
| `get_all()` | `List[import_module]` | Get all import modules |
| `get_all_entries()` | `List[import_entry]` | Get all import entries |
| `find_by_name(name)` | `Optional[import_entry]` | Find import by name |

---

## Stack Frames

`db.stack_frames` - Stack frame and variable analysis.

| Method | Returns | Description |
|--------|---------|-------------|
| `get_frame(func)` | `Optional[struc_t]` | Get stack frame structure |
| `get_frame_size(func)` | `int` | Get frame size |
| `get_local_vars_size(func)` | `int` | Get local vars area size |
| `get_saved_regs_size(func)` | `int` | Get saved registers size |
| `get_args_size(func)` | `int` | Get arguments area size |

---

## Search

`db.search` - Pattern-based address searching.

| Method | Returns | Description |
|--------|---------|-------------|
| `find_next(ea, what, direction)` | `Optional[ea_t]` | Find next match |
| `find_all(start_ea, end_ea, what)` | `Iterator[ea_t]` | Find all matches |
| `next_undefined(ea, direction)` | `Optional[ea_t]` | Find undefined bytes |
| `next_defined(ea, direction)` | `Optional[ea_t]` | Find defined item |
| `next_code(ea, direction)` | `Optional[ea_t]` | Find code address |
| `next_data(ea, direction)` | `Optional[ea_t]` | Find data address |
| `next_code_outside_function(ea, direction)` | `Optional[ea_t]` | Find orphaned code |
| `all_undefined(start_ea, end_ea)` | `Iterator[ea_t]` | Iterate undefined |
| `all_code(start_ea, end_ea)` | `Iterator[ea_t]` | Iterate code |
| `all_data(start_ea, end_ea)` | `Iterator[ea_t]` | Iterate data |

---

## Switches

`db.switches` - Switch statement analysis.

| Method | Returns | Description |
|--------|---------|-------------|
| `get_at(ea)` | `Optional[switch_info_t]` | Get switch at address |
| `get_cases(switch_info)` | `List[case_info]` | Get switch cases |

---

## Try Blocks

`db.try_blocks` - Exception handling blocks.

| Method | Returns | Description |
|--------|---------|-------------|
| `get_at(ea)` | `Optional[tryblk_t]` | Get try block at address |
| `get_in_function(func)` | `List[tryblk_t]` | Get all try blocks in function |

---

## Fixups

`db.fixups` - Relocation/fixup information.

| Method | Returns | Description |
|--------|---------|-------------|
| `get_at(ea)` | `Optional[fixup_data_t]` | Get fixup at address |
| `get_all()` | `Iterator[fixup_data_t]` | Iterate all fixups |

---

## Problems

`db.problems` - IDA problem list operations.

| Method | Returns | Description |
|--------|---------|-------------|
| `get_all()` | `List[problem_t]` | Get all problems |
| `get_at(ea)` | `Optional[problem_t]` | Get problem at address |

---

## Exporter

`db.exporter` - Export data to various formats.

| Method | Returns | Description |
|--------|---------|-------------|
| `to_asm(path)` | `bool` | Export to assembly file |
| `to_html(path)` | `bool` | Export to HTML file |

---

## Signature Files

`db.signature_files` - FLIRT signature operations.

| Method | Returns | Description |
|--------|---------|-------------|
| `apply(sig_name)` | `int` | Apply signature file |
| `get_applied()` | `List[str]` | Get applied signatures |

---

## Analysis

`db.analysis` - Control auto-analysis.

| Method | Returns | Description |
|--------|---------|-------------|
| `wait_for_completion()` | `None` | Wait for auto-analysis |
| `is_complete` | `bool` | Check if analysis done |
| `auto_mark(ea, what)` | `None` | Mark address for analysis |

---

## Heads

`db.heads` - Iterate over instruction/data starts.

**Iteration**: `for ea in db.heads`

| Method | Returns | Description |
|--------|---------|-------------|
| `get_between(start_ea, end_ea)` | `Iterator[ea_t]` | Iterate heads in range |

---

## Hooks

`db.hooks` - Event hook management.

| Method | Returns | Description |
|--------|---------|-------------|
| `add(hook)` | `None` | Register hook handler |
| `remove(hook)` | `None` | Unregister hook handler |
