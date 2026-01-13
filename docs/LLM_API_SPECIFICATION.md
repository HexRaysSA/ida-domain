# IDA-Domain LLM-Optimized API Specification

This document specifies a refactored API design optimized for LLM consumption. The goal is to create a minimal, predictable, and self-documenting API surface.

## Design Principles

1. **Minimal surface** - Fewer methods to remember
2. **Predictable patterns** - Same method names across entities
3. **String literals** - No enums to import (validated at runtime)
4. **Rich returns** - Objects with properties, not primitives
5. **Sensible defaults** - Most parameters optional
6. **Clear naming** - Self-documenting method names

## Compatibility Rules

1. **Pre-fork methods are NEVER removed** - They must remain for backward compatibility
2. **Pre-fork methods can be renamed** - But the old name must remain as a deprecated alias
3. **Post-fork methods can be freely modified** - They are new additions with no compatibility requirements

---

## Legend

| Symbol | Meaning |
|--------|---------|
| `[PRE-FORK]` | Method existed before fork - CANNOT be removed |
| `[POST-FORK]` | Method added after fork - can be modified/removed |
| `[KEEP]` | Keep as-is, no changes |
| `[ALIAS]` | Add new method name, keep old as deprecated alias |
| `[REMOVE]` | Remove method (POST-FORK only) |
| `[NEW]` | New method to create |
| `[MERGE]` | Merge multiple methods into one |
| `[DEPRECATE]` | Mark as deprecated, keep for compatibility |

---

## Standard Entity Interface

Every entity SHOULD implement these methods where applicable:

```python
class Entity:
    def get_at(ea) -> Object | None        # Get single item
    def get_all() -> Iterator[Object]      # Iterate all items
    def get_in_range(start, end) -> Iterator[Object]  # Items in range
    def exists_at(ea) -> bool              # Check existence
    def create(...) -> Object | bool       # Create new item
    def delete(ea) -> bool                 # Delete item
    def count() -> int                     # Total count
```

---

## Entity Specifications

### 1. Database

**File:** `ida_domain/database.py`

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `open` | `[PRE-FORK]` `[KEEP]` | `open(path) -> Database` | Open database file |
| `open_current` | `[PRE-FORK]` `[KEEP]` | `open_current() -> Database` | Get current IDA database |
| `close` | `[PRE-FORK]` `[KEEP]` | `close() -> None` | Close database |
| `save` | `[PRE-FORK]` `[KEEP]` | `save() -> bool` | Save database |
| `save_as` | `[POST-FORK]` `[KEEP]` | `save_as(path) -> bool` | Save to new path |
| `is_valid_ea` | `[PRE-FORK]` `[KEEP]` | `is_valid_ea(ea) -> bool` | Check if address is valid |

**Entity Accessors:** All `[KEEP]` - `functions`, `bytes`, `names`, `segments`, `comments`, `xrefs`, `instructions`, `types`, `strings`, `analysis`, `imports`, `search`, `stack_frames`, `switches`, `problems`, `fixups`, `exporter`, `try_blocks`, `decompiler`

---

### 2. Functions

**File:** `ida_domain/functions.py`

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `get_at` | `[PRE-FORK]` `[KEEP]` | `get_at(ea) -> func_t \| None` | Get function containing address |
| `get_all` | `[PRE-FORK]` `[KEEP]` | `get_all() -> Iterator[func_t]` | Iterate all functions |
| `get_between` | `[PRE-FORK]` `[KEEP]` | `get_between(start, end) -> Iterator[func_t]` | Functions in range |
| `get_by_name` | `[PRE-FORK]` `[KEEP]` | `get_by_name(name) -> func_t \| None` | Find by name |
| `create` | `[PRE-FORK]` `[KEEP]` | `create(ea) -> bool` | Create function |
| `remove` | `[PRE-FORK]` `[KEEP]` | `remove(ea) -> bool` | Delete function |
| `get_next` | `[PRE-FORK]` `[KEEP]` | `get_next(ea) -> func_t \| None` | Get next function |
| `get_previous` | `[POST-FORK]` `[KEEP]` | `get_previous(ea) -> func_t \| None` | Get previous function |
| `set_name` | `[PRE-FORK]` `[KEEP]` | `set_name(func, name) -> bool` | Set function name |
| `get_name` | `[PRE-FORK]` `[KEEP]` | `get_name(func) -> str` | Get function name |
| `get_signature` | `[PRE-FORK]` `[KEEP]` | `get_signature(func) -> str` | Get function signature |
| `get_callers` | `[PRE-FORK]` `[KEEP]` | `get_callers(func) -> List[func_t]` | Get calling functions |
| `get_callees` | `[PRE-FORK]` `[KEEP]` | `get_callees(func) -> List[func_t]` | Get called functions |
| `get_disassembly` | `[PRE-FORK]` `[KEEP]` | `get_disassembly(func) -> List[str]` | Get disassembly lines |
| `get_pseudocode` | `[PRE-FORK]` `[KEEP]` | `get_pseudocode(func) -> List[str]` | Get decompiled code |
| `get_microcode` | `[PRE-FORK]` `[KEEP]` | `get_microcode(func) -> List[str]` | Get microcode |
| `get_flowchart` | `[PRE-FORK]` `[KEEP]` | `get_flowchart(func) -> Flowchart` | Get flowchart |
| `get_instructions` | `[PRE-FORK]` `[KEEP]` | `get_instructions(func) -> Iterator[insn_t]` | Get instructions |
| `get_chunk_at` | `[PRE-FORK]` `[KEEP]` | `get_chunk_at(ea) -> func_t \| None` | Get chunk at address |
| `get_tails` | `[PRE-FORK]` `[KEEP]` | `get_tails(func) -> List[func_t]` | Get tail chunks |
| `is_entry_chunk` | `[PRE-FORK]` `[KEEP]` | `is_entry_chunk(chunk) -> bool` | Check if entry chunk |
| `is_tail_chunk` | `[PRE-FORK]` `[KEEP]` | `is_tail_chunk(chunk) -> bool` | Check if tail chunk |
| `get_flags` | `[PRE-FORK]` `[KEEP]` | `get_flags(func) -> FunctionFlags` | Get function flags |
| `is_far` | `[PRE-FORK]` `[KEEP]` | `is_far(func) -> bool` | Check if far function |
| `does_return` | `[PRE-FORK]` `[KEEP]` | `does_return(func) -> bool` | Check if function returns |
| `reanalyze` | `[POST-FORK]` `[KEEP]` | `reanalyze(func) -> bool` | Reanalyze function |

**New methods to add:**

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `delete` | `[NEW]` | `delete(ea) -> bool` | Alias for `remove` (standard naming) |
| `count` | `[NEW]` | `count() -> int` | Total function count |
| `exists_at` | `[NEW]` | `exists_at(ea) -> bool` | Check if function exists |
| `get_in_range` | `[NEW]` | `get_in_range(start, end) -> Iterator[func_t]` | Alias for `get_between` (standard naming) |

**Methods to REMOVE (post-fork only):**

| Method | Status | Reason |
|--------|--------|--------|
| `get_index` | `[POST-FORK]` `[REMOVE]` | Low-level, use iteration |
| `contains` | `[POST-FORK]` `[REMOVE]` | Use `get_at(ea) is not None` |
| `set_start` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `set_end` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `update` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `add_tail` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `remove_tail` | `[POST-FORK]` `[REMOVE]` | Low-level |

---

### 3. Bytes

**File:** `ida_domain/bytes.py`

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `get_byte_at` | `[PRE-FORK]` `[KEEP]` | `get_byte_at(ea) -> int` | Read byte |
| `get_word_at` | `[PRE-FORK]` `[KEEP]` | `get_word_at(ea) -> int` | Read word (2 bytes) |
| `get_dword_at` | `[PRE-FORK]` `[KEEP]` | `get_dword_at(ea) -> int` | Read dword (4 bytes) |
| `get_qword_at` | `[PRE-FORK]` `[KEEP]` | `get_qword_at(ea) -> int` | Read qword (8 bytes) |
| `get_float_at` | `[PRE-FORK]` `[KEEP]` | `get_float_at(ea) -> float` | Read float |
| `get_double_at` | `[PRE-FORK]` `[KEEP]` | `get_double_at(ea) -> float` | Read double |
| `set_byte_at` | `[PRE-FORK]` `[KEEP]` | `set_byte_at(ea, value) -> bool` | Write byte |
| `set_word_at` | `[PRE-FORK]` `[KEEP]` | `set_word_at(ea, value) -> None` | Write word |
| `set_dword_at` | `[PRE-FORK]` `[KEEP]` | `set_dword_at(ea, value) -> None` | Write dword |
| `set_qword_at` | `[PRE-FORK]` `[KEEP]` | `set_qword_at(ea, value) -> None` | Write qword |
| `set_bytes_at` | `[PRE-FORK]` `[KEEP]` | `set_bytes_at(ea, data) -> None` | Write bytes |
| `patch_byte_at` | `[PRE-FORK]` `[KEEP]` | `patch_byte_at(ea, value) -> bool` | Patch byte |
| `patch_word_at` | `[PRE-FORK]` `[KEEP]` | `patch_word_at(ea, value) -> bool` | Patch word |
| `patch_dword_at` | `[PRE-FORK]` `[KEEP]` | `patch_dword_at(ea, value) -> bool` | Patch dword |
| `patch_qword_at` | `[PRE-FORK]` `[KEEP]` | `patch_qword_at(ea, value) -> bool` | Patch qword |
| `patch_bytes_at` | `[PRE-FORK]` `[KEEP]` | `patch_bytes_at(ea, data) -> None` | Patch bytes |
| `get_original_byte_at` | `[PRE-FORK]` `[KEEP]` | `get_original_byte_at(ea) -> int` | Get original byte |
| `get_original_word_at` | `[PRE-FORK]` `[KEEP]` | `get_original_word_at(ea) -> int` | Get original word |
| `get_original_dword_at` | `[PRE-FORK]` `[KEEP]` | `get_original_dword_at(ea) -> int` | Get original dword |
| `get_original_qword_at` | `[PRE-FORK]` `[KEEP]` | `get_original_qword_at(ea) -> int` | Get original qword |
| `revert_byte_at` | `[PRE-FORK]` `[KEEP]` | `revert_byte_at(ea) -> bool` | Revert patch |
| `find_bytes_between` | `[PRE-FORK]` `[KEEP]` | `find_bytes_between(start, end, pattern) -> Iterator[ea_t]` | Search for bytes |
| `find_text_between` | `[PRE-FORK]` `[KEEP]` | `find_text_between(start, end, text) -> Iterator[ea_t]` | Search for text |
| `find_immediate_between` | `[PRE-FORK]` `[KEEP]` | `find_immediate_between(start, end, value) -> Iterator[ea_t]` | Search for immediate |
| `create_byte_at` | `[PRE-FORK]` `[KEEP]` | `create_byte_at(ea, count, force) -> bool` | Create byte data |
| `create_word_at` | `[PRE-FORK]` `[KEEP]` | `create_word_at(ea, count, force) -> bool` | Create word data |
| `create_dword_at` | `[PRE-FORK]` `[KEEP]` | `create_dword_at(ea, count, force) -> bool` | Create dword data |
| `create_qword_at` | `[PRE-FORK]` `[KEEP]` | `create_qword_at(ea, count, force) -> bool` | Create qword data |
| `get_disassembly_at` | `[PRE-FORK]` `[KEEP]` | `get_disassembly_at(ea) -> str` | Get disasm line |
| `get_item_size_at` | `[POST-FORK]` `[KEEP]` | `get_item_size_at(ea) -> int` | Item size |

**New methods to add:**

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `find_bytes` | `[NEW]` | `find_bytes(start, end, pattern) -> Iterator[ea_t]` | Alias for `find_bytes_between` |
| `find_text` | `[NEW]` | `find_text(start, end, text) -> Iterator[ea_t]` | Alias for `find_text_between` |
| `set_operand_format` | `[NEW]` | `set_operand_format(ea, n, format) -> bool` | Set operand display. `format`: `"hex"`, `"decimal"`, `"octal"`, `"binary"`, `"char"` |
| `get_operand_type` | `[NEW]` | `get_operand_type(ea, n) -> str` | Get operand type. Returns: `"offset"`, `"char"`, `"enum"`, `"struct_offset"`, `"stack_var"`, `"immediate"`, etc. |

**Methods to REMOVE (post-fork only):**

| Method | Status | Reason |
|--------|--------|--------|
| `set_operand_hex` | `[POST-FORK]` `[REMOVE]` | Use `set_operand_format(ea, n, "hex")` |
| `set_operand_decimal` | `[POST-FORK]` `[REMOVE]` | Use `set_operand_format(ea, n, "decimal")` |
| `set_operand_octal` | `[POST-FORK]` `[REMOVE]` | Use `set_operand_format(ea, n, "octal")` |
| `set_operand_binary` | `[POST-FORK]` `[REMOVE]` | Use `set_operand_format(ea, n, "binary")` |
| `set_operand_char` | `[POST-FORK]` `[REMOVE]` | Use `set_operand_format(ea, n, "char")` |
| `is_offset_operand` | `[POST-FORK]` `[REMOVE]` | Use `get_operand_type(ea, n) == "offset"` |
| `is_char_operand` | `[POST-FORK]` `[REMOVE]` | Use `get_operand_type(ea, n) == "char"` |
| `is_enum_operand` | `[POST-FORK]` `[REMOVE]` | Use `get_operand_type(ea, n) == "enum"` |
| `is_struct_offset_operand` | `[POST-FORK]` `[REMOVE]` | Use `get_operand_type(ea, n) == "struct_offset"` |
| `is_stack_var_operand` | `[POST-FORK]` `[REMOVE]` | Use `get_operand_type(ea, n) == "stack_var"` |
| `get_item_head_at` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `get_item_end_at` | `[POST-FORK]` `[REMOVE]` | Low-level |

---

### 4. Names

**File:** `ida_domain/names.py`

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `get_at` | `[PRE-FORK]` `[KEEP]` | `get_at(ea) -> str \| None` | Get name at address |
| `get_all` | `[PRE-FORK]` `[KEEP]` | `get_all() -> Iterator[Tuple[ea_t, str]]` | All named addresses |
| `get_at_index` | `[PRE-FORK]` `[KEEP]` | `get_at_index(index) -> Tuple[ea_t, str] \| None` | Get by index |
| `get_count` | `[PRE-FORK]` `[KEEP]` | `get_count() -> int` | Total named addresses |
| `set_name` | `[PRE-FORK]` `[KEEP]` | `set_name(ea, name) -> bool` | Set name |
| `force_name` | `[PRE-FORK]` `[KEEP]` | `force_name(ea, name) -> bool` | Force set name |
| `delete` | `[PRE-FORK]` `[KEEP]` | `delete(ea) -> bool` | Delete name |
| `is_valid_name` | `[PRE-FORK]` `[KEEP]` | `is_valid_name(name) -> bool` | Check if valid name |
| `is_public_name` | `[PRE-FORK]` `[KEEP]` | `is_public_name(ea) -> bool` | Check if public |
| `make_name_public` | `[PRE-FORK]` `[KEEP]` | `make_name_public(ea) -> None` | Make public |
| `make_name_non_public` | `[PRE-FORK]` `[KEEP]` | `make_name_non_public(ea) -> None` | Make non-public |
| `is_weak_name` | `[PRE-FORK]` `[KEEP]` | `is_weak_name(ea) -> bool` | Check if weak |
| `make_name_weak` | `[PRE-FORK]` `[KEEP]` | `make_name_weak(ea) -> None` | Make weak |
| `make_name_non_weak` | `[PRE-FORK]` `[KEEP]` | `make_name_non_weak(ea) -> None` | Make non-weak |
| `get_demangled_name` | `[PRE-FORK]` `[KEEP]` | `get_demangled_name(ea) -> str` | Get demangled |
| `demangle_name` | `[PRE-FORK]` `[KEEP]` | `demangle_name(name) -> str` | Demangle C++ name |

**New methods to add:**

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `resolve` | `[NEW]` | `resolve(name) -> ea_t \| None` | Resolve name to address |
| `count` | `[NEW]` | `count() -> int` | Alias for `get_count` |
| `set` | `[NEW]` | `set(ea, name, force=False) -> bool` | Unified setter (calls `set_name` or `force_name`) |
| `is_valid` | `[NEW]` | `is_valid(name) -> bool` | Alias for `is_valid_name` |
| `is_public` | `[NEW]` | `is_public(ea) -> bool` | Alias for `is_public_name` |
| `is_weak` | `[NEW]` | `is_weak(ea) -> bool` | Alias for `is_weak_name` |
| `set_public` | `[NEW]` | `set_public(ea, public=True) -> None` | Unified public setter |
| `set_weak` | `[NEW]` | `set_weak(ea, weak=True) -> None` | Unified weak setter |

**Methods to REMOVE (post-fork only):**

| Method | Status | Reason |
|--------|--------|--------|
| `resolve_name` | `[POST-FORK]` `[REMOVE]` | Replaced by `resolve` |
| `resolve_value` | `[POST-FORK]` `[REMOVE]` | Specialized |
| `delete_local` | `[POST-FORK]` `[REMOVE]` | Use `delete` |
| `create_dummy` | `[POST-FORK]` `[REMOVE]` | Specialized |
| `get_visible_name` | `[POST-FORK]` `[REMOVE]` | Use `get_at` |
| `validate` | `[POST-FORK]` `[REMOVE]` | Use `is_valid` |
| `get_colored_name` | `[POST-FORK]` `[REMOVE]` | Specialized |
| `format_expression` | `[POST-FORK]` `[REMOVE]` | Specialized |

---

### 5. Xrefs

**File:** `ida_domain/xrefs.py`

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `to_ea` | `[PRE-FORK]` `[KEEP]` | `to_ea(ea, flags) -> Iterator[XrefInfo]` | Refs pointing to address |
| `from_ea` | `[PRE-FORK]` `[KEEP]` | `from_ea(ea, flags) -> Iterator[XrefInfo]` | Refs from address |
| `code_refs_to_ea` | `[PRE-FORK]` `[KEEP]` | `code_refs_to_ea(ea, flow) -> Iterator[ea_t]` | Code refs to |
| `code_refs_from_ea` | `[PRE-FORK]` `[KEEP]` | `code_refs_from_ea(ea, flow) -> Iterator[ea_t]` | Code refs from |
| `data_refs_to_ea` | `[PRE-FORK]` `[KEEP]` | `data_refs_to_ea(ea) -> Iterator[ea_t]` | Data refs to |
| `data_refs_from_ea` | `[PRE-FORK]` `[KEEP]` | `data_refs_from_ea(ea) -> Iterator[ea_t]` | Data refs from |
| `get_callers` | `[PRE-FORK]` `[KEEP]` | `get_callers(func_ea) -> Iterator[CallerInfo]` | Get callers |
| `calls_to_ea` | `[PRE-FORK]` `[KEEP]` | `calls_to_ea(ea) -> Iterator[ea_t]` | Calls to address |
| `calls_from_ea` | `[PRE-FORK]` `[KEEP]` | `calls_from_ea(ea) -> Iterator[ea_t]` | Calls from address |
| `jumps_to_ea` | `[PRE-FORK]` `[KEEP]` | `jumps_to_ea(ea) -> Iterator[ea_t]` | Jumps to address |
| `jumps_from_ea` | `[PRE-FORK]` `[KEEP]` | `jumps_from_ea(ea) -> Iterator[ea_t]` | Jumps from address |
| `reads_of_ea` | `[PRE-FORK]` `[KEEP]` | `reads_of_ea(ea) -> Iterator[ea_t]` | Reads of address |
| `writes_to_ea` | `[PRE-FORK]` `[KEEP]` | `writes_to_ea(ea) -> Iterator[ea_t]` | Writes to address |

**New methods to add (LLM-friendly aliases):**

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `get_refs_to` | `[NEW]` | `get_refs_to(ea) -> Iterator[XrefInfo]` | Alias for `to_ea` |
| `get_refs_from` | `[NEW]` | `get_refs_from(ea) -> Iterator[XrefInfo]` | Alias for `from_ea` |
| `has_refs_to` | `[NEW]` | `has_refs_to(ea, type=None) -> bool` | Check if refs exist. `type`: `None`, `"code"`, `"data"` |
| `has_refs_from` | `[NEW]` | `has_refs_from(ea) -> bool` | Check if refs from exist |
| `add` | `[NEW]` | `add(from_ea, to_ea, type="code") -> bool` | Add xref |
| `delete` | `[NEW]` | `delete(from_ea, to_ea) -> bool` | Delete xref |

**Methods to REMOVE (post-fork only):**

| Method | Status | Reason |
|--------|--------|--------|
| `has_any_refs_to` | `[POST-FORK]` `[REMOVE]` | Use `has_refs_to(ea)` |
| `has_any_refs_from` | `[POST-FORK]` `[REMOVE]` | Use `has_refs_from(ea)` |
| `has_code_refs_to` | `[POST-FORK]` `[REMOVE]` | Use `has_refs_to(ea, "code")` |
| `has_data_refs_to` | `[POST-FORK]` `[REMOVE]` | Use `has_refs_to(ea, "data")` |
| `count_refs_to` | `[POST-FORK]` `[REMOVE]` | Use `len(list(get_refs_to(ea)))` |
| `count_refs_from` | `[POST-FORK]` `[REMOVE]` | Use `len(list(get_refs_from(ea)))` |

---

### 6. Instructions

**File:** `ida_domain/instructions.py`

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `get_at` | `[PRE-FORK]` `[KEEP]` | `get_at(ea) -> insn_t \| None` | Get instruction |
| `get_all` | `[PRE-FORK]` `[KEEP]` | `get_all() -> Iterator[insn_t]` | All instructions |
| `get_between` | `[PRE-FORK]` `[KEEP]` | `get_between(start, end) -> Iterator[insn_t]` | Instructions in range |
| `get_previous` | `[PRE-FORK]` `[KEEP]` | `get_previous(ea) -> insn_t \| None` | Previous instruction |
| `get_mnemonic` | `[PRE-FORK]` `[KEEP]` | `get_mnemonic(insn) -> str` | Get mnemonic |
| `get_operands` | `[PRE-FORK]` `[KEEP]` | `get_operands(insn) -> List[Operand]` | Get operands |
| `get_operand` | `[PRE-FORK]` `[KEEP]` | `get_operand(insn, index) -> Operand \| None` | Get operand |
| `get_operands_count` | `[PRE-FORK]` `[KEEP]` | `get_operands_count(insn) -> int` | Operand count |
| `get_disassembly` | `[PRE-FORK]` `[KEEP]` | `get_disassembly(insn) -> str` | Get disassembly |
| `is_valid` | `[PRE-FORK]` `[KEEP]` | `is_valid(insn) -> bool` | Check if valid |
| `is_call_instruction` | `[PRE-FORK]` `[KEEP]` | `is_call_instruction(insn) -> bool` | Check if call |
| `is_indirect_jump_or_call` | `[PRE-FORK]` `[KEEP]` | `is_indirect_jump_or_call(insn) -> bool` | Check if indirect |
| `breaks_sequential_flow` | `[PRE-FORK]` `[KEEP]` | `breaks_sequential_flow(insn) -> bool` | Check if breaks flow |
| `get_next` | `[POST-FORK]` `[KEEP]` | `get_next(ea) -> insn_t \| None` | Next instruction |
| `create_at` | `[POST-FORK]` `[KEEP]` | `create_at(ea) -> bool` | Create instruction |

**New methods to add:**

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `get_in_range` | `[NEW]` | `get_in_range(start, end) -> Iterator[insn_t]` | Alias for `get_between` |
| `create` | `[NEW]` | `create(ea) -> bool` | Alias for `create_at` |
| `is_call` | `[NEW]` | `is_call(insn) -> bool` | Alias for `is_call_instruction` |
| `add_xref` | `[NEW]` | `add_xref(from_ea, to_ea, type="code") -> bool` | Add code/data xref |

**Methods to REMOVE (post-fork only):**

| Method | Status | Reason |
|--------|--------|--------|
| `decode_at` | `[POST-FORK]` `[REMOVE]` | Use `get_at` |
| `get_preceding` | `[POST-FORK]` `[REMOVE]` | Duplicate of `get_previous` |
| `can_decode` | `[POST-FORK]` `[REMOVE]` | Use `get_at(ea) is not None` |
| `get_size` | `[POST-FORK]` `[REMOVE]` | Use `insn.size` property |
| `format_operand` | `[POST-FORK]` `[REMOVE]` | Specialized |
| `add_code_reference` | `[POST-FORK]` `[REMOVE]` | Use `add_xref(from, to, "code")` |
| `add_data_reference` | `[POST-FORK]` `[REMOVE]` | Use `add_xref(from, to, "data")` |
| `get_data_type_size` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `get_data_type_by_size` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `get_data_type_flag` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `is_floating_data_type` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `map_operand_address` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `calculate_data_segment` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `set_operand_offset` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `set_operand_offset_ex` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `get_operand_offset_base` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `get_operand_offset_target` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `format_offset_expression` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `calculate_offset_base` | `[POST-FORK]` `[REMOVE]` | Low-level |

---

### 7. Segments

**File:** `ida_domain/segments.py`

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `get_at` | `[PRE-FORK]` `[KEEP]` | `get_at(ea) -> segment_t \| None` | Get segment containing address |
| `get_all` | `[PRE-FORK]` `[KEEP]` | `get_all() -> Iterator[segment_t]` | All segments |
| `get_by_name` | `[PRE-FORK]` `[KEEP]` | `get_by_name(name) -> segment_t \| None` | Find by name |
| `get_name` | `[PRE-FORK]` `[KEEP]` | `get_name(seg) -> str` | Get segment name |
| `set_name` | `[PRE-FORK]` `[KEEP]` | `set_name(seg, name) -> bool` | Set segment name |
| `get_size` | `[PRE-FORK]` `[KEEP]` | `get_size(seg) -> int` | Get segment size |
| `get_class` | `[PRE-FORK]` `[KEEP]` | `get_class(seg) -> str` | Get segment class |
| `get_bitness` | `[PRE-FORK]` `[KEEP]` | `get_bitness(seg) -> int` | Get bitness |
| `get_comment` | `[PRE-FORK]` `[KEEP]` | `get_comment(seg, repeatable) -> str` | Get comment |
| `set_comment` | `[PRE-FORK]` `[KEEP]` | `set_comment(seg, comment, repeatable) -> bool` | Set comment |
| `set_permissions` | `[PRE-FORK]` `[KEEP]` | `set_permissions(seg, perms) -> bool` | Set permissions |
| `add_permissions` | `[PRE-FORK]` `[KEEP]` | `add_permissions(seg, perms) -> bool` | Add permissions |
| `remove_permissions` | `[PRE-FORK]` `[KEEP]` | `remove_permissions(seg, perms) -> bool` | Remove permissions |
| `set_addressing_mode` | `[PRE-FORK]` `[KEEP]` | `set_addressing_mode(seg, mode) -> bool` | Set addressing mode |
| `add` | `[PRE-FORK]` `[KEEP]` | `add(start, end, name, ...) -> bool` | Create segment |
| `append` | `[PRE-FORK]` `[KEEP]` | `append(name, sclass, size) -> bool` | Append segment |
| `get_by_index` | `[POST-FORK]` `[KEEP]` | `get_by_index(index) -> segment_t \| None` | Get by index |
| `set_class` | `[POST-FORK]` `[KEEP]` | `set_class(seg, sclass) -> bool` | Set segment class |
| `delete` | `[POST-FORK]` `[KEEP]` | `delete(seg) -> bool` | Delete segment |
| `get_first` | `[POST-FORK]` `[KEEP]` | `get_first() -> segment_t \| None` | First segment |
| `get_last` | `[POST-FORK]` `[KEEP]` | `get_last() -> segment_t \| None` | Last segment |
| `get_next` | `[POST-FORK]` `[KEEP]` | `get_next(seg) -> segment_t \| None` | Next segment |
| `get_previous` | `[POST-FORK]` `[KEEP]` | `get_previous(seg) -> segment_t \| None` | Previous segment |

**New methods to add:**

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `create` | `[NEW]` | `create(start, end, name, sclass) -> bool` | Alias for `add` |
| `count` | `[NEW]` | `count() -> int` | Total segment count |

**Methods to REMOVE (post-fork only):**

| Method | Status | Reason |
|--------|--------|--------|
| `get_index` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `get_type` | `[POST-FORK]` `[REMOVE]` | Use segment properties |
| `get_paragraph` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `get_base` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `set_start` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `set_end` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `update` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `move` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `rebase` | `[POST-FORK]` `[REMOVE]` | Low-level |
| `set_visible` | `[POST-FORK]` `[REMOVE]` | Specialized |
| `is_visible` | `[POST-FORK]` `[REMOVE]` | Specialized |

---

### 8. Comments

**File:** `ida_domain/comments.py`

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `get_at` | `[PRE-FORK]` `[KEEP]` | `get_at(ea, kind) -> str \| None` | Get comment |
| `set_at` | `[PRE-FORK]` `[KEEP]` | `set_at(ea, comment, kind) -> bool` | Set comment |
| `delete_at` | `[PRE-FORK]` `[KEEP]` | `delete_at(ea, kind) -> None` | Delete comment |
| `get_all` | `[PRE-FORK]` `[KEEP]` | `get_all(kind) -> Iterator[CommentInfo]` | All comments |
| `set_extra_at` | `[PRE-FORK]` `[KEEP]` | `set_extra_at(ea, index, comment, kind) -> bool` | Set extra comment |
| `get_extra_at` | `[PRE-FORK]` `[KEEP]` | `get_extra_at(ea, index, kind) -> str \| None` | Get extra comment |
| `get_all_extra_at` | `[PRE-FORK]` `[KEEP]` | `get_all_extra_at(ea, kind) -> Iterator[str]` | Get all extra |
| `delete_extra_at` | `[PRE-FORK]` `[KEEP]` | `delete_extra_at(ea, index, kind) -> bool` | Delete extra comment |

**New methods to add:**

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `get` | `[NEW]` | `get(ea, repeatable=False) -> str \| None` | Simplified get |
| `set` | `[NEW]` | `set(ea, comment, repeatable=False) -> bool` | Simplified set |
| `delete` | `[NEW]` | `delete(ea, repeatable=False) -> None` | Simplified delete |

**Methods to REMOVE (post-fork only):**

| Method | Status | Reason |
|--------|--------|--------|
| `delete_all_extra_at` | `[POST-FORK]` `[REMOVE]` | Specialized |
| `get_first_free_extra_index` | `[POST-FORK]` `[REMOVE]` | Specialized |
| `generate_disasm_line` | `[POST-FORK]` `[REMOVE]` | Move to Instructions or utility |
| `generate_disassembly` | `[POST-FORK]` `[REMOVE]` | Move to Instructions or utility |
| `strip_color_tags` | `[POST-FORK]` `[REMOVE]` | Move to utility module |
| `calculate_visual_length` | `[POST-FORK]` `[REMOVE]` | Move to utility module |
| `skip_color_tags` | `[POST-FORK]` `[REMOVE]` | Move to utility module |
| `advance_in_colored_string` | `[POST-FORK]` `[REMOVE]` | Move to utility module |
| `colorize` | `[POST-FORK]` `[REMOVE]` | Move to utility module |
| `requires_color_escape` | `[POST-FORK]` `[REMOVE]` | Move to utility module |
| `get_prefix_color` | `[POST-FORK]` `[REMOVE]` | Specialized |
| `get_background_color` | `[POST-FORK]` `[REMOVE]` | Specialized |
| `add_sourcefile` | `[POST-FORK]` `[REMOVE]` | Specialized |
| `get_sourcefile` | `[POST-FORK]` `[REMOVE]` | Specialized |
| `delete_sourcefile` | `[POST-FORK]` `[REMOVE]` | Specialized |

---

### 9. Analysis

**File:** `ida_domain/analysis.py`

This is a **new entity (post-fork)** - all methods can be freely modified.

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `wait` | `[NEW]` | `wait() -> bool` | Wait for completion |
| `analyze` | `[NEW]` | `analyze(start, end, wait=True) -> int` | Analyze range |
| `schedule` | `[NEW]` | `schedule(ea, what="reanalysis") -> None` | Schedule analysis. `what`: `"code"`, `"function"`, `"reanalysis"` |
| `cancel` | `[NEW]` | `cancel(start, end) -> None` | Cancel analysis |
| `is_complete` | `[POST-FORK]` `[KEEP]` | `is_complete -> bool` | Property: analysis complete? |
| `is_enabled` | `[POST-FORK]` `[KEEP]` | `is_enabled -> bool` | Property: analysis enabled? |
| `set_enabled` | `[POST-FORK]` `[KEEP]` | `set_enabled(enabled) -> bool` | Enable/disable analysis |

**Methods to REMOVE (all post-fork):**

| Method | Reason |
|--------|--------|
| `wait_for_completion` | Rename to `wait` |
| `analyze_range` | Rename to `analyze` |
| `analyze_range_until_stable` | Use `analyze(start, end)` |
| `wait_for_range` | Use `analyze(start, end, wait=True)` |
| `schedule_code_analysis` | Use `schedule(ea, "code")` |
| `schedule_function_analysis` | Use `schedule(ea, "function")` |
| `schedule_reanalysis` | Use `schedule(ea, "reanalysis")` |
| `schedule_range_analysis` | Use `analyze(start, end, wait=False)` |
| `cancel_analysis` | Rename to `cancel` |
| `cancel_queue` | Merge into `cancel` |
| `current_state` | Specialized |
| `auto_wait` | Legacy |
| `plan_and_wait` | Legacy |
| `auto_is_ok` | Legacy |
| `get_auto_state` | Legacy |
| `plan_ea` | Legacy |
| `plan_range` | Legacy |
| `get_auto_display` | Legacy |
| `enable_auto` | Legacy |
| `disable_auto` | Legacy |
| `show_auto` | Legacy/UI |
| `noshow_auto` | Legacy/UI |
| `analysis_active` | Legacy |
| `show_addr` | UI only |
| `reanalyze_function_callers` | Specialized |
| `recreate_instruction` | Specialized |
| `revert_analysis` | Specialized |

---

### 10. Search

**File:** `ida_domain/search.py`

This is a **new entity (post-fork)** - all methods can be freely modified.

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `find_next` | `[NEW]` | `find_next(ea, what, direction="forward") -> ea_t \| None` | Find next match |
| `find_all` | `[NEW]` | `find_all(start, end, what) -> Iterator[ea_t]` | Find all matches |

**`what` parameter values:** `"undefined"`, `"defined"`, `"code"`, `"data"`, `"code_outside_function"`, `"error"`, `"untyped_operand"`, `"suspicious_operand"`

**Methods to REMOVE (all post-fork):**

| Method | Reason |
|--------|--------|
| `next_undefined` | Use `find_next(ea, "undefined")` |
| `next_defined` | Use `find_next(ea, "defined")` |
| `next_code` | Use `find_next(ea, "code")` |
| `next_data` | Use `find_next(ea, "data")` |
| `next_code_outside_function` | Use `find_next(ea, "code_outside_function")` |
| `next_error` | Use `find_next(ea, "error")` |
| `next_untyped_operand` | Use `find_next(ea, "untyped_operand")` |
| `next_suspicious_operand` | Use `find_next(ea, "suspicious_operand")` |
| `next_register_access` | Specialized |
| `all_undefined` | Use `find_all(start, end, "undefined")` |
| `all_defined` | Use `find_all(start, end, "defined")` |
| `all_code` | Use `find_all(start, end, "code")` |
| `all_data` | Use `find_all(start, end, "data")` |
| `all_code_outside_functions` | Use `find_all(start, end, "code_outside_function")` |
| `all_errors` | Use `find_all(start, end, "error")` |
| `all_untyped_operands` | Use `find_all(start, end, "untyped_operand")` |
| `all_register_accesses` | Specialized |

---

### 11. Imports

**File:** `ida_domain/imports.py`

This is a **new entity (post-fork)** - all methods can be freely modified.

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `get_all` | `[POST-FORK]` `[KEEP]` | `get_all() -> Iterator[ImportModule]` | All import modules |
| `get_all_entries` | `[POST-FORK]` `[KEEP]` | `get_all_entries() -> Iterator[ImportEntry]` | All import entries |
| `get_at` | `[POST-FORK]` `[KEEP]` | `get_at(ea) -> ImportEntry \| None` | Import at address |
| `get_module` | `[NEW]` | `get_module(name_or_index) -> ImportModule \| None` | Get module by name or index |
| `find` | `[NEW]` | `find(name, module=None) -> ImportEntry \| None` | Find import by name |
| `exists_at` | `[NEW]` | `exists_at(ea) -> bool` | Check if import exists |
| `count` | `[NEW]` | `count() -> int` | Total import count |
| `has_imports` | `[POST-FORK]` `[KEEP]` | `has_imports() -> bool` | Check if any imports |

**Methods to REMOVE (all post-fork):**

| Method | Reason |
|--------|--------|
| `get_module_by_name` | Merge into `get_module` |
| `get_module_names` | Iterate `get_all()` |
| `get_entries_by_module` | Use `module.imports` |
| `find_by_name` | Rename to `find` |
| `find_all_by_name` | Use `find` with iteration |
| `filter_entries` | Use Python comprehension |
| `search_by_pattern` | Use Python regex |
| `is_import` | Rename to `exists_at` |
| `get_statistics` | Specialized |

---

### 12. StackFrames

**File:** `ida_domain/stack_frames.py`

This is a **new entity (post-fork)** - all methods can be freely modified.

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `get_at` | `[POST-FORK]` `[KEEP]` | `get_at(func_ea) -> StackFrame \| None` | Get stack frame |
| `create` | `[POST-FORK]` `[KEEP]` | `create(func_ea, local_size, ...) -> bool` | Create frame |
| `delete` | `[POST-FORK]` `[KEEP]` | `delete(func_ea) -> bool` | Delete frame |
| `get_variable` | `[POST-FORK]` `[KEEP]` | `get_variable(func_ea, offset) -> StackVariable \| None` | Get variable |
| `get_variable_by_name` | `[POST-FORK]` `[KEEP]` | `get_variable_by_name(func_ea, name) -> StackVariable \| None` | Get by name |
| `define_variable` | `[POST-FORK]` `[KEEP]` | `define_variable(func_ea, offset, name, ...) -> bool` | Define variable |
| `rename_variable` | `[POST-FORK]` `[KEEP]` | `rename_variable(func_ea, offset, name) -> bool` | Rename variable |
| `delete_variable` | `[POST-FORK]` `[KEEP]` | `delete_variable(func_ea, offset) -> bool` | Delete variable |

**Methods to REMOVE (all post-fork):**

| Method | Reason |
|--------|--------|
| `resize` | Low-level |
| `set_purged_bytes` | Low-level |
| `get_arguments_section` | Use frame properties |
| `get_locals_section` | Use frame properties |
| `get_saved_regs_section` | Use frame properties |
| `set_variable_type` | Low-level |
| `delete_variables_in_range` | Specialized |
| `get_variable_xrefs` | Specialized |
| `get_as_struct` | Specialized |
| `calc_runtime_offset` | Low-level |
| `calc_frame_offset` | Low-level |
| `generate_auto_name` | Specialized |
| `add_sp_change_point` | Low-level |
| `delete_sp_change_point` | Low-level |
| `get_sp_delta` | Low-level |
| `get_sp_change` | Low-level |

---

### 13. Switches

**File:** `ida_domain/switches.py`

This is a **new entity (post-fork)** - all methods can be freely modified.

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `get_at` | `[POST-FORK]` `[KEEP]` | `get_at(ea) -> SwitchInfo \| None` | Get switch info |
| `exists_at` | `[POST-FORK]` `[KEEP]` | `exists_at(ea) -> bool` | Check if switch exists |
| `create` | `[POST-FORK]` `[KEEP]` | `create(ea, switch_info) -> bool` | Create switch |
| `delete` | `[NEW]` | `delete(ea) -> bool` | Delete switch |
| `get_cases` | `[NEW]` | `get_cases(ea) -> List[int]` | Get case values |
| `get_targets` | `[NEW]` | `get_targets(ea) -> List[ea_t]` | Get jump targets |
| `count_cases` | `[NEW]` | `count_cases(ea) -> int` | Case count |

**Methods to REMOVE (all post-fork):**

| Method | Reason |
|--------|--------|
| `remove` | Rename to `delete` |
| `update` | Low-level |
| `get_parent` | Specialized |
| `set_parent` | Specialized |
| `remove_parent` | Specialized |
| `get_jump_table_addresses` | Rename to `get_targets` |
| `get_case_values` | Rename to `get_cases` |
| `get_case_count` | Rename to `count_cases` |

---

### 14. TryBlocks

**File:** `ida_domain/try_blocks.py`

This is a **new entity (post-fork)** - all methods can be freely modified.

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `get_at` | `[POST-FORK]` `[KEEP]` | `get_at(ea) -> TryBlock \| None` | Get try block |
| `get_in_range` | `[POST-FORK]` `[KEEP]` | `get_in_range(start, end) -> Iterator[TryBlock]` | Try blocks in range |
| `is_in_try_block` | `[POST-FORK]` `[KEEP]` | `is_in_try_block(ea) -> bool` | Check if in try block |
| `create` | `[NEW]` | `create(try_block) -> bool` | Add try block |
| `delete` | `[NEW]` | `delete(start, end) -> bool` | Delete in range |

**Methods to REMOVE (all post-fork):**

| Method | Reason |
|--------|--------|
| `add` | Rename to `create` |
| `remove_in_range` | Rename to `delete` |
| `is_catch_start` | Use TryBlock properties |
| `is_seh_handler_start` | Use TryBlock properties |
| `is_seh_filter_start` | Use TryBlock properties |
| `find_seh_region` | Specialized |
| `has_fallthrough_from_unwind` | Specialized |

---

### 15. Problems

**File:** `ida_domain/problems.py`

This is a **new entity (post-fork)** - all methods can be freely modified.

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `get_at` | `[POST-FORK]` `[KEEP]` | `get_at(ea) -> Iterator[Problem]` | Problems at address |
| `get_all` | `[POST-FORK]` `[KEEP]` | `get_all(type=None) -> Iterator[Problem]` | All problems |
| `get_in_range` | `[NEW]` | `get_in_range(start, end, type=None) -> Iterator[Problem]` | Problems in range |
| `create` | `[NEW]` | `create(ea, type) -> bool` | Add problem |
| `delete` | `[NEW]` | `delete(ea, type=None) -> int` | Delete problems |
| `clear` | `[NEW]` | `clear(type=None) -> int` | Clear all |
| `count` | `[POST-FORK]` `[KEEP]` | `count(type=None) -> int` | Count problems |
| `exists_at` | `[NEW]` | `exists_at(ea, type=None) -> bool` | Check if problem exists |

**Methods to REMOVE (all post-fork):**

| Method | Reason |
|--------|--------|
| `get_between` | Rename to `get_in_range` |
| `get_next` | Use iteration |
| `has_problem` | Rename to `exists_at` |
| `was_auto_decision` | Specialized |
| `count_by_type` | Use `count(type)` |
| `add` | Rename to `create` |
| `remove` | Merge into `delete` |
| `remove_at` | Merge into `delete` |
| `clear_all` | Merge into `clear` |

---

### 16. Fixups

**File:** `ida_domain/fixups.py`

This is a **new entity (post-fork)** - all methods can be freely modified.

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `get_at` | `[POST-FORK]` `[KEEP]` | `get_at(ea) -> FixupInfo \| None` | Get fixup |
| `get_all` | `[POST-FORK]` `[KEEP]` | `get_all() -> Iterator[FixupInfo]` | All fixups |
| `get_in_range` | `[NEW]` | `get_in_range(start, end) -> Iterator[FixupInfo]` | Fixups in range |
| `exists_at` | `[NEW]` | `exists_at(ea) -> bool` | Check if exists |
| `create` | `[NEW]` | `create(ea, type, target, ...) -> bool` | Create fixup |
| `delete` | `[NEW]` | `delete(ea) -> bool` | Delete fixup |
| `count` | `[POST-FORK]` `[KEEP]` | `count() -> int` | Total count |

**Methods to REMOVE (all post-fork):**

| Method | Reason |
|--------|--------|
| `get_between` | Rename to `get_in_range` |
| `has_fixup` | Rename to `exists_at` |
| `add` | Rename to `create` |
| `remove` | Rename to `delete` |
| `contains_fixups` | Use `get_in_range` |
| `get_description` | Specialized |
| `patch_value` | Specialized |

---

### 17. Exporter

**File:** `ida_domain/exporter.py`

This is a **new entity (post-fork)** - all methods can be freely modified.

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `export` | `[NEW]` | `export(path, format, start=None, end=None, **options) -> bool` | Export to file |

**`format` values:** `"asm"`, `"lst"`, `"map"`, `"idc"`, `"exe"`, `"diff"`, `"bytes"`

**Methods to REMOVE (all post-fork):**

| Method | Reason |
|--------|--------|
| `generate_map_file` | Use `export(path, "map")` |
| `generate_assembly` | Use `export(path, "asm")` |
| `generate_listing` | Use `export(path, "lst")` |
| `generate_executable` | Use `export(path, "exe")` |
| `generate_idc_script` | Use `export(path, "idc")` |
| `generate_diff` | Use `export(path, "diff")` |
| `export_bytes` | Use `export(path, "bytes", start, end)` |
| `import_bytes` | Specialized |
| `export_range` | Use `export` with start/end |

---

### 18. Decompiler

**File:** `ida_domain/decompiler.py`

This is a **new entity (post-fork)** - all methods can be freely modified.

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `is_available` | `[POST-FORK]` `[KEEP]` | `is_available() -> bool` | Check if decompiler exists |
| `decompile` | `[NEW]` | `decompile(ea) -> List[str] \| None` | Decompile function |

**Methods to REMOVE (all post-fork):**

| Method | Reason |
|--------|--------|
| `decompile_at` | Rename to `decompile` |

---

### 19. Types

**File:** `ida_domain/types.py`

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `load_library` | `[PRE-FORK]` `[KEEP]` | `load_library(path) -> til_t` | Load type library |
| `unload_library` | `[PRE-FORK]` `[KEEP]` | `unload_library(library) -> None` | Unload type library |
| `visit_type` | `[PRE-FORK]` `[KEEP]` | `visit_type(type_info, visitor) -> bool` | Visit type |
| `is_enum` | `[POST-FORK]` `[KEEP]` | `is_enum(type_info) -> bool` | Check if enum |
| `is_struct` | `[POST-FORK]` `[KEEP]` | `is_struct(type_info) -> bool` | Check if struct |
| `is_union` | `[POST-FORK]` `[KEEP]` | `is_union(type_info) -> bool` | Check if union |

**New methods to add:**

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `get` | `[NEW]` | `get(name_or_ordinal) -> tinfo_t \| None` | Get type by name or ordinal |
| `apply` | `[NEW]` | `apply(ea, type_or_name) -> bool` | Apply type to address |
| `guess` | `[NEW]` | `guess(ea) -> tinfo_t \| None` | Guess type at address |
| `format` | `[NEW]` | `format(type_info) -> str` | Format type as string |

**Methods to REMOVE (post-fork only):**

| Method | Status | Reason |
|--------|--------|--------|
| `get_by_ordinal` | `[POST-FORK]` `[REMOVE]` | Merge into `get` |
| `get_ordinal` | `[POST-FORK]` `[REMOVE]` | Specialized |
| `apply_by_name` | `[POST-FORK]` `[REMOVE]` | Merge into `apply` |
| `apply_declaration` | `[POST-FORK]` `[REMOVE]` | Merge into `apply` |
| `guess_at` | `[POST-FORK]` `[REMOVE]` | Rename to `guess` |
| `format_type` | `[POST-FORK]` `[REMOVE]` | Rename to `format` |
| `format_type_at` | `[POST-FORK]` `[REMOVE]` | Use `format(guess(ea))` |
| `compare_types` | `[POST-FORK]` `[REMOVE]` | Use Python `==` |
| `validate_type` | `[POST-FORK]` `[REMOVE]` | Specialized |
| `resolve_typedef` | `[POST-FORK]` `[REMOVE]` | Specialized |
| `remove_pointer` | `[POST-FORK]` `[REMOVE]` | Specialized |
| `is_udt` | `[POST-FORK]` `[REMOVE]` | Use `is_struct or is_union` |

---

## Summary Statistics

| Category | Count |
|----------|-------|
| Pre-fork methods kept | ~100 |
| Pre-fork methods with new aliases | ~20 |
| Post-fork methods to remove | ~120 |
| Post-fork methods to keep | ~40 |
| New methods to add | ~50 |

**Final API surface: ~170 methods** (down from ~350+)

---

## Compatibility Notes

### Deprecated Aliases (Pre-fork renames)

When adding LLM-friendly aliases for pre-fork methods, the old method MUST remain and be marked deprecated:

```python
def get_in_range(self, start: ea_t, end: ea_t) -> Iterator[func_t]:
    """Get functions in range (LLM-friendly alias for get_between)."""
    return self.get_between(start, end)

@deprecated("Use get_in_range instead")
def get_between(self, start: ea_t, end: ea_t) -> Iterator[func_t]:
    """Get functions between start and end addresses.

    .. deprecated::
        Use :meth:`get_in_range` instead.
    """
    # Original implementation
    ...
```

### Pre-fork Methods That Get Aliases

| Entity | Original Method | New Alias |
|--------|-----------------|-----------|
| Functions | `get_between` | `get_in_range` |
| Functions | `remove` | `delete` |
| Bytes | `find_bytes_between` | `find_bytes` |
| Bytes | `find_text_between` | `find_text` |
| Names | `get_count` | `count` |
| Names | `is_valid_name` | `is_valid` |
| Names | `is_public_name` | `is_public` |
| Names | `is_weak_name` | `is_weak` |
| Xrefs | `to_ea` | `get_refs_to` |
| Xrefs | `from_ea` | `get_refs_from` |
| Instructions | `get_between` | `get_in_range` |
| Instructions | `is_call_instruction` | `is_call` |
| Segments | `add` | `create` |
| Comments | `set_at` | `set` |
| Comments | `delete_at` | `delete` |

---

## Example LLM Usage

After refactoring, typical LLM interactions become simple and predictable:

```python
db = Database.open_current()

# Find all functions
for func in db.functions.get_all():
    print(db.functions.get_name(func))

# Search for undefined bytes
for ea in db.search.find_all(0x401000, 0x410000, "undefined"):
    print(hex(ea))

# Get cross-references to an address
for xref in db.xrefs.get_refs_to(0x401000):
    print(f"{hex(xref.from_ea)} -> {hex(xref.to_ea)}")

# Wait for analysis
db.analysis.wait()

# Export to assembly
db.exporter.export("/tmp/output.asm", "asm")

# Decompile a function
lines = db.decompiler.decompile(0x401000)
```

**No imports beyond `Database`. Predictable method names. String literals instead of enums.**
