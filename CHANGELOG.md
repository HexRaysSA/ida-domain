# Changelog

All notable changes to this project are documented in this file.

## [Unreleased] - Fork Enhancements

This section documents all changes made after forking from the upstream `ida-domain` repository (fork point: v0.3.6-dev.2, commit `080aa8f`, December 8, 2025).

### Summary

| Metric | Value |
|--------|-------|
| Total commits | 47 |
| Lines added | +24,750 |
| Lines removed | -164 |
| New entity modules | 10 |
| New methods | 150+ |
| New test files | 16 |
| mypy strict errors fixed | 218 → 0 |

---

## New Entities

### Analysis

`ida_domain/analysis.py` - Complete auto-analysis control and management.

| Method | Description |
|--------|-------------|
| `is_enabled()` | Check if auto-analysis is enabled |
| `is_complete()` | Check if analysis has completed |
| `current_state()` | Get current analysis state |
| `wait_for_completion()` | Wait for analysis to finish |
| `analyze_range(start, end, wait)` | Analyze a specific range |
| `set_enabled(enabled)` | Enable/disable auto-analysis |
| `schedule_code_analysis(ea)` | Queue address for code analysis |
| `schedule_function_analysis(ea)` | Queue address for function analysis |
| `schedule_range_analysis(start, end, queue_type)` | Queue range for analysis |
| `wait_for_range(start, end)` | Wait for range analysis |
| `analyze_range_until_stable(start, end)` | Analyze until no changes |
| `schedule_reanalysis(ea)` | Schedule reanalysis of address |
| `cancel_analysis(start, end)` | Cancel pending analysis |
| `cancel_queue(queue_type)` | Cancel entire queue |
| `auto_wait()` | Legacy: wait for auto-analysis |
| `plan_and_wait(start, end)` | Legacy: plan range and wait |
| `auto_is_ok()` | Legacy: check if auto-analysis is OK |
| `get_auto_state()` | Legacy: get auto-analysis state |
| `plan_ea(ea)` | Legacy: plan single address |
| `plan_range(start, end)` | Legacy: plan range |
| `get_auto_display()` | Legacy: get auto display info |
| `enable_auto(enable)` | Legacy: enable auto-analysis |
| `disable_auto()` | Legacy: disable auto-analysis |
| `show_auto(ea, queue_type)` | Legacy: show auto-analysis address |
| `noshow_auto()` | Legacy: hide auto-analysis display |
| `analysis_active()` | Legacy: check if analysis is active |
| `show_addr(ea)` | Show address in auto-analysis |
| `reanalyze_function_callers(func_ea, ...)` | Reanalyze function callers |
| `recreate_instruction(ea)` | Recreate instruction at address |
| `revert_analysis(start, end)` | Revert analysis in range |

---

### Imports

`ida_domain/imports.py` - Import table enumeration and module operations.

**ImportEntry Properties:**

| Property | Description |
|----------|-------------|
| `is_ordinal_import()` | Check if import is by ordinal |
| `is_named_import()` | Check if import is by name |
| `full_name()` | Get full import name with module |

**ImportModule Properties:**

| Property | Description |
|----------|-------------|
| `imports()` | Iterate over module's imports |

**Imports Methods:**

| Method | Description |
|--------|-------------|
| `get_all()` | Get all import modules |
| `get_module(index)` | Get module by index |
| `get_module_by_name(name)` | Get module by name |
| `get_module_names()` | Get list of module names |
| `get_entries_by_module(module_name)` | Get entries for module |
| `get_all_entries()` | Get all import entries |
| `get_at(ea)` | Get import at address |
| `find_by_name(name, module_name)` | Find import by name |
| `find_all_by_name(name, module_name)` | Find all matching imports |
| `filter_entries(predicate, module_name)` | Filter imports |
| `search_by_pattern(pattern, module_name)` | Regex search imports |
| `has_imports()` | Check if database has imports |
| `is_import(ea)` | Check if address is an import |
| `get_statistics()` | Get import statistics |

---

### Search

`ida_domain/search.py` - 17 search methods for finding patterns in the database.

| Method | Description |
|--------|-------------|
| `next_undefined(ea, ...)` | Find next undefined byte |
| `next_defined(ea, ...)` | Find next defined item |
| `all_undefined(start, end)` | Iterate all undefined bytes |
| `all_defined(start, end)` | Iterate all defined items |
| `next_code(ea, ...)` | Find next code address |
| `next_data(ea, ...)` | Find next data address |
| `next_code_outside_function(ea, ...)` | Find orphan code |
| `all_code(start, end)` | Iterate all code addresses |
| `all_data(start, end)` | Iterate all data addresses |
| `all_code_outside_functions(start, end)` | Iterate orphan code |
| `next_error(ea, ...)` | Find next analysis error |
| `next_untyped_operand(ea, ...)` | Find untyped operand |
| `next_suspicious_operand(ea, ...)` | Find suspicious operand |
| `all_errors(start, end)` | Iterate all errors |
| `all_untyped_operands(start, end)` | Iterate untyped operands |
| `next_register_access(ea, ...)` | Find register access |
| `all_register_accesses(start, end, ...)` | Iterate register accesses |

---

### StackFrames

`ida_domain/stack_frames.py` - Comprehensive stack frame and variable operations.

**StackFrameInstance Properties:**

| Property | Description |
|----------|-------------|
| `size()` | Total frame size |
| `local_size()` | Size of local variables |
| `argument_size()` | Size of arguments |
| `saved_registers_size()` | Size of saved registers |
| `return_address_size()` | Size of return address |
| `purged_bytes()` | Bytes purged by function |
| `frame_pointer_delta()` | Frame pointer delta |
| `variables()` | Iterate all variables |
| `arguments()` | Iterate argument variables |
| `locals()` | Iterate local variables |
| `stack_points()` | Iterate stack pointer changes |

**StackFrames Methods:**

| Method | Description |
|--------|-------------|
| `get_at(func_ea)` | Get stack frame for function |
| `create(func_ea, local_size, saved_regs_size, arg_size)` | Create frame |
| `delete(func_ea)` | Delete stack frame |
| `resize(func_ea, local_size, saved_regs_size, arg_size)` | Resize frame |
| `set_purged_bytes(func_ea, nbytes, override)` | Set purged bytes |
| `get_arguments_section(func_ea)` | Get arguments section info |
| `get_locals_section(func_ea)` | Get locals section info |
| `get_saved_regs_section(func_ea)` | Get saved regs section info |
| `define_variable(func_ea, offset, name, var_type, size)` | Define variable |
| `get_variable(func_ea, offset)` | Get variable at offset |
| `get_variable_by_name(func_ea, name)` | Get variable by name |
| `set_variable_type(func_ea, offset, var_type)` | Set variable type |
| `rename_variable(func_ea, offset, new_name)` | Rename variable |
| `delete_variable(func_ea, offset)` | Delete variable |
| `delete_variables_in_range(func_ea, start_offset, end_offset)` | Delete range |
| `get_variable_xrefs(func_ea, offset)` | Get variable cross-references |
| `get_as_struct(func_ea)` | Get frame as structure type |
| `calc_runtime_offset(func_ea, frame_offset, insn_ea)` | Calculate runtime offset |
| `calc_frame_offset(func_ea, runtime_offset, insn_ea)` | Calculate frame offset |
| `generate_auto_name(func_ea, offset)` | Generate automatic name |
| `add_sp_change_point(func_ea, ea, delta)` | Add SP change point |
| `delete_sp_change_point(func_ea, ea)` | Delete SP change point |
| `get_sp_delta(func_ea, ea)` | Get SP delta at address |
| `get_sp_change(func_ea, ea)` | Get SP change at address |

---

### Switches

`ida_domain/switches.py` - Switch statement analysis and manipulation.

**SwitchInfo Properties:**

| Property | Description |
|----------|-------------|
| `is_sparse()` | Check if switch is sparse |
| `is_indirect()` | Check if switch uses indirect table |
| `has_default()` | Check if switch has default case |
| `jtable_element_size()` | Jump table element size |
| `vtable_element_size()` | Value table element size |
| `shift()` | Shift value for case calculation |

**Switches Methods:**

| Method | Description |
|--------|-------------|
| `get_at(ea)` | Get switch info at address |
| `exists_at(ea)` | Check if switch exists at address |
| `create(ea, switch_info)` | Create switch at address |
| `remove(ea)` | Remove switch |
| `update(ea, switch_info)` | Update switch info |
| `get_parent(ea)` | Get parent switch address |
| `set_parent(ea, parent_ea)` | Set parent switch |
| `remove_parent(ea)` | Remove parent association |
| `get_jump_table_addresses(switch_info)` | Get jump table addresses |
| `get_case_values(switch_info)` | Get case values |
| `get_case_count(ea)` | Get number of cases |

---

### TryBlocks

`ida_domain/try_blocks.py` - Exception handling block analysis.

**CatchHandler Properties:**

| Property | Description |
|----------|-------------|
| `is_catch_all()` | Check if catch-all handler |
| `is_cleanup()` | Check if cleanup handler |
| `start_ea()` | Handler start address |
| `end_ea()` | Handler end address |

**SehHandler Properties:**

| Property | Description |
|----------|-------------|
| `has_filter()` | Check if has filter |
| `is_finally()` | Check if finally handler |
| `start_ea()` | Handler start address |
| `end_ea()` | Handler end address |
| `filter_start_ea()` | Filter start address |

**TryBlock Properties:**

| Property | Description |
|----------|-------------|
| `is_cpp()` | Check if C++ try block |
| `is_seh()` | Check if SEH try block |
| `start_ea()` | Try block start address |
| `end_ea()` | Try block end address |
| `is_empty()` | Check if block is empty |

**TryBlocks Methods:**

| Method | Description |
|--------|-------------|
| `get_in_range(start_ea, end_ea)` | Get try blocks in range |
| `get_at(ea)` | Get try block at address |
| `is_in_try_block(ea, kind)` | Check if in try block |
| `is_catch_start(ea)` | Check if catch handler start |
| `is_seh_handler_start(ea)` | Check if SEH handler start |
| `is_seh_filter_start(ea)` | Check if SEH filter start |
| `find_seh_region(ea)` | Find containing SEH region |
| `has_fallthrough_from_unwind(ea)` | Check for unwind fallthrough |
| `add(try_block)` | Add try block |
| `remove_in_range(start_ea, end_ea)` | Remove try blocks in range |

---

### Exporter

`ida_domain/exporter.py` - File export operations.

| Method | Description |
|--------|-------------|
| `generate_map_file(output_path, ...)` | Generate MAP file |
| `generate_assembly(output_path, ...)` | Generate assembly file |
| `generate_listing(output_path, ...)` | Generate listing file |
| `generate_executable(output_path)` | Generate executable |
| `generate_idc_script(output_path, ...)` | Generate IDC script |
| `generate_diff(output_path, ...)` | Generate diff file |
| `export_bytes(output_path, start, end, ...)` | Export raw bytes |
| `import_bytes(input_path, start, ...)` | Import bytes from file |
| `export_range(output_path, start, end, format)` | Export range |

---

### Problems

`ida_domain/problems.py` - Problem list management.

**Problem Properties:**

| Property | Description |
|----------|-------------|
| `type_name()` | Get problem type name |

**Problems Methods:**

| Method | Description |
|--------|-------------|
| `count()` | Get total problem count |
| `get_all(problem_type)` | Get all problems |
| `get_between(start, end, problem_type)` | Get problems in range |
| `get_at(ea)` | Get problems at address |
| `get_next(ea, problem_type)` | Get next problem |
| `has_problem(ea, problem_type)` | Check if problem exists |
| `was_auto_decision(ea)` | Check if auto-decided |
| `count_by_type(problem_type)` | Count by type |
| `add(ea, problem_type)` | Add problem |
| `remove(ea, problem_type)` | Remove specific problem |
| `remove_at(ea)` | Remove all problems at address |
| `clear(problem_type)` | Clear all of type |
| `clear_all()` | Clear all problems |

---

### Fixups

`ida_domain/fixups.py` - Relocation and fixup operations.

**FixupInfo Properties:**

| Property | Description |
|----------|-------------|
| `target()` | Get fixup target address |

**Fixups Methods:**

| Method | Description |
|--------|-------------|
| `count()` | Get total fixup count |
| `get_at(address)` | Get fixup at address |
| `has_fixup(address)` | Check if fixup exists |
| `get_all()` | Iterate all fixups |
| `get_between(start, end)` | Get fixups in range |
| `contains_fixups(start, size)` | Check if range has fixups |
| `get_description(address)` | Get fixup description |
| `add(address, fixup_type, flags, target, ...)` | Add fixup |
| `remove(address)` | Remove fixup |
| `patch_value(address)` | Patch fixup value |

---

### Decompiler

`ida_domain/decompiler.py` - Basic decompilation support.

| Method | Description |
|--------|-------------|
| `is_available()` | Check if decompiler is available |
| `decompile_at(address, remove_tags)` | Decompile function at address |

---

## Enhanced Entities

### Bytes

`ida_domain/bytes.py`

| Method | Description |
|--------|-------------|
| `get_item_head_at(ea)` | Get item head address |
| `get_item_end_at(ea)` | Get item end address |
| `get_item_size_at(ea)` | Get item size |
| `set_operand_hex(ea, n)` | Set operand to hex format |
| `set_operand_decimal(ea, n)` | Set operand to decimal format |
| `set_operand_octal(ea, n)` | Set operand to octal format |
| `set_operand_binary(ea, n)` | Set operand to binary format |
| `set_operand_char(ea, n)` | Set operand to char format |
| `set_operand_enum(ea, n, enum_id, serial)` | Set operand to enum |
| `is_offset_operand(ea, n)` | Check if operand is offset |
| `is_char_operand(ea, n)` | Check if operand is char |
| `is_enum_operand(ea, n)` | Check if operand is enum |
| `is_struct_offset_operand(ea, n)` | Check if operand is struct offset |
| `is_stack_var_operand(ea, n)` | Check if operand is stack variable |

---

### Instructions

`ida_domain/instructions.py`

| Method | Description |
|--------|-------------|
| `decode_at(ea, out)` | Decode instruction into buffer |
| `get_preceding(ea)` | Get preceding instruction |
| `get_next(ea)` | Get next instruction |
| `create_at(ea)` | Create instruction at address |
| `can_decode(ea)` | Check if can decode at address |
| `get_size(ea)` | Get instruction size |
| `format_operand(ea, operand_index, flags)` | Format operand text |
| `add_code_reference(from_ea, to_ea, flow_type)` | Add code xref |
| `add_data_reference(from_ea, to_ea, dr_type)` | Add data xref |
| `get_data_type_size(dtype)` | Get data type size |
| `get_data_type_by_size(size)` | Get data type for size |
| `get_data_type_flag(dtype)` | Get data type flag |
| `is_floating_data_type(dtype)` | Check if floating type |
| `map_operand_address(ea, operand_index, address)` | Map operand address |
| `calculate_data_segment(ea, operand_index)` | Calculate data segment |
| `set_operand_offset(ea, operand_index, base)` | Set operand offset |
| `set_operand_offset_ex(ea, operand_index, refinfo)` | Set offset extended |
| `get_operand_offset_base(ea, operand_index)` | Get offset base |
| `get_operand_offset_target(ea, operand_index)` | Get offset target |
| `format_offset_expression(ea, operand_index, ...)` | Format offset expression |
| `calculate_offset_base(ea, operand_index)` | Calculate offset base |

---

### Types

`ida_domain/types.py`

| Method | Description |
|--------|-------------|
| `get_by_ordinal(ordinal, library)` | Get type by ordinal |
| `get_ordinal(name, library)` | Get ordinal by name |
| `apply_by_name(ea, name, flags)` | Apply type by name |
| `apply_declaration(ea, decl, flags)` | Apply type declaration |
| `guess_at(ea)` | Guess type at address |
| `format_type(type_info, ...)` | Format type as string |
| `format_type_at(ea, ...)` | Format type at address |
| `compare_types(type1, type2)` | Compare two types |
| `validate_type(type_info)` | Validate type |
| `resolve_typedef(type_info)` | Resolve typedef chain |
| `remove_pointer(type_info)` | Remove pointer from type |
| `is_enum(type_info)` | Check if type is enum |
| `is_struct(type_info)` | Check if type is struct |
| `is_union(type_info)` | Check if type is union |
| `is_udt(type_info)` | Check if type is UDT |

---

### Segments

`ida_domain/segments.py`

| Method | Description |
|--------|-------------|
| `get_by_index(index)` | Get segment by index |
| `get_index(segment)` | Get segment index |
| `get_first()` | Get first segment |
| `get_last()` | Get last segment |
| `get_next(segment)` | Get next segment |
| `get_previous(segment)` | Get previous segment |
| `get_type(segment)` | Get segment type |
| `get_paragraph(segment)` | Get segment paragraph |
| `get_base(segment)` | Get segment base |
| `set_class(segment, sclass)` | Set segment class |
| `set_start(segment, new_start, keep_data)` | Set segment start |
| `set_end(segment, new_end, keep_data)` | Set segment end |
| `delete(segment, keep_data)` | Delete segment |
| `update(segment)` | Update segment in database |
| `move(segment, new_start, flags)` | Move segment |
| `rebase(delta, fix_once)` | Rebase all segments |
| `set_visible(segment, visible)` | Set segment visibility |
| `is_visible(segment)` | Check segment visibility |

---

### Names

`ida_domain/names.py`

| Method | Description |
|--------|-------------|
| `resolve_name(name, from_ea)` | Resolve name to address |
| `resolve_value(expression, from_ea)` | Resolve expression value |
| `delete_local(ea)` | Delete local name |
| `create_dummy(from_ea, ea)` | Create dummy name |
| `get_visible_name(ea, local)` | Get visible name |
| `validate(name, strict)` | Validate name |
| `get_colored_name(ea, local)` | Get colored name |
| `format_expression(ea, ...)` | Format name expression |

---

### Functions

`ida_domain/functions.py`

| Method | Description |
|--------|-------------|
| `get_previous(ea)` | Get previous function |
| `get_index(func)` | Get function index |
| `contains(func, ea)` | Check if function contains address |
| `set_start(func, new_start)` | Set function start |
| `set_end(func, new_end)` | Set function end |
| `update(func)` | Update function in database |
| `reanalyze(func)` | Reanalyze function |
| `add_tail(func, tail_start, tail_end)` | Add function tail chunk |
| `remove_tail(func, tail_ea)` | Remove function tail chunk |

---

### Comments

`ida_domain/comments.py`

| Method | Description |
|--------|-------------|
| `delete_all_extra_at(ea, kind)` | Delete all extra comments |
| `get_first_free_extra_index(ea, kind)` | Get free extra index |
| `generate_disasm_line(ea, remove_tags)` | Generate disassembly line |
| `generate_disassembly(start, end, ...)` | Generate disassembly range |
| `strip_color_tags(text)` | Strip color tags from text |
| `calculate_visual_length(text)` | Calculate visual length |
| `skip_color_tags(text, start_offset)` | Skip color tags |
| `advance_in_colored_string(text, n)` | Advance in colored string |
| `colorize(text, color_code)` | Add color to text |
| `requires_color_escape(char)` | Check if char needs escape |
| `get_prefix_color(ea)` | Get address prefix color |
| `get_background_color(ea)` | Get address background color |
| `add_sourcefile(start_ea, end_ea, filename)` | Add source file info |
| `get_sourcefile(ea)` | Get source file info |
| `delete_sourcefile(ea)` | Delete source file info |

---

### Xrefs

`ida_domain/xrefs.py`

| Method | Description |
|--------|-------------|
| `has_any_refs_to(ea)` | Check if any refs to address |
| `has_any_refs_from(ea)` | Check if any refs from address |
| `has_code_refs_to(ea)` | Check if code refs to address |
| `has_data_refs_to(ea)` | Check if data refs to address |
| `count_refs_to(ea, flags)` | Count references to address |
| `count_refs_from(ea, flags)` | Count references from address |

---

### Database

`ida_domain/database.py`

**New Methods:**

| Method | Description |
|--------|-------------|
| `save_as(new_path, flags)` | Save database to new path |

**New Entity Accessors:**

| Accessor | Description |
|----------|-------------|
| `analysis` | Access Analysis entity |
| `decompiler` | Access Decompiler entity |
| `fixups` | Access Fixups entity |
| `imports` | Access Imports entity |
| `search` | Access Search entity |
| `stack_frames` | Access StackFrames entity |
| `switches` | Access Switches entity |
| `problems` | Access Problems entity |
| `exporter` | Access Exporter entity |
| `try_blocks` | Access TryBlocks entity |

---

## Code Quality

### Fixed

- All 218 mypy --strict errors resolved
- Ruff linting compliance (line length fixes)
- Various typos and bugs fixed during development

---

## Pre-Fork History (Upstream)

For reference, the upstream repository history before the fork:

| Version | Date | Description |
|---------|------|-------------|
| 0.3.6-dev.2 | Dec 8, 2025 | LocalVariableAccessType bugfix |
| 0.3.5 | Nov 4, 2025 | Python badge fix |
| 0.3.4 | Nov 3, 2025 | Documentation improvements |
| 0.3.3 | Oct 14, 2025 | Various fixes |
| 0.3.2 | Oct 8, 2025 | String decoding fix |
| 0.3.1 | Oct 6, 2025 | String type retrieval fix |
| 0.3.0 | Sep 26, 2025 | Local variable references |
| 0.2.2 | Sep 23, 2025 | Microcode format fix |
| 0.2.1 | Sep 18, 2025 | Multi-block function fix |
| 0.2.0 | Sep 5, 2025 | API enhancements |
| 0.1.0 | Aug 15, 2025 | First release |
| 0.0.1 | Aug 15, 2025 | Initial import |
