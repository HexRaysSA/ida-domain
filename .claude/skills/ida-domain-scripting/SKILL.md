---
name: ida-domain-scripting
description: Write Python scripts using ida-domain, a clean Python API for IDA Pro binary analysis. Use when writing IDA Pro automation scripts, analyzing binaries, working with disassembly, decompilation, cross-references, functions, or any IDA database operations.
---

# IDA Domain Scripting

**Auto-generated documentation** - regenerate with `generate_skill_docs.py`

## Core Pattern

```python
from ida_domain import Database

with Database.open("path/to/binary_or_idb") as db:
    for func in db.functions:
        print(func.name, hex(func.start_ea))
```

## All Handlers

Access via `db.<handler>`:

| Handler | Purpose |
|---------|---------|
| `analysis` | Provides access to auto-analysis control and queue management |
| `callgraph` | Inter-procedural call graph traversal |
| `comments` | Provides access to user-defined comments in the IDA database |
| `decompiler` | Provides access to Hex-Rays decompiler functionality |
| `entries` | Provides access to entries in the IDA database |
| `exporter` | Provides file export operations for IDA databases |
| `fixups` | Manages fixup (relocation) information in the IDA database |
| `flowchart` | Provides access to basic block properties and navigation
    between connected blocks within a control flow graph |
| `functions` | Provides access to function-related operations within the IDA database |
| `heads` | Provides access to heads (instructions or data items) in the IDA database |
| `hooks` | Handler |
| `imports` | Provides access to import table operations in the IDA database |
| `instructions` | Provides access to instruction-related operations using structured operand hierarchy |
| `names` | Provides access to symbol and label management in the IDA database |
| `problems` | Provides access to IDA's problem list operations |
| `search` | Provides search operations for finding addresses by various criteria |
| `segments` | Provides access to segment-related operations in the IDA database |
| `signature_files` | Provides access to FLIRT signature ( |
| `stack_frames` | Provides access to stack frame operations within the IDA database |
| `strings` | Provides access to string-related operations in the IDA database |
| `switches` | Provides comprehensive access to switch statement analysis and manipulation |
| `try_blocks` | Provides access to exception handling try/catch blocks |
| `types` | Provides access to type information and manipulation in the IDA database |
| `xrefs` | Provides unified access to cross-reference (xref) analysis in the IDA database |

## API Conventions

- `get_*` methods return `Optional[T]` - returns `None` if not found
- `get_at(ea)` - get item at/containing address
- `get_by_name(name)` - find item by name
- `get_in_range(start, end)` - iterate items in range
- Most handlers support iteration: `for item in db.handler`

## References

- **Handler methods**: [references/api-handlers.md](references/api-handlers.md)
- **Enum values**: [references/enums-types.md](references/enums-types.md)
- **Usage patterns**: [references/patterns.md](references/patterns.md)
