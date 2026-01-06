---
name: ida-domain-scripting
description: Write Python scripts using the ida-domain API for IDA Pro binary analysis. Use when asked to create scripts for reverse engineering tasks like analyzing functions, cross-references, strings, bytes, types, call graphs, local variables, switches, or any IDA database operations. Triggers on requests involving IDA Pro scripting, binary analysis automation, disassembly, decompilation, or ida-domain library usage.
---

# IDA Domain Scripting

Write Python scripts using ida-domain, a clean Python API for IDA Pro binary analysis.

## Core Pattern

```python
from ida_domain import Database

with Database.open("path/to/binary_or_idb") as db:
    for func in db.functions:
        print(func.name, hex(func.start_ea))
```

## API Conventions

**Return patterns** (critical for error handling):
- `get_*` methods return `Optional[T]` - returns `None` if not found, never raises
- `create_*` methods return `bool` - `True` on success, `False` on failure
- `has_*/is_*` methods return `bool`
- `count_*` methods return `int` (0 if none)
- Most handlers support iteration: `for item in db.handler`

## All Handlers

Access via `db.<handler>`:

| Handler | Purpose |
|---------|---------|
| `functions` | Function analysis, pseudocode, callers/callees, local variables |
| `instructions` | Instruction decoding, operands, mnemonics |
| `xrefs` | Cross-references (code/data, calls, jumps, reads, writes) |
| `callgraph` | Multi-hop call graph traversal |
| `decompiler` | Hex-Rays decompiler access |
| `bytes` | Raw byte operations (get/set/patch) |
| `strings` | String discovery and iteration |
| `names` | Symbol naming operations |
| `comments` | Code comments (regular/repeatable) |
| `types` | Type information and TIL management |
| `segments` | Memory segment operations |
| `entries` | Entry point operations |
| `imports` | Import table access |
| `stack_frames` | Stack frame and variable analysis |
| `search` | Pattern-based address searching |
| `switches` | Switch statement analysis |
| `try_blocks` | Exception handling blocks |
| `fixups` | Relocation/fixup information |
| `problems` | Problem list operations |
| `exporter` | Export data to various formats |
| `signature_files` | FLIRT signature operations |
| `analysis` | Control auto-analysis |
| `heads` | Head iteration (instruction/data starts) |
| `hooks` | Event hook management |

## Key Enums

Import from `ida_domain.<module>`:

```python
from ida_domain.xrefs import XrefType, XrefKind
from ida_domain.operands import OperandType, OperandDataType
from ida_domain.functions import FunctionFlags, LocalVariableAccessType, LocalVariableContext
from ida_domain.search import SearchDirection, SearchTarget
```

For enum values and meanings, see [references/enums-types.md](references/enums-types.md).

## Common Patterns

### Iterate functions with pseudocode
```python
for func in db.functions:
    name = db.functions.get_name(func)
    for line in db.functions.get_pseudocode(func):
        print(line)
```

### Analyze cross-references
```python
for xref in db.xrefs.to_ea(target_addr):
    print(f"{hex(xref.from_ea)} -> {hex(xref.to_ea)} ({xref.type.name})")
```

### Multi-hop call graph
```python
# Find all functions that can reach dangerous_func (up to 5 hops)
for caller_ea in db.callgraph.callers_of(dangerous_func_ea, max_depth=5):
    print(f"Caller: {hex(caller_ea)}")
```

### Search for patterns
```python
from ida_domain.search import SearchTarget, SearchDirection
ea = db.search.find_next(start_ea, SearchTarget.CODE, SearchDirection.DOWN)
```

### Local variable analysis
```python
lvars = db.functions.get_local_variables(func)
for lvar in lvars:
    refs = db.functions.get_local_variable_references(func, lvar)
    for ref in refs:
        print(f"{lvar.name}: {ref.access_type.name} at line {ref.line_number}")
```

## Key Points

1. **Single import**: `from ida_domain import Database`
2. **Context manager**: Always use `with Database.open(...) as db:`
3. **Iteration**: Most handlers support `for item in db.handler`
4. **Address format**: Use hex addresses (e.g., `0x401000`)
5. **IDA requirement**: Requires IDA Pro 9.1+

## References

- **Handler methods**: [references/api-handlers.md](references/api-handlers.md)
- **Enum values**: [references/enums-types.md](references/enums-types.md)
- **Usage patterns**: [references/patterns.md](references/patterns.md)
- **Full docs**: https://ida-domain.docs.hex-rays.com/
