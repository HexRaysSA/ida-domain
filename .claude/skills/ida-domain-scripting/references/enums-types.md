# IDA Domain Enums and Types Reference

Complete reference for enum values used in ida-domain scripts.

## Table of Contents

1. [XrefType](#xreftype)
2. [XrefKind](#xrefkind)
3. [OperandType](#operandtype)
4. [OperandDataType](#operanddatatype)
5. [FunctionFlags](#functionflags)
6. [LocalVariableAccessType](#localvariableaccesstype)
7. [LocalVariableContext](#localvariablecontext)
8. [SearchDirection](#searchdirection)
9. [SearchTarget](#searchtarget)

---

## XrefType

Cross-reference types for code and data references.

```python
from ida_domain.xrefs import XrefType
```

### Code References

| Value | Description |
|-------|-------------|
| `XrefType.CALL_NEAR` | Near call (creates function at target) |
| `XrefType.CALL_FAR` | Far call (creates function at target) |
| `XrefType.JUMP_NEAR` | Near jump |
| `XrefType.JUMP_FAR` | Far jump |
| `XrefType.ORDINARY_FLOW` | Ordinary flow to next instruction |
| `XrefType.USER_SPECIFIED` | User-specified reference (obsolete) |

### Data References

| Value | Description |
|-------|-------------|
| `XrefType.READ` | Read access |
| `XrefType.WRITE` | Write access |
| `XrefType.OFFSET` | Offset reference (OFFSET flag set) |
| `XrefType.TEXT` | Text reference (forced operands only) |
| `XrefType.INFORMATIONAL` | Informational reference |
| `XrefType.SYMBOLIC` | Reference to enum member (symbolic constant) |
| `XrefType.UNKNOWN` | Unknown type |

### Helper Methods

```python
xref_type.is_code_ref()  # True if code reference
xref_type.is_data_ref()  # True if data reference
```

### XrefInfo Properties

```python
xref.is_call    # True if CALL_NEAR or CALL_FAR
xref.is_jump    # True if JUMP_NEAR or JUMP_FAR
xref.is_read    # True if READ
xref.is_write   # True if WRITE
xref.is_flow    # True if ORDINARY_FLOW
```

---

## XrefKind

Filter kind for cross-reference queries.

```python
from ida_domain.xrefs import XrefKind
```

| Value | Description |
|-------|-------------|
| `XrefKind.ALL` | All cross-references |
| `XrefKind.CODE` | Code cross-references only |
| `XrefKind.DATA` | Data cross-references only |
| `XrefKind.CALLS` | Call cross-references only |
| `XrefKind.JUMPS` | Jump cross-references only |
| `XrefKind.READS` | Read cross-references only |
| `XrefKind.WRITES` | Write cross-references only |

### Usage

```python
# Using XrefKind enum
for xref in db.xrefs.get_refs_to(ea, XrefKind.CALLS):
    print(f"Called from {hex(xref)}")

# String values also work
for xref in db.xrefs.get_refs_to(ea, "calls"):
    print(f"Called from {hex(xref)}")
```

---

## OperandType

Instruction operand types.

```python
from ida_domain.operands import OperandType
```

| Value | Description |
|-------|-------------|
| `OperandType.VOID` | No operand |
| `OperandType.REGISTER` | Processor register (e.g., `eax`, `rdi`) |
| `OperandType.MEMORY` | Direct memory reference (e.g., `[0x401000]`) |
| `OperandType.PHRASE` | Register-based phrase (e.g., `[ebx+ecx]`) |
| `OperandType.DISPLACEMENT` | Register + displacement (e.g., `[ebp-0x10]`) |
| `OperandType.IMMEDIATE` | Immediate value (e.g., `0x42`) |
| `OperandType.FAR_ADDRESS` | Far address (segment:offset) |
| `OperandType.NEAR_ADDRESS` | Near address |
| `OperandType.PROCESSOR_SPECIFIC_0` | Processor-specific type 0 |
| `OperandType.PROCESSOR_SPECIFIC_1` | Processor-specific type 1 |
| `OperandType.PROCESSOR_SPECIFIC_2` | Processor-specific type 2 |
| `OperandType.PROCESSOR_SPECIFIC_3` | Processor-specific type 3 |
| `OperandType.PROCESSOR_SPECIFIC_4` | Processor-specific type 4 |
| `OperandType.PROCESSOR_SPECIFIC_5` | Processor-specific type 5 |

### Usage

```python
operands = db.instructions.get_operands(insn)
for op in operands:
    if op.type == OperandType.REGISTER:
        print(f"Register: {op.get_register_name()}")
    elif op.type == OperandType.IMMEDIATE:
        print(f"Immediate: {hex(op.get_value())}")
    elif op.type == OperandType.MEMORY:
        print(f"Memory: {hex(op.get_address())}")
```

---

## OperandDataType

Operand data size types.

```python
from ida_domain.operands import OperandDataType
```

| Value | Size | Description |
|-------|------|-------------|
| `OperandDataType.BYTE` | 1 | Byte (8-bit) |
| `OperandDataType.WORD` | 2 | Word (16-bit) |
| `OperandDataType.DWORD` | 4 | Double word (32-bit) |
| `OperandDataType.QWORD` | 8 | Quad word (64-bit) |
| `OperandDataType.FLOAT` | 4 | Single-precision float |
| `OperandDataType.DOUBLE` | 8 | Double-precision float |
| `OperandDataType.TBYTE` | 10 | Extended precision (80-bit) |
| `OperandDataType.PACKREAL` | - | Packed real |
| `OperandDataType.BYTE16` | 16 | 128-bit (SSE) |
| `OperandDataType.BYTE32` | 32 | 256-bit (AVX) |
| `OperandDataType.BYTE64` | 64 | 512-bit (AVX-512) |
| `OperandDataType.HALF` | 2 | Half-precision float |
| `OperandDataType.FWORD` | 6 | Far pointer (48-bit) |
| `OperandDataType.BITFIELD` | - | Bit field |
| `OperandDataType.STRING` | - | String |
| `OperandDataType.UNICODE` | - | Unicode string |
| `OperandDataType.LDBL` | - | Long double |
| `OperandDataType.CODE` | - | Code reference |
| `OperandDataType.VOID` | 0 | Void type |

### Usage

```python
op = db.instructions.get_operand(insn, 0)
if op:
    print(f"Data type: {op.data_type.name}")
    print(f"Size: {op.size_bytes} bytes")
    print(f"Is floating point: {op.is_floating_point()}")
```

---

## FunctionFlags

Function attribute flags.

```python
from ida_domain.functions import FunctionFlags
```

| Value | Description |
|-------|-------------|
| `FunctionFlags.NORET` | Function doesn't return |
| `FunctionFlags.FAR` | Far function |
| `FunctionFlags.LIB` | Library function |
| `FunctionFlags.STATICDEF` | Static function |
| `FunctionFlags.FRAME` | Function uses frame pointer (BP) |
| `FunctionFlags.USERFAR` | User has specified far-ness |
| `FunctionFlags.HIDDEN` | Hidden function chunk |
| `FunctionFlags.THUNK` | Thunk (jump) function |
| `FunctionFlags.BOTTOMBP` | BP points to bottom of stack frame |
| `FunctionFlags.NORET_PENDING` | Non-return analysis needed |
| `FunctionFlags.SP_READY` | SP-analysis performed |
| `FunctionFlags.FUZZY_SP` | SP changes in untraceable way |
| `FunctionFlags.PROLOG_OK` | Prolog analysis performed |
| `FunctionFlags.PURGED_OK` | 'argsize' field validated |
| `FunctionFlags.TAIL` | Function tail chunk |
| `FunctionFlags.LUMINA` | Info from Lumina |
| `FunctionFlags.OUTLINE` | Outlined code, not real function |
| `FunctionFlags.REANALYZE` | Frame changed, reanalyze requested |
| `FunctionFlags.UNWIND` | Exception unwind handler |
| `FunctionFlags.CATCH` | Exception catch handler |

### Usage

```python
flags = db.functions.get_flags(func)

if FunctionFlags.NORET in flags:
    print("Function does not return")

if FunctionFlags.THUNK in flags:
    print("This is a thunk function")

if FunctionFlags.LIB in flags:
    print("Library function")
```

---

## LocalVariableAccessType

How a local variable is accessed.

```python
from ida_domain.functions import LocalVariableAccessType
```

| Value | Description |
|-------|-------------|
| `LocalVariableAccessType.READ` | Variable value is read |
| `LocalVariableAccessType.WRITE` | Variable value is modified |
| `LocalVariableAccessType.ADDRESS` | Address of variable is taken (`&var`) |

### Usage

```python
refs = db.functions.get_local_variable_references(func, lvar)
for ref in refs:
    if ref.access_type == LocalVariableAccessType.WRITE:
        print(f"Variable written at line {ref.line_number}")
```

---

## LocalVariableContext

Context where a local variable is referenced.

```python
from ida_domain.functions import LocalVariableContext
```

| Value | Description |
|-------|-------------|
| `LocalVariableContext.ASSIGNMENT` | `var = expr` or `expr = var` |
| `LocalVariableContext.CONDITION` | `if (var)`, `while (var)`, etc. |
| `LocalVariableContext.CALL_ARG` | `func(var)` |
| `LocalVariableContext.RETURN` | `return var` |
| `LocalVariableContext.ARITHMETIC` | `var + 1`, `var * 2`, etc. |
| `LocalVariableContext.COMPARISON` | `var == x`, `var < y`, etc. |
| `LocalVariableContext.ARRAY_INDEX` | `arr[var]` or `var[i]` |
| `LocalVariableContext.POINTER_DEREF` | `*var` or `var->field` |
| `LocalVariableContext.CAST` | `(type)var` |
| `LocalVariableContext.OTHER` | Other contexts |

### Usage

```python
refs = db.functions.get_local_variable_references(func, lvar)
for ref in refs:
    if ref.context == LocalVariableContext.CALL_ARG:
        print(f"Variable passed as argument at line {ref.line_number}")
```

---

## SearchDirection

Direction for search operations.

```python
from ida_domain.search import SearchDirection
```

| Value | Description |
|-------|-------------|
| `SearchDirection.UP` | Search towards lower addresses |
| `SearchDirection.DOWN` | Search towards higher addresses |

### Usage

```python
# Find next code going forward
ea = db.search.next_code(start_ea, SearchDirection.DOWN)

# Find previous code going backward
ea = db.search.next_code(start_ea, SearchDirection.UP)
```

---

## SearchTarget

Type of address to find in search operations.

```python
from ida_domain.search import SearchTarget
```

| Value | Description |
|-------|-------------|
| `SearchTarget.UNDEFINED` | Find undefined/unexplored bytes |
| `SearchTarget.DEFINED` | Find defined items (instructions or data) |
| `SearchTarget.CODE` | Find code addresses |
| `SearchTarget.DATA` | Find data addresses |
| `SearchTarget.CODE_OUTSIDE_FUNCTION` | Find orphaned code (not in functions) |

### Usage

```python
# Using enum (preferred)
ea = db.search.find_next(start, SearchTarget.CODE, SearchDirection.DOWN)

# Using string (also works)
ea = db.search.find_next(start, "code", "forward")

# Iterate all code in range
for ea in db.search.find_all(start_ea, end_ea, SearchTarget.CODE):
    print(hex(ea))
```
