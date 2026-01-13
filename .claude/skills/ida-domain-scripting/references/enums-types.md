# IDA Domain Enums and Types Reference

Auto-generated from source code. Do not edit manually.

---

## AccessType

```python
from ida_domain.operands import AccessType
```

Enumeration of operand access types.

| Value | Description |
|-------|-------------|
| `AccessType.NONE` |  |
| `AccessType.READ` |  |
| `AccessType.WRITE` |  |
| `AccessType.READ_WRITE` |  |

---

## FunctionFlags

```python
from ida_domain.functions import FunctionFlags
```

Function attribute flags from IDA SDK.

| Value | Description |
|-------|-------------|
| `FunctionFlags.NORET` |  |
| `FunctionFlags.FAR` |  |
| `FunctionFlags.LIB` |  |
| `FunctionFlags.STATICDEF` |  |
| `FunctionFlags.FRAME` |  |
| `FunctionFlags.USERFAR` |  |
| `FunctionFlags.HIDDEN` |  |
| `FunctionFlags.THUNK` |  |
| `FunctionFlags.BOTTOMBP` |  |
| `FunctionFlags.NORET_PENDING` |  |
| `FunctionFlags.SP_READY` |  |
| `FunctionFlags.FUZZY_SP` |  |
| `FunctionFlags.PROLOG_OK` |  |
| `FunctionFlags.PURGED_OK` |  |
| `FunctionFlags.TAIL` |  |
| `FunctionFlags.LUMINA` |  |
| `FunctionFlags.OUTLINE` |  |
| `FunctionFlags.REANALYZE` |  |
| `FunctionFlags.UNWIND` |  |
| `FunctionFlags.CATCH` |  |

---

## LocalVariableAccessType

```python
from ida_domain.functions import LocalVariableAccessType
```

Type of access to a local variable.

| Value | Description |
|-------|-------------|
| `LocalVariableAccessType.READ` |  |
| `LocalVariableAccessType.WRITE` |  |
| `LocalVariableAccessType.ADDRESS` |  |

---

## LocalVariableContext

```python
from ida_domain.functions import LocalVariableContext
```

Context where local variable is referenced.

| Value | Description |
|-------|-------------|
| `LocalVariableContext.ASSIGNMENT` |  |
| `LocalVariableContext.CONDITION` |  |
| `LocalVariableContext.CALL_ARG` |  |
| `LocalVariableContext.RETURN` |  |
| `LocalVariableContext.ARITHMETIC` |  |
| `LocalVariableContext.COMPARISON` |  |
| `LocalVariableContext.ARRAY_INDEX` |  |
| `LocalVariableContext.POINTER_DEREF` |  |
| `LocalVariableContext.CAST` |  |
| `LocalVariableContext.OTHER` |  |

---

## OperandDataType

```python
from ida_domain.operands import OperandDataType
```

Enumeration of operand data types.

| Value | Description |
|-------|-------------|
| `OperandDataType.BYTE` |  |
| `OperandDataType.WORD` |  |
| `OperandDataType.DWORD` |  |
| `OperandDataType.QWORD` |  |
| `OperandDataType.FLOAT` |  |
| `OperandDataType.DOUBLE` |  |
| `OperandDataType.TBYTE` |  |
| `OperandDataType.PACKREAL` |  |
| `OperandDataType.BYTE16` |  |
| `OperandDataType.BYTE32` |  |
| `OperandDataType.BYTE64` |  |
| `OperandDataType.HALF` |  |
| `OperandDataType.FWORD` |  |
| `OperandDataType.BITFIELD` |  |
| `OperandDataType.STRING` |  |
| `OperandDataType.UNICODE` |  |
| `OperandDataType.LDBL` |  |
| `OperandDataType.CODE` |  |
| `OperandDataType.VOID` |  |

---

## OperandType

```python
from ida_domain.operands import OperandType
```

Enumeration of operand types for easier identification.

| Value | Description |
|-------|-------------|
| `OperandType.VOID` |  |
| `OperandType.REGISTER` |  |
| `OperandType.MEMORY` |  |
| `OperandType.PHRASE` |  |
| `OperandType.DISPLACEMENT` |  |
| `OperandType.IMMEDIATE` |  |
| `OperandType.FAR_ADDRESS` |  |
| `OperandType.NEAR_ADDRESS` |  |
| `OperandType.PROCESSOR_SPECIFIC_0` |  |
| `OperandType.PROCESSOR_SPECIFIC_1` |  |
| `OperandType.PROCESSOR_SPECIFIC_2` |  |
| `OperandType.PROCESSOR_SPECIFIC_3` |  |
| `OperandType.PROCESSOR_SPECIFIC_4` |  |
| `OperandType.PROCESSOR_SPECIFIC_5` |  |

---

## SearchDirection

```python
from ida_domain.search import SearchDirection
```

Direction for search operations.

| Value | Description |
|-------|-------------|
| `SearchDirection.UP` |  |
| `SearchDirection.DOWN` |  |

---

## SearchTarget

```python
from ida_domain.search import SearchTarget
```

Type of address to find in search operations.

| Value | Description |
|-------|-------------|
| `SearchTarget.UNDEFINED` |  |
| `SearchTarget.DEFINED` |  |
| `SearchTarget.CODE` |  |
| `SearchTarget.DATA` |  |
| `SearchTarget.CODE_OUTSIDE_FUNCTION` |  |

---

## XrefKind

```python
from ida_domain.xrefs import XrefKind
```

Filter kind for cross-reference queries.

| Value | Description |
|-------|-------------|
| `XrefKind.ALL` |  |
| `XrefKind.CODE` |  |
| `XrefKind.DATA` |  |
| `XrefKind.CALLS` |  |
| `XrefKind.JUMPS` |  |
| `XrefKind.READS` |  |
| `XrefKind.WRITES` |  |

---

## XrefType

```python
from ida_domain.xrefs import XrefType
```

Unified cross-reference types (both code and data).

| Value | Description |
|-------|-------------|
| `XrefType.UNKNOWN` |  |
| `XrefType.OFFSET` |  |
| `XrefType.WRITE` |  |
| `XrefType.READ` |  |
| `XrefType.TEXT` |  |
| `XrefType.INFORMATIONAL` |  |
| `XrefType.SYMBOLIC` |  |
| `XrefType.CALL_FAR` |  |
| `XrefType.CALL_NEAR` |  |
| `XrefType.JUMP_FAR` |  |
| `XrefType.JUMP_NEAR` |  |
| `XrefType.USER_SPECIFIED` |  |
| `XrefType.ORDINARY_FLOW` |  |

---

## XrefsFlags

```python
from ida_domain.xrefs import XrefsFlags
```

Flags for xref iteration control.

| Value | Description |
|-------|-------------|
| `XrefsFlags.ALL` |  |
| `XrefsFlags.NOFLOW` |  |
| `XrefsFlags.DATA` |  |
| `XrefsFlags.CODE` |  |
| `XrefsFlags.CODE_NOFLOW` |  |

---
