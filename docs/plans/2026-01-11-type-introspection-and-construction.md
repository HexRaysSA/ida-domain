# IDA Domain API: Type Introspection and Construction

**Status:** Implemented
**Branch:** `feature/type-introspection-and-construction`
**Date:** 2026-01-11

## Motivation

When writing scripts that need to export or import type information (like the REshare IDA scripts), the current IDA Domain API requires falling back to raw `ida_typeinf` primitives for:

1. **Member iteration** - Getting struct/union members, enum members, function arguments
2. **Type construction** - Creating new primitive, pointer, struct, union, enum, and function types
3. **Type component access** - Getting pointed type, array element type, return type, etc.

This proposal adds APIs that follow the established IDA Domain conventions to address these gaps.

---

## Part 1: Type Introspection - Member Details

### New Dataclasses

Following the pattern of `TypeDetails`, `UdtDetails`, etc., add member-level detail classes:

```python
@dataclass
class UdtMemberInfo:
    """Details about a struct/union member."""
    name: str
    type: tinfo_t
    offset: int
    size: int
    is_bitfield: bool
    bit_offset: Optional[int] = None
    bit_size: Optional[int] = None


@dataclass
class EnumMemberInfo:
    """Details about an enum member."""
    name: str
    value: int


@dataclass
class FuncArgumentInfo:
    """Details about a function argument."""
    index: int
    name: str
    type: tinfo_t
```

### New Methods on `Types` class

| Method | Purpose |
|--------|---------|
| `get_udt_members(type_info)` | Iterate struct/union members |
| `get_udt_member_by_name(type_info, name)` | Get member by name |
| `get_udt_member_by_offset(type_info, offset)` | Get member by offset |
| `get_udt_member_count(type_info)` | Count members |
| `get_enum_members(type_info)` | Iterate enum members |
| `get_enum_member_by_name(type_info, name)` | Get enum member by name |
| `get_enum_member_by_value(type_info, value)` | Get enum member by value |
| `get_enum_member_count(type_info)` | Count enum members |
| `get_func_arguments(type_info)` | Iterate function arguments |
| `get_func_argument_by_index(type_info, index)` | Get argument by index |
| `get_func_argument_count(type_info)` | Count arguments |
| `get_return_type(type_info)` | Get function return type |
| `get_pointed_type(type_info)` | Get pointer target type |
| `get_array_element_type(type_info)` | Get array element type |
| `get_array_length(type_info)` | Get array length |

---

## Part 2: Type Construction

### Type Builder Classes

```python
class StructBuilder:
    def __init__(self, name: str) -> None: ...
    def add_member(self, name: str, member_type: tinfo_t, offset: Optional[int] = None) -> StructBuilder: ...
    def set_packed(self, packed: bool = True) -> StructBuilder: ...
    def set_alignment(self, alignment: int) -> StructBuilder: ...
    def build(self) -> tinfo_t: ...
    def build_and_save(self, library: Optional[til_t] = None) -> tinfo_t: ...


class UnionBuilder:
    def __init__(self, name: str) -> None: ...
    def add_member(self, name: str, member_type: tinfo_t) -> UnionBuilder: ...
    def build(self) -> tinfo_t: ...
    def build_and_save(self, library: Optional[til_t] = None) -> tinfo_t: ...


class EnumBuilder:
    def __init__(self, name: str, base_size: int = 4) -> None: ...
    def add_member(self, name: str, value: int) -> EnumBuilder: ...
    def set_bitmask(self, is_bitmask: bool = True) -> EnumBuilder: ...
    def build(self) -> tinfo_t: ...
    def build_and_save(self, library: Optional[til_t] = None) -> tinfo_t: ...


class FuncTypeBuilder:
    def __init__(self) -> None: ...
    def set_return_type(self, ret_type: tinfo_t) -> FuncTypeBuilder: ...
    def add_argument(self, name: str, arg_type: tinfo_t) -> FuncTypeBuilder: ...
    def set_calling_convention(self, cc: CallingConvention) -> FuncTypeBuilder: ...
    def set_variadic(self, variadic: bool = True) -> FuncTypeBuilder: ...
    def build(self) -> tinfo_t: ...


class CallingConvention(Enum):
    CDECL = "cdecl"
    STDCALL = "stdcall"
    FASTCALL = "fastcall"
    THISCALL = "thiscall"
    DEFAULT = "default"
```

### New Creation Methods on `Types` class

| Method | Purpose |
|--------|---------|
| `create_void()` | Create void type |
| `create_primitive(size, signed=True)` | Create int/uint type |
| `create_float(size=4)` | Create float/double type |
| `create_pointer(target)` | Create pointer type |
| `create_array(element_type, count)` | Create array type |
| `create_struct(name)` | Create struct builder |
| `create_union(name)` | Create union builder |
| `create_enum(name, base_size=4)` | Create enum builder |
| `create_func_type()` | Create function type builder |

---

## Part 3: LLM-Friendly Unified Interface

```python
class TypeMemberLookupMode(Enum):
    NAME = "name"      # Look up by member/argument name
    OFFSET = "offset"  # Look up by byte offset (UDT only)
    INDEX = "index"    # Look up by index (enum, func args)
    VALUE = "value"    # Look up by enum value (enum only)
```

| Method | Purpose |
|--------|---------|
| `get_member(type_info, key, by="name")` | Unified member lookup |
| `get_members(type_info)` | Unified member iteration |

---

## Usage Examples

### Export struct members

```python
for member in db.types.get_udt_members(struct_type):
    print(f"{member.name}: {member.size} bytes at offset {member.offset}")
```

### Export enum members

```python
for member in db.types.get_enum_members(enum_type):
    print(f"{member.name} = {member.value}")
```

### Export function arguments

```python
for arg in db.types.get_func_arguments(func_type):
    print(f"Arg {arg.index}: {arg.name}")
```

### Create struct

```python
point = db.types.create_struct("Point") \
    .add_member("x", db.types.create_primitive(4)) \
    .add_member("y", db.types.create_primitive(4)) \
    .build_and_save()
```

### Create enum

```python
file_mode = db.types.create_enum("FileMode", base_size=4) \
    .add_member("READ", 1) \
    .add_member("WRITE", 2) \
    .add_member("EXEC", 4) \
    .build_and_save()
```

### Create function type

```python
func_type = db.types.create_func_type() \
    .set_return_type(db.types.create_primitive(4)) \
    .add_argument("count", db.types.create_primitive(4)) \
    .add_argument("buffer", db.types.create_pointer(db.types.create_primitive(1))) \
    .build()
```

---

## Summary

### New Classes

| Class | Purpose |
|-------|---------|
| `UdtMemberInfo` | Dataclass for struct/union member details |
| `EnumMemberInfo` | Dataclass for enum member details |
| `FuncArgumentInfo` | Dataclass for function argument details |
| `StructBuilder` | Builder for creating struct types |
| `UnionBuilder` | Builder for creating union types |
| `EnumBuilder` | Builder for creating enum types |
| `FuncTypeBuilder` | Builder for creating function types |
| `CallingConvention` | Enum for calling conventions |
| `TypeMemberLookupMode` | Enum for member lookup modes |

### Files Modified

- `ida_domain/types.py` - Added all new classes and methods
