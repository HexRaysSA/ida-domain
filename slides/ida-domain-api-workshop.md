---
theme: apple-basic
title: Practical Binary Analysis with the IDA Domain API
info: |
  ## From clicking to scripting
  A hands-on workshop for reverse engineers
drawings:
  persist: false
transition: slide-left
mdc: true
layout: intro-image-right
image: https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=1200
---

<div class="absolute top-10">
  <img src="https://hex-rays.com/hubfs/logo.svg" class="w-32" />
</div>

<div class="mt-12">

# IDA Domain API

Practical Binary Analysis Workshop

<p class="opacity-50">From clicking to scripting</p>

</div>

---
layout: section
---

# Part 1
## The Problem & The Solution

---

# The Problem with IDAPython

Traditional scripting is powerful but painful:

```python
# Classic IDAPython: Find all callers of a function
import idautils
import idc
import ida_funcs

ea = 0x401000
for xref in idautils.XrefsTo(ea):
    if xref.type in [ida_xref.fl_CF, ida_xref.fl_CN]:
        func = ida_funcs.get_func(xref.frm)
        if func:
            name = idc.get_func_name(func.start_ea)
            print(f"Called from {name}")
```

<v-clicks>

- Multiple imports required
- Must know magic constants (`fl_CF`, `fl_CN`)
- Inconsistent naming conventions
- No discoverability

</v-clicks>

---

# Enter the IDA Domain API

The same task, simplified:

```python
from ida_domain import Database

with Database() as db:
    for xref in db.xrefs.calls_to_ea(0x401000):
        func = db.functions.get_at(xref.from_ea)
        print(f"Called from {func.name}")
```

<v-click>

<div class="mt-4 p-4 bg-green-500/20 border-l-4 border-green-400 rounded">

**Key improvements:**
- Single entry point: `Database`
- Domain-focused methods: `calls_to_ea()` not magic constants
- Pythonic: context managers, iteration, properties
- Discoverable: tab-completion shows available operations

</div>

</v-click>

---

# Domain API Mental Model

<div class="text-center mt-8">

```
                    ┌─────────────┐
                    │  Database   │
                    └──────┬──────┘
       ┌──────────┬────────┼────────┬──────────┐
       ▼          ▼        ▼        ▼          ▼
  ┌─────────┐ ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐
  │functions│ │ xrefs │ │strings│ │ bytes │ │  ...  │
  └─────────┘ └───────┘ └───────┘ └───────┘ └───────┘
```

</div>

<v-click>

<div class="mt-8 p-4 bg-blue-500/20 border-l-4 border-blue-400 rounded">

**Pattern:** `db.<entity>.<action>()`

- `db.functions` → work with functions
- `db.xrefs` → work with cross-references
- `db.strings` → work with string literals
- `db.bytes` → work with raw bytes

</div>

</v-click>

---
layout: section
---

# Part 2
## Our Target Binary

---

# The License Checker

A realistic analysis target written in Zig:

<div class="grid grid-cols-2 gap-4">
<div>

**Program flow:**
```
main()
├── get_machine_id()
├── hash_id()
├── validate_license()
│   └── parse_license_key()
└── check_trial_status()
```

</div>
<div>

**Behavior:**
- Reads machine ID from `/etc/machine-id`
- Hashes to create hardware fingerprint
- Validates license key against fingerprint
- Falls back to trial mode

</div>
</div>

<v-click>

<div class="mt-4 p-4 bg-yellow-500/20 border-l-4 border-yellow-400 rounded">

**What makes it interesting:** XOR constants, string references, multiple code paths, clear validation logic to discover.

</div>

</v-click>

---

# Compiling & Stripping

Creating our analysis target:

```bash
# Compile with Zig (includes stripping)
zig build-exe license_checker.zig -target x86_64-linux -O ReleaseSafe -fno-PIE -fstrip

# Verify it's stripped
file license_checker
# license_checker: ELF 64-bit LSB executable, x86-64, statically linked, stripped

# Size: ~45KB
ls -lh license_checker
```

<v-click>

<div class="grid grid-cols-2 gap-8 mt-6">
<div class="p-4 bg-red-500/10 rounded-lg border border-red-400/30">

### What we lose
- Function names → `sub_401000`
- Variable names
- Type information
- Debug info

</div>
<div class="p-4 bg-green-500/10 rounded-lg border border-green-400/30">

### What remains
- String literals
- Code structure
- Cross-references

</div>
</div>

</v-click>

---
layout: section
---

# Part 3
## Hands-On Scripts

---

# Example 1: Finding Strings

Our first entry point into the binary:

```python
from ida_domain import Database

with Database() as db:
    keywords = ["license", "trial", "valid", "invalid", "expired"]

    for s in db.strings:
        content = s.content.lower()
        if any(kw in content for kw in keywords):
            print(f"0x{s.ea:08x}: {s.content!r}")
```

<v-click>

**Output:**
```
0x00402010: 'License Invalid'
0x00402020: 'License Valid - Full Mode'
0x00402040: 'Trial Mode - %d days remaining'
0x00402070: 'Trial Expired'
```

</v-click>

<v-click>

<div class="mt-2 p-3 bg-green-500/20 border-l-4 border-green-400 rounded text-sm">

**Result:** Found our targets in milliseconds, no clicking required.

</div>

</v-click>

---

# StringInfo Objects

What does a String object give us?

```python
@dataclass
class StringInfo:
    ea: int          # Address of the string
    content: str     # The string content
    length: int      # Length in bytes
    string_type: StringType  # C, Pascal, Unicode, etc.
```

<v-click>

<div class="grid grid-cols-2 gap-4 mt-4">
<div>

**Domain API:**
```python
for s in db.strings:
    print(s.ea, s.content, s.length)
```

</div>
<div>

**Classic IDAPython:**
```python
ea = 0x402010
content = idc.get_strlit_contents(ea)
length = idc.get_item_size(ea)
str_type = idc.get_str_type(ea)
```

</div>
</div>

</v-click>

<v-click>

<div class="mt-4 p-3 bg-blue-500/20 border-l-4 border-blue-400 rounded text-sm">

**Pattern:** All related info bundled in dataclasses, not scattered across function calls.

</div>

</v-click>

---

# Example 2: Tracing Xrefs

Who uses these strings?

```python
from ida_domain import Database

with Database() as db:
    for s in db.strings:
        if s.content == "License Invalid":
            print(f"String at 0x{s.ea:08x}")
            print("Referenced by:")

            for xref in db.xrefs.to_ea(s.ea):
                print(f"  0x{xref.from_ea:08x} ({xref.type.name})")
```

<v-click>

**Output:**
```
String at 0x00402010
Referenced by:
  0x00401234 (DATA_READ)
```

</v-click>

<v-click>

<div class="mt-2 p-3 bg-green-500/20 border-l-4 border-green-400 rounded text-sm">

**Found it:** Code at `0x401234` displays "License Invalid" - likely near validation logic.

</div>

</v-click>

---

# XrefInfo Objects

<div class="grid grid-cols-2 gap-4">
<div>

Cross-references are first-class citizens:

```python
@dataclass
class XrefInfo:
    from_ea: int      # Source address
    to_ea: int        # Destination address
    is_code: bool     # Code or data?
    type: XrefType    # Specific type
    user: bool        # User-defined?

    @property
    def is_call(self) -> bool: ...
    @property
    def is_jump(self) -> bool: ...
```

</div>
<div>

<v-click>

<div class="p-3 bg-indigo-500/10 rounded-lg border border-indigo-400/30 text-sm mb-3">

**Available methods:**
- `db.xrefs.to_ea(ea)`
- `db.xrefs.from_ea(ea)`
- `db.xrefs.calls_to_ea(ea)`
- `db.xrefs.reads_of_ea(ea)`

</div>

<div class="p-3 bg-emerald-500/10 rounded-lg border border-emerald-400/30 text-sm">

**No more magic constants:**
- `xref.is_call` vs `fl_CF`
- `xref.is_jump` vs `fl_JF`
- Clear, readable code

</div>

</v-click>

</div>
</div>

---

# Example 3: Mapping to Functions

What function contains this reference?

<div class="grid grid-cols-2 gap-4">
<div>

```python
from ida_domain import Database

with Database() as db:
    ref_addr = 0x00401234
    func = db.functions.get_at(ref_addr)

    if func:
        print(f"Function: {func.name}")
        print(f"  Start: 0x{func.start_ea:08x}")
        print(f"  End:   0x{func.end_ea:08x}")
        size = func.end_ea - func.start_ea
        print(f"  Size:  {size} bytes")
```

</div>
<div>

<v-click>

**Output:**
```
Function: sub_401200
  Start: 0x00401200
  End:   0x00401350
  Size:  336 bytes
```

</v-click>

<v-click>

<div class="mt-2 p-3 bg-blue-500/20 border-l-4 border-blue-400 rounded text-sm">

**Identified:** `sub_401200` is our validation function.

</div>

</v-click>

</div>
</div>

---

# Example 4: Building Call Graphs

Who calls our validation function?

```python
from ida_domain import Database

with Database() as db:
    target_ea = 0x00401200

    print(f"Callers of sub_{target_ea:x}:")

    for caller in db.xrefs.calls_to_ea(target_ea):
        caller_func = db.functions.get_at(caller.from_ea)
        if caller_func:
            print(f"  {caller_func.name} @ 0x{caller.from_ea:08x}")
```

<v-click>

**Output:**
```
Callers of sub_401200:
  sub_401100 @ 0x00401156
```

</v-click>

<v-click>

<div class="mt-2 p-3 bg-green-500/20 border-l-4 border-green-400 rounded text-sm">

**Found:** `sub_401100` calls validation - this is probably `main()`.

</div>

</v-click>

---

# Recursive Call Tree

<div class="grid grid-cols-2 gap-4">
<div>

```python
def build_call_tree(db, start_ea, depth=0,
                    max_depth=3, visited=None):
    if visited is None:
        visited = set()
    if depth > max_depth or start_ea in visited:
        return
    visited.add(start_ea)
    func = db.functions.get_at(start_ea)
    if not func:
        return
    print("  " * depth + f"{func.name}")
    for xref in db.xrefs.from_ea(func.start_ea):
        if xref.is_call:
            build_call_tree(db, xref.to_ea,
                           depth + 1, max_depth, visited)
```

</div>
<div>

<v-click>

**Output:**
```
sub_401100        <- main
  sub_401200      <- validate_license
    sub_401400    <- hash_id
    sub_401500    <- parse_license_key
  sub_401600      <- check_trial_status
  sub_401050      <- get_machine_id
```

</v-click>

</div>
</div>

---

# Example 5: Control Flow Analysis

Understanding branching inside a function:

```python
from ida_domain import Database

with Database() as db:
    func = db.functions.get_at(0x401200)
    flowchart = db.functions.get_flowchart(func)

    print(f"Basic blocks: {len(flowchart)}")

    for block in flowchart:
        successors = list(block.succs())

        if len(successors) == 2:  # Conditional branch
            print(f"Branch at 0x{block.end_ea:08x}")
            print(f"  True:  -> 0x{successors[0].start_ea:08x}")
            print(f"  False: -> 0x{successors[1].start_ea:08x}")
```

<v-click>

<div class="mt-4 p-3 bg-yellow-500/20 border-l-4 border-yellow-400 rounded text-sm">

**Why this matters:** The validation function must have a key branch - one path leads to "valid", one to "invalid". Finding this branch = finding the patch point.

</div>

</v-click>

---

# Example 6: Byte Pattern Search

Finding XOR constants in hash functions:

```python
from ida_domain import Database

with Database() as db:
    # Get bytes from suspected hash function
    hash_func = db.functions.get_at(0x401400)

    func_bytes = db.bytes.get_bytes(
        hash_func.start_ea,
        hash_func.end_ea - hash_func.start_ea
    )

    # Display as hex dump
    for i in range(0, len(func_bytes), 16):
        chunk = func_bytes[i:i+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        print(f"0x{hash_func.start_ea + i:08x}: {hex_str}")
```

<v-click>

<div class="mt-4 p-3 bg-green-500/20 border-l-4 border-green-400 rounded text-sm">

**Look for:** `0xDEADBEEF` - our XOR constant should appear in the function bytes.

</div>

</v-click>

---

# Example 7: Adding Annotations

Documenting our findings:

```python {*}{maxHeight:'320px'}
from ida_domain import Database

with Database() as db:
    # Rename functions based on analysis
    db.names.set_name(0x401100, "main")
    db.names.set_name(0x401050, "get_machine_id")
    db.names.set_name(0x401200, "validate_license")
    db.names.set_name(0x401400, "hash_id")
    db.names.set_name(0x401500, "parse_license_key")
    db.names.set_name(0x401600, "check_trial_status")

    # Add comments at key locations
    db.comments.set_comment(0x401423, "XOR constant: 0xDEADBEEF")
    db.comments.set_comment(0x401250, "Branch: valid vs invalid")
```

<v-click>

<div class="mt-2 p-3 bg-blue-500/20 border-l-4 border-blue-400 rounded text-sm">

**Saved to IDB:** Annotations persist. Next session, all analysis is preserved.

</div>

</v-click>

---

# Example 8: Automated Report

Putting it all together:

```python
def generate_report(db):
    report = ["=" * 60, "LICENSE CHECKER ANALYSIS REPORT", "=" * 60, ""]

    funcs = list(db.functions)
    strings = list(db.strings)

    report.append(f"Total functions: {len(funcs)}")
    report.append(f"Total strings: {len(strings)}")
    report.append("")

    report.append("KEY FUNCTIONS:")
    for func in funcs:
        if not func.name.startswith("sub_"):
            report.append(f"  {func.name}: 0x{func.start_ea:08x}")

    report.append("")
    report.append("LICENSE STRINGS:")
    for s in strings:
        if "license" in s.content.lower():
            report.append(f"  0x{s.ea:08x}: {s.content!r}")

    return "\n".join(report)
```

---
layout: section
---

# Part 4
## Wrap-Up

---
layout: two-cols
---

# Manual vs Scripted

<div class="text-sm">

| Task | Manual | Scripted |
|------|--------|----------|
| Find strings | ~2 min | 0.5 sec |
| Trace xrefs | ~5 min | 0.5 sec |
| Map call graph | ~10 min | 1 sec |
| Find branches | ~5 min | 0.5 sec |
| Find constants | ~10 min | 1 sec |
| Add annotations | ~5 min | 1 sec |
| **Total** | **~40 min** | **~5 sec** |

</div>

::right::

<div class="ml-4">

<v-click>

<div class="p-4 bg-green-500/20 border-l-4 border-green-400 rounded mt-8">

**Beyond speed:**

- Scripts are **repeatable**
- Scripts are **shareable**
- Scripts are **accurate**
- No missed xrefs
- Team knowledge capture

</div>

</v-click>

</div>

---

# When to Use Domain API

<div class="grid grid-cols-2 gap-8">
<div class="p-4 bg-green-500/10 rounded-lg border border-green-400/30">

### Use Domain API

- Analyzing multiple similar binaries
- Building analysis tools/plugins
- Teaching/documenting RE
- Need reproducible analysis
- Complex data structure recovery
- Quick prototypes

</div>
<div class="p-4 bg-yellow-500/10 rounded-lg border border-yellow-400/30">

### Drop to IDAPython

- Performance-critical inner loops
- Features not yet in Domain API
- Direct IDA internals manipulation
- One-off quick checks

</div>
</div>

<v-click>

<div class="mt-4 p-3 bg-blue-500/20 border-l-4 border-blue-400 rounded text-sm">

**Remember:** Domain API complements IDAPython, doesn't replace it.

</div>

</v-click>

---

# Key Takeaways

<v-clicks>

1. **One entry point:** `from ida_domain import Database`

2. **Consistent pattern:** `db.<entity>.<action>()`

3. **Everything iterates:** `for x in db.functions`, `for x in db.strings`

4. **Rich objects:** Dataclasses with properties, not raw addresses

5. **Context managers:** `with Database() as db:` handles cleanup

6. **Discoverable:** Tab-complete `db.` to see what's available

7. **Incremental:** Use it for new scripts, keep old IDAPython

</v-clicks>

---

# Quick Reference

```
┌─────────────────────────────────────────────────────────────┐
│              IDA DOMAIN API QUICK REFERENCE                 │
├─────────────────────────────────────────────────────────────┤
│ FUNCTIONS                                                   │
│   for func in db.functions           # iterate all         │
│   func = db.functions.get_at(ea)     # get by address      │
│   fc = db.functions.get_flowchart(f) # get basic blocks    │
├─────────────────────────────────────────────────────────────┤
│ CROSS-REFERENCES                                            │
│   db.xrefs.to_ea(ea)                 # refs TO address     │
│   db.xrefs.from_ea(ea)               # refs FROM address   │
│   db.xrefs.calls_to_ea(ea)           # calls only          │
├─────────────────────────────────────────────────────────────┤
│ STRINGS & BYTES                                             │
│   for s in db.strings                # iterate strings     │
│   db.bytes.get_bytes(ea, size)       # read bytes          │
├─────────────────────────────────────────────────────────────┤
│ NAMES & COMMENTS                                            │
│   db.names.set_name(ea, "name")      # rename              │
│   db.comments.set_comment(ea, "...")  # add comment        │
└─────────────────────────────────────────────────────────────┘
```

---

# Getting Started

**Installation:**
```bash
pip install ida-domain
```

**First script:**
```python
from ida_domain import Database

with Database() as db:
    for func in db.functions:
        print(func.name)
```

<v-click>

<div class="grid grid-cols-2 gap-4 mt-4 text-sm">
<div class="p-3 bg-indigo-500/10 rounded-lg border border-indigo-400/30">

**Resources:**
- GitHub: `hex-rays/ida-domain`
- Docs: `ida-domain.readthedocs.io`
- Examples: `examples/` folder

</div>
<div class="p-3 bg-emerald-500/10 rounded-lg border border-emerald-400/30">

**Practice exercises:**
1. Find all URL strings
2. Build complete call graph
3. Create analysis template

</div>
</div>

</v-click>

---
layout: center
class: text-center
---

# Questions?

<div class="pt-8">

### Workshop Materials

<div class="grid grid-cols-2 gap-8 text-sm mt-4">
<div>

**Sample binary:**
`examples/workshop/license_checker`

**Analysis scripts:**
`examples/workshop/01-08_*.py`

</div>
<div>

**Documentation:**
`docs.hex-rays.com`

**Support:**
`support@hex-rays.com`

</div>
</div>

</div>

<div class="absolute bottom-10 left-10">
  <img src="https://hex-rays.com/hubfs/logo.svg" class="w-24 opacity-50" />
</div>
