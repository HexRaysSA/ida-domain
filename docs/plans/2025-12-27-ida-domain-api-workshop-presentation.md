# Practical Binary Analysis with the IDA Domain API

## Workshop Presentation Outline

**Duration:** 45-60 minutes
**Audience:** Junior to intermediate reverse engineers
**Format:** Hands-on workshop with progressive scripting examples

---

# PART 1: SETUP (~8 minutes)

---

## Slide 1: Title

**Practical Binary Analysis with the IDA Domain API**

*From clicking to scripting: A hands-on workshop*

- Your Name / Hex-Rays
- Date

> **Speaker notes:** Welcome the audience. This workshop will take them from manual IDA clicking to writing scripts that automate real analysis tasks. By the end, they'll have a toolkit of patterns they can apply immediately.

---

## Slide 2: The Problem with IDAPython

**Traditional IDAPython is powerful but painful**

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

**Pain points:**
- Multiple imports required (`idautils`, `idc`, `ida_funcs`, `ida_xref`)
- Must know magic constants (`fl_CF`, `fl_CN`)
- Raw addresses everywhere, easy to make mistakes
- No discoverability - must read docs to find functions
- Inconsistent naming (`XrefsTo` vs `get_func` vs `get_func_name`)

> **Speaker notes:** Ask the audience: "Who has written IDAPython scripts?" Then: "Who has been frustrated by them?" This slide validates their pain before introducing the solution.

---

## Slide 3: Enter the IDA Domain API

**A modern, Pythonic layer over IDAPython**

```python
# IDA Domain API: Same task
from ida_domain import Database

with Database() as db:
    for xref in db.xrefs.calls_to_ea(0x401000):
        func = db.functions.get_at(xref.from_ea)
        print(f"Called from {func.name}")
```

**Key improvements:**
- Single entry point: `Database`
- Domain-focused methods: `calls_to_ea()` not magic constants
- Pythonic: context managers, iteration, properties
- Discoverable: tab-completion shows available operations
- Consistent: `db.entity.action()` pattern throughout

> **Speaker notes:** Emphasize that the Domain API doesn't replace IDAPython - it wraps it. You can always drop down to raw IDAPython when needed.

---

## Slide 4: Our Target - A License Checker

**We'll analyze a stripped license validation binary**

The program (written in Zig, compiled to Linux ELF):

```
┌─────────────────────────────────────────────────────┐
│                      main()                         │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────┐ │
│  │get_machine_ │  │  validate_   │  │check_trial_│ │
│  │    id()     │──│  license()   │──│  status()  │ │
│  └─────────────┘  └──────────────┘  └────────────┘ │
│         │               │                          │
│         ▼               ▼                          │
│  ┌─────────────┐  ┌──────────────┐                 │
│  │  hash_id()  │  │parse_license_│                 │
│  │             │  │    key()     │                 │
│  └─────────────┘  └──────────────┘                 │
└─────────────────────────────────────────────────────┘
```

**What it does:**
- Reads machine ID from `/etc/machine-id`
- Hashes it to create a hardware fingerprint
- Validates license key against fingerprint
- Falls back to trial mode if no valid license

> **Speaker notes:** Briefly show the Zig source on your screen (but not in slides). Say "Now forget you saw that - we're going to recover this logic from the stripped binary."

---

## Slide 5: Compiling and Stripping

**Creating our analysis target**

```bash
# Compile with Zig (includes stripping)
zig build-exe license_checker.zig -target x86_64-linux -O ReleaseSafe -fno-PIE -fstrip

# Verify it's stripped
file license_checker
# license_checker: ELF 64-bit LSB executable, x86-64, statically linked, stripped

# Check size (should be ~45KB)
ls -lh license_checker
```

**What we lose:**
- Function names → `sub_401000`
- Variable names → register/stack references
- Type information → raw bytes
- Debug info → just machine code

**What remains:**
- String literals (our entry point!)
- Code structure
- Cross-references

> **Speaker notes:** If doing this live, compile the binary now. Otherwise, have it pre-compiled.

---

# PART 2: FIRST CONTACT (~7 minutes)

---

## Slide 6: Loading in IDA

**Initial automated analysis**

1. Open IDA, drag in `license_checker`
2. Accept default options (ELF 64-bit)
3. Wait for auto-analysis to complete

**What IDA finds automatically:**
- Entry point and `_start`
- String literals in `.rodata`
- Some function boundaries
- Basic cross-references

**What it doesn't know:**
- What functions actually do
- Meaningful names
- Data structure layouts
- The overall program logic

> **Speaker notes:** Show IDA's initial view. Point out the `sub_XXXX` function names and lack of context.

---

## Slide 7: Manual Analysis Pain Points

**The clicking treadmill**

To understand this binary manually, you would:

1. **Strings window** (Shift+F12) → Find interesting strings
2. **Double-click** → Jump to string in data section
3. **Xrefs** (X) → See what references the string
4. **Jump** → Go to the referencing code
5. **Identify function** → F5 to decompile
6. **Repeat** for each string, each xref, each caller...

**Problems:**
- Context switching constantly
- Losing track of what you've analyzed
- No systematic coverage
- Hard to document findings
- Repetitive strain!

> **Speaker notes:** Actually do this manually for one string to show the tedium. Then say "Now imagine doing this for 50 strings."

---

## Slide 8: The Scripting Opportunity

**What if we could automate this?**

| Manual Task | Scripted Equivalent |
|------------|---------------------|
| Open Strings window, scroll | `for s in db.strings` |
| Press X for each string | `db.xrefs.to_ea(s.ea)` |
| Navigate to function | `db.functions.get_at(ea)` |
| Copy-paste to notes | `print()` or write to file |
| Repeat 50 times | Loop once |

**Goal for this workshop:**
Write scripts that in **seconds** accomplish what takes **minutes** of clicking

> **Speaker notes:** This is the "aha" slide. Transition from "why" to "how".

---

## Slide 9: Domain API Mental Model

**One hub, many domains**

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

**Pattern:** `db.<entity>.<action>()`

- `db.functions` → work with functions
- `db.xrefs` → work with cross-references
- `db.strings` → work with string literals
- `db.bytes` → work with raw bytes
- `db.comments` → work with comments

**Everything is iterable, everything is typed.**

> **Speaker notes:** Draw this on a whiteboard if possible. Emphasize the consistency - once you learn the pattern, you can guess how to do things.

---

# PART 3: HANDS-ON SCRIPTS (~30 minutes)

---

## Slide 10: Example 1 - Finding Interesting Strings

**Our first entry point into the binary**

```python
from ida_domain import Database

with Database() as db:
    # Find all strings in the binary
    print(f"Found {len(list(db.strings))} strings\n")

    # Look for license-related strings
    keywords = ["license", "trial", "valid", "invalid", "expired"]

    for s in db.strings:
        content = s.content.lower()
        if any(kw in content for kw in keywords):
            print(f"0x{s.ea:08x}: {s.content!r}")
```

**Expected output:**
```
Found 23 strings

0x00402010: 'License Invalid'
0x00402020: 'License Valid - Full Mode'
0x00402040: 'Trial Mode - %d days remaining'
0x00402070: 'Trial Expired'
```

> **Speaker notes:** Run this live. Point out how we immediately found our targets without any clicking.

---

## Slide 11: Understanding String Objects

**What does a String object give us?**

```python
with Database() as db:
    for s in db.strings:
        if "License" in s.content:
            print(f"Address:  0x{s.ea:08x}")
            print(f"Content:  {s.content!r}")
            print(f"Length:   {s.length}")
            print(f"Type:     {s.string_type}")
            print("---")
```

**The `StringInfo` dataclass:**
```python
@dataclass
class StringInfo:
    ea: int          # Address of the string
    content: str     # The string content
    length: int      # Length in bytes
    string_type: StringType  # C, Pascal, Unicode, etc.
```

**Compare to classic IDAPython:**
```python
# Classic: must call multiple functions
ea = 0x402010
content = idc.get_strlit_contents(ea)
length = idc.get_item_size(ea)
str_type = idc.get_str_type(ea)
```

> **Speaker notes:** Emphasize the dataclass pattern - all related info bundled together.

---

## Slide 12: Example 2 - Tracing String References

**Who uses these strings?**

```python
from ida_domain import Database

with Database() as db:
    # Find the "License Invalid" string
    target_string = None
    for s in db.strings:
        if s.content == "License Invalid":
            target_string = s
            break

    if not target_string:
        print("String not found!")
        exit()

    print(f"String at 0x{target_string.ea:08x}")
    print("Referenced by:")

    # Find all cross-references TO this string
    for xref in db.xrefs.to_ea(target_string.ea):
        print(f"  0x{xref.from_ea:08x} (type: {xref.type.name})")
```

**Expected output:**
```
String at 0x00402010
Referenced by:
  0x00401234 (type: DATA_READ)
```

> **Speaker notes:** We've now found the code that displays "License Invalid" - this is likely near the validation logic.

---

## Slide 13: Understanding XrefInfo

**Cross-references are first-class objects**

```python
@dataclass
class XrefInfo:
    from_ea: int      # Source address
    to_ea: int        # Destination address
    is_code: bool     # Code or data reference?
    type: XrefType    # Specific type
    user: bool        # User-defined?

    # Convenience properties
    @property
    def is_call(self) -> bool: ...
    @property
    def is_jump(self) -> bool: ...
    @property
    def is_read(self) -> bool: ...
    @property
    def is_write(self) -> bool: ...
```

**Xref types in the API:**
- `db.xrefs.to_ea(ea)` → all refs pointing TO address
- `db.xrefs.from_ea(ea)` → all refs FROM address
- `db.xrefs.calls_to_ea(ea)` → only CALL refs to address
- `db.xrefs.reads_of_ea(ea)` → only READ refs to address

> **Speaker notes:** The typed properties (`is_call`, `is_jump`) eliminate the need to remember IDA's xref type constants.

---

## Slide 14: Example 3 - Mapping to Functions

**What function contains this reference?**

```python
from ida_domain import Database

with Database() as db:
    # Address we found referencing "License Invalid"
    ref_addr = 0x00401234  # From previous example

    # Get the function containing this address
    func = db.functions.get_at(ref_addr)

    if func:
        print(f"Function: {func.name}")
        print(f"  Start:  0x{func.start_ea:08x}")
        print(f"  End:    0x{func.end_ea:08x}")
        print(f"  Size:   {func.end_ea - func.start_ea} bytes")
    else:
        print("Address not inside a function!")
```

**Expected output:**
```
Function: sub_401200
  Start:  0x00401200
  End:    0x00401350
  Size:   336 bytes
```

> **Speaker notes:** We've identified the function - this is probably our validation function. But `sub_401200` isn't a helpful name...

---

## Slide 15: Exploring Function Properties

**What does a Function object give us?**

```python
with Database() as db:
    func = db.functions.get_at(0x401200)

    print(f"Name:       {func.name}")
    print(f"Start:      0x{func.start_ea:08x}")
    print(f"End:        0x{func.end_ea:08x}")
    print(f"Frame size: {func.frame_size}")
    print(f"Flags:      {func.flags}")

    # Check specific flags
    if func.flags & FunctionFlags.NORET:
        print("  - Does not return")
    if func.flags & FunctionFlags.THUNK:
        print("  - Is a thunk")
    if func.flags & FunctionFlags.LIB:
        print("  - Library function")
```

**Iterate all functions:**
```python
for func in db.functions:
    print(f"{func.name}: 0x{func.start_ea:08x}")
```

> **Speaker notes:** Point out that iteration just works - no need to call `get_next_func()` in a loop like classic IDAPython.

---

## Slide 16: Example 4 - Building a Call Graph

**Who calls our validation function?**

```python
from ida_domain import Database

with Database() as db:
    # Our suspected validation function
    target_ea = 0x00401200

    print(f"Callers of sub_{target_ea:x}:")
    print("-" * 40)

    for caller in db.xrefs.calls_to_ea(target_ea):
        # Get the calling function
        caller_func = db.functions.get_at(caller.from_ea)
        if caller_func:
            print(f"  {caller_func.name} @ 0x{caller.from_ea:08x}")
```

**Expected output:**
```
Callers of sub_401200:
----------------------------------------
  sub_401100 @ 0x00401156
```

> **Speaker notes:** We've found that `sub_401100` calls our validation function. This is probably `main()`.

---

## Slide 17: Visualizing the Call Hierarchy

**Building a complete picture**

```python
from ida_domain import Database
from collections import defaultdict

def build_call_graph(db, start_ea, depth=0, max_depth=3, visited=None):
    if visited is None:
        visited = set()

    if depth > max_depth or start_ea in visited:
        return

    visited.add(start_ea)
    func = db.functions.get_at(start_ea)
    if not func:
        return

    indent = "  " * depth
    print(f"{indent}{func.name} (0x{start_ea:08x})")

    # Find all functions this one calls
    for xref in db.xrefs.from_ea(start_ea):
        if xref.is_call:
            build_call_graph(db, xref.to_ea, depth + 1, max_depth, visited)

with Database() as db:
    print("Call hierarchy from main:")
    build_call_graph(db, 0x401100)
```

**Expected output:**
```
Call hierarchy from main:
sub_401100 (0x00401100)
  sub_401200 (0x00401200)    <- validate_license
    sub_401400 (0x00401400)  <- hash_id
    sub_401500 (0x00401500)  <- parse_license_key
  sub_401600 (0x00401600)    <- check_trial_status
  sub_401050 (0x00401050)    <- get_machine_id
```

> **Speaker notes:** Now we see the whole structure! This matches our original Zig design.

---

## Slide 18: Example 5 - Analyzing Control Flow

**Understanding branching inside a function**

```python
from ida_domain import Database

with Database() as db:
    func = db.functions.get_at(0x401200)  # validate_license

    # Get the function's flowchart (basic blocks)
    flowchart = db.functions.get_flowchart(func)

    print(f"Function {func.name} has {len(flowchart)} basic blocks:")
    print()

    for i, block in enumerate(flowchart):
        print(f"Block {i}:")
        print(f"  Range: 0x{block.start_ea:08x} - 0x{block.end_ea:08x}")
        print(f"  Size:  {block.end_ea - block.start_ea} bytes")

        # Count successors (branches)
        successors = list(block.succs())
        print(f"  Successors: {len(successors)}")
        for succ in successors:
            print(f"    -> 0x{succ.start_ea:08x}")
        print()
```

> **Speaker notes:** Basic blocks are the atoms of control flow analysis. A block with 2 successors means a conditional branch.

---

## Slide 19: Identifying Branch Points

**Finding the validation decision point**

```python
from ida_domain import Database

with Database() as db:
    func = db.functions.get_at(0x401200)
    flowchart = db.functions.get_flowchart(func)

    print("Conditional branches in validate_license:")
    print("-" * 50)

    for block in flowchart:
        successors = list(block.succs())

        # 2 successors = conditional branch
        if len(successors) == 2:
            branch_addr = block.end_ea - 1  # Approximate
            print(f"Branch at ~0x{branch_addr:08x}")
            print(f"  If true:  -> 0x{successors[0].start_ea:08x}")
            print(f"  If false: -> 0x{successors[1].start_ea:08x}")
            print()
```

**Why this matters:**
- The validation function must have at least one key branch
- One path leads to "valid", one to "invalid"
- Finding this branch = finding the patch point

> **Speaker notes:** In a real analysis, you'd look at the instructions at this branch to understand the condition being tested.

---

## Slide 20: Example 6 - Extracting Byte Patterns

**Finding the XOR constant in hash_id**

```python
from ida_domain import Database

with Database() as db:
    # Our suspected hash function
    hash_func = db.functions.get_at(0x401400)

    print(f"Bytes in {hash_func.name}:")
    print()

    # Get the raw bytes of the function
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

> **Speaker notes:** Raw bytes are useful for finding constants, signatures, or implementing pattern matching.

---

## Slide 21: Searching for Patterns

**Finding specific byte sequences**

```python
from ida_domain import Database

with Database() as db:
    # Search for XOR with immediate value (common in hash functions)
    # x86-64: XOR with 32-bit immediate often starts with 0x35 or 0x81 F0

    # Search the entire .text section
    results = db.bytes.search_binary(
        start_ea=db.minimum_ea,
        end_ea=db.maximum_ea,
        pattern="35 ?? ?? ?? ??",  # XOR EAX, imm32
        direction="DOWN"
    )

    print("Found XOR EAX, imm32 instructions:")
    for ea in results:
        # Get the immediate value (bytes 1-4)
        imm_bytes = db.bytes.get_bytes(ea + 1, 4)
        imm_value = int.from_bytes(imm_bytes, 'little')
        print(f"  0x{ea:08x}: XOR EAX, 0x{imm_value:08x}")
```

**Expected output:**
```
Found XOR EAX, imm32 instructions:
  0x00401423: XOR EAX, 0xDEADBEEF
```

> **Speaker notes:** We found the XOR constant! This is exactly what a reverser would need to understand or bypass the hash.

---

## Slide 22: Example 7 - Adding Annotations

**Documenting our findings**

```python
from ida_domain import Database

with Database() as db:
    # Rename functions based on our analysis
    db.names.set_name(0x401100, "main")
    db.names.set_name(0x401050, "get_machine_id")
    db.names.set_name(0x401200, "validate_license")
    db.names.set_name(0x401400, "hash_id")
    db.names.set_name(0x401500, "parse_license_key")
    db.names.set_name(0x401600, "check_trial_status")

    print("Functions renamed!")

    # Add comments at key locations
    db.comments.set_comment(
        0x401423,
        "XOR constant: 0xDEADBEEF - used in hardware fingerprint"
    )

    db.comments.set_comment(
        0x401250,
        "Branch: valid license vs invalid"
    )

    print("Comments added!")
```

> **Speaker notes:** These annotations are saved to the IDB. Next time you open the database, all the analysis is preserved.

---

## Slide 23: Verifying Our Annotations

**Confirming the changes**

```python
from ida_domain import Database

with Database() as db:
    print("Renamed functions:")
    print("-" * 40)

    for func in db.functions:
        # Skip library functions
        if not func.name.startswith("sub_"):
            print(f"  0x{func.start_ea:08x}: {func.name}")

    print()
    print("Comments we added:")
    print("-" * 40)

    for ea in [0x401423, 0x401250]:
        comment = db.comments.get_comment(ea)
        if comment:
            print(f"  0x{ea:08x}: {comment}")
```

**Expected output:**
```
Renamed functions:
----------------------------------------
  0x00401050: get_machine_id
  0x00401100: main
  0x00401200: validate_license
  0x00401400: hash_id
  0x00401500: parse_license_key
  0x00401600: check_trial_status

Comments we added:
----------------------------------------
  0x00401423: XOR constant: 0xDEADBEEF - used in hardware fingerprint
  0x00401250: Branch: valid license vs invalid
```

> **Speaker notes:** The binary is no longer a mystery. We've recovered the structure and documented key insights.

---

## Slide 24: Example 8 - Automated Analysis Report

**Putting it all together**

```python
from ida_domain import Database
from datetime import datetime

def generate_report(db):
    report = []
    report.append("=" * 60)
    report.append("LICENSE CHECKER ANALYSIS REPORT")
    report.append(f"Generated: {datetime.now().isoformat()}")
    report.append("=" * 60)
    report.append("")

    # Summary statistics
    funcs = list(db.functions)
    strings = list(db.strings)
    report.append(f"Total functions: {len(funcs)}")
    report.append(f"Total strings:   {len(strings)}")
    report.append("")

    # Key functions identified
    report.append("KEY FUNCTIONS IDENTIFIED:")
    report.append("-" * 40)
    key_funcs = ["main", "validate_license", "hash_id",
                 "get_machine_id", "check_trial_status"]
    for name in key_funcs:
        for func in funcs:
            if func.name == name:
                report.append(f"  {name}: 0x{func.start_ea:08x}")
                break
    report.append("")

    # License-related strings
    report.append("LICENSE STRINGS:")
    report.append("-" * 40)
    for s in strings:
        if any(kw in s.content.lower() for kw in ["license", "trial"]):
            report.append(f"  0x{s.ea:08x}: {s.content!r}")
    report.append("")

    # Critical findings
    report.append("CRITICAL FINDINGS:")
    report.append("-" * 40)
    report.append("  1. XOR constant in hash_id: 0xDEADBEEF")
    report.append("  2. Validation branch at: 0x00401250")
    report.append("  3. Trial check reads: ~/.license_trial")
    report.append("")

    return "\n".join(report)

with Database() as db:
    report = generate_report(db)
    print(report)

    # Optionally save to file
    with open("/tmp/analysis_report.txt", "w") as f:
        f.write(report)
    print("Report saved to /tmp/analysis_report.txt")
```

> **Speaker notes:** This is a real deliverable you could share with a team or include in a writeup. The script is reusable across similar binaries.

---

# PART 4: WRAP-UP (~8 minutes)

---

## Slide 25: Manual vs Scripted - A Comparison

**What we accomplished**

| Task | Manual | Scripted |
|------|--------|----------|
| Find license strings | ~2 min clicking | 0.5 sec |
| Trace all xrefs | ~5 min per string | 0.5 sec total |
| Map call hierarchy | ~10 min | 1 sec |
| Identify branch points | ~5 min | 0.5 sec |
| Find XOR constants | ~10 min | 1 sec |
| Add all annotations | ~5 min | 1 sec |
| **Total** | **~40 minutes** | **~5 seconds** |

**But more importantly:**
- Scripts are **repeatable** (run on similar binaries)
- Scripts are **shareable** (team knowledge capture)
- Scripts are **accurate** (no missed xrefs)

> **Speaker notes:** The time comparison is dramatic, but emphasize the qualitative benefits too.

---

## Slide 26: When to Use the Domain API

**Decision framework**

| Situation | Use Domain API? |
|-----------|----------------|
| One-off quick check | Maybe not - just click |
| Analyzing multiple similar binaries | **Yes** |
| Building analysis tools/plugins | **Yes** |
| Teaching/documenting RE process | **Yes** |
| Need reproducible analysis | **Yes** |
| Complex data structure recovery | **Yes** |
| Quick prototype before full plugin | **Yes** |

**When to drop to raw IDAPython:**
- Performance-critical inner loops
- Features not yet in Domain API
- Direct manipulation of IDA internals

> **Speaker notes:** The Domain API is a complement, not a replacement. Use the right tool for the job.

---

## Slide 27: Getting Started

**How to begin using the Domain API**

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

**Resources:**
- GitHub: `github.com/hex-rays/ida-domain`
- Documentation: `ida-domain.readthedocs.io`
- Examples: `github.com/hex-rays/ida-domain/examples`

**Practice exercises:**
1. Modify Example 1 to find all URL strings
2. Extend Example 4 to build a full call graph
3. Combine examples into an analysis template

> **Speaker notes:** Encourage them to try these exercises on their own binaries.

---

## Slide 28: Key Takeaways

**What to remember**

1. **One entry point:** `from ida_domain import Database`

2. **Consistent pattern:** `db.<entity>.<action>()`

3. **Everything iterates:** `for x in db.functions`, `for x in db.strings`

4. **Rich objects:** Don't just get addresses, get dataclasses with properties

5. **Context managers:** `with Database() as db:` handles cleanup

6. **Discoverable:** Tab-complete `db.` to see what's available

7. **Incremental adoption:** Use it for new scripts, keep old IDAPython

> **Speaker notes:** These are the mental anchors. If they remember these 7 points, they can figure out the rest.

---

## Slide 29: What's Next

**Continuing your journey**

**Intermediate topics:**
- Using the Decompiler API for pseudocode analysis
- Type manipulation and structure recovery
- Writing IDA plugins with Domain API
- Hooking database events

**Advanced applications:**
- Automated vulnerability finding
- Binary diffing and patch analysis
- Protocol reverse engineering
- Malware family clustering

**This workshop's binary:**
- Try to fully automate the patch identification
- Add support for different license formats
- Detect similar patterns in other binaries

> **Speaker notes:** Give them a path forward. The Domain API scales to much more complex tasks.

---

## Slide 30: Q&A

**Questions?**

Contact:
- Workshop materials: [repo URL]
- IDA Domain API: [repo URL]
- Your email/twitter

**Remember:**
> "The best RE tool is the one that gets out of your way and lets you think about the binary, not the API."

---

# APPENDIX

---

## Appendix A: The Complete Zig Source

```zig
const std = @import("std");
const fs = std.fs;
const mem = std.mem;
const posix = std.posix;

// Constants that will be visible in the binary analysis
const XOR_CONSTANT: u32 = 0xDEADBEEF;
const TRIAL_DAYS: i64 = 30;
const MAGIC_CHECK: u32 = 0x12345678;

pub fn main() !void {
    const stdout = std.fs.File.stdout();
    const writer = stdout.deprecatedWriter();
    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Get machine fingerprint
    const machine_id = getMachineId();
    const fingerprint = hashId(machine_id);

    // Check for license key argument
    if (args.len > 1) {
        const license_key = args[1];
        if (validateLicense(license_key, fingerprint)) {
            try writer.print("License Valid - Full Mode\n", .{});
            return;
        }
    }

    // Fall back to trial check
    if (checkTrialStatus()) |days_left| {
        try writer.print("Trial Mode - {d} days remaining\n", .{days_left});
    } else {
        try writer.print("License Invalid\n", .{});
        std.process.exit(1);
    }
}

fn getMachineId() [16]u8 {
    var buffer: [16]u8 = undefined;
    const file = fs.openFileAbsolute("/etc/machine-id", .{}) catch {
        @memcpy(&buffer, "0000000000000000");
        return buffer;
    };
    defer file.close();

    _ = file.read(&buffer) catch {
        @memcpy(&buffer, "0000000000000000");
        return buffer;
    };
    return buffer;
}

fn hashId(id: [16]u8) u32 {
    var result: u32 = 0;
    for (id) |byte| {
        result = result ^ @as(u32, byte);
        result = std.math.rotl(u32, result, 5);
    }
    return result ^ XOR_CONSTANT;
}

fn parseLicenseKey(key: []const u8) ?u32 {
    if (key.len != 19) return null;

    var result: u32 = 0;
    var hex_count: usize = 0;

    for (key) |c| {
        if (c == '-') continue;
        const digit = std.fmt.charToDigit(c, 16) catch return null;
        result = (result << 4) | @as(u32, digit);
        hex_count += 1;
    }

    if (hex_count != 16) return null;
    return result;
}

fn validateLicense(key: []const u8, fingerprint: u32) bool {
    const parsed = parseLicenseKey(key) orelse return false;
    const check = parsed ^ fingerprint;
    return check == MAGIC_CHECK;
}

fn checkTrialStatus() ?i64 {
    const home = posix.getenv("HOME") orelse return null;

    var path_buf: [256]u8 = undefined;
    const trial_path = std.fmt.bufPrint(&path_buf, "{s}/.license_trial", .{home}) catch return null;

    const file = fs.openFileAbsolute(trial_path, .{}) catch {
        const new_file = fs.createFileAbsolute(trial_path, .{}) catch return null;
        defer new_file.close();

        const timestamp = std.time.timestamp();
        var ts_buf: [20]u8 = undefined;
        const ts_str = std.fmt.bufPrint(&ts_buf, "{d}", .{timestamp}) catch return null;
        new_file.writeAll(ts_str) catch return null;
        return TRIAL_DAYS;
    };
    defer file.close();

    var buf: [20]u8 = undefined;
    const bytes_read = file.readAll(&buf) catch return null;

    const start_time = std.fmt.parseInt(i64, buf[0..bytes_read], 10) catch return null;
    const current_time = std.time.timestamp();
    const days_elapsed = @divFloor(current_time - start_time, 86400);

    if (days_elapsed >= TRIAL_DAYS) {
        return null;
    }
    return TRIAL_DAYS - days_elapsed;
}
```

---

## Appendix B: Build Instructions

```bash
# Save the source as license_checker.zig

# Build for Linux x86-64 with stripping
zig build-exe license_checker.zig \
    -target x86_64-linux \
    -O ReleaseSafe \
    -fno-PIE \
    -fstrip

# Verify
file license_checker
# Should show: ELF 64-bit LSB executable, x86-64, statically linked, stripped

# Size should be ~45KB
ls -lh license_checker

# Test it (on a Linux system or via emulation)
./license_checker
# Should print: License Invalid (or create trial)

./license_checker "AAAA-BBBB-CCCC-DDDD"
# Should print: License Invalid (wrong key)
```

---

## Appendix C: Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│              IDA DOMAIN API QUICK REFERENCE                  │
├─────────────────────────────────────────────────────────────┤
│ SETUP                                                        │
│   from ida_domain import Database                           │
│   with Database() as db:                                    │
│       ...                                                   │
├─────────────────────────────────────────────────────────────┤
│ FUNCTIONS                                                    │
│   for func in db.functions:           # iterate all         │
│   func = db.functions.get_at(ea)      # get by address      │
│   fc = db.functions.get_flowchart(f)  # get basic blocks    │
├─────────────────────────────────────────────────────────────┤
│ CROSS-REFERENCES                                             │
│   db.xrefs.to_ea(ea)                  # refs TO address     │
│   db.xrefs.from_ea(ea)                # refs FROM address   │
│   db.xrefs.calls_to_ea(ea)            # calls only          │
│   xref.is_call, xref.is_jump          # type checks         │
├─────────────────────────────────────────────────────────────┤
│ STRINGS                                                      │
│   for s in db.strings:                # iterate all         │
│   s.ea, s.content, s.length           # properties          │
├─────────────────────────────────────────────────────────────┤
│ BYTES                                                        │
│   db.bytes.get_bytes(ea, size)        # read bytes          │
│   db.bytes.search_binary(...)         # pattern search      │
├─────────────────────────────────────────────────────────────┤
│ NAMES & COMMENTS                                             │
│   db.names.set_name(ea, "name")       # rename              │
│   db.comments.set_comment(ea, "...")  # add comment         │
│   db.comments.get_comment(ea)         # read comment        │
└─────────────────────────────────────────────────────────────┘
```

---

## Appendix D: Common Patterns

**Pattern 1: Find and trace strings**
```python
for s in db.strings:
    if "target" in s.content:
        for xref in db.xrefs.to_ea(s.ea):
            func = db.functions.get_at(xref.from_ea)
            print(f"{s.content} used in {func.name}")
```

**Pattern 2: Map all callers of a function**
```python
def get_callers(db, ea):
    return [
        db.functions.get_at(x.from_ea)
        for x in db.xrefs.calls_to_ea(ea)
    ]
```

**Pattern 3: Find functions by characteristic**
```python
# Functions that don't return
noret_funcs = [f for f in db.functions if f.flags & FunctionFlags.NORET]

# Large functions (>1000 bytes)
large_funcs = [f for f in db.functions if f.end_ea - f.start_ea > 1000]
```

**Pattern 4: Batch annotation**
```python
annotations = {
    0x401000: "main",
    0x401100: "init",
    0x401200: "process",
}
for ea, name in annotations.items():
    db.names.set_name(ea, name)
```

---

*End of presentation materials*
