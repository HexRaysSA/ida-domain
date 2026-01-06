# Workflow-Oriented API Additions Proposal

**Date:** 2025-12-28
**Status:** Draft (Reviewed 2026-01-02)
**Related:** LLM_API_SPECIFICATION.md, tests/workflows/

## Motivation

While writing workflow-oriented integration tests, we identified gaps in the API that make common reverse engineering tasks more verbose than necessary. These additions follow the existing entity-centric pattern and LLM API design principles.

## Design Principles (from LLM_API_SPECIFICATION.md)

1. **Minimal surface** - Fewer methods to remember
2. **Predictable patterns** - Same method names across entities
3. **String literals** - No enums to import (validated at runtime)
4. **Rich returns** - Objects with properties, not primitives
5. **Sensible defaults** - Most parameters optional
6. **Clear naming** - Self-documenting method names

---

## Proposed Additions

### 1. Functions Entity

**File:** `ida_domain/functions.py`

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `get_call_graph` | `[NEW]` | `get_call_graph(func, depth=2, direction="callees") -> CallGraph` | Build call graph from function |
| `find_call_path` | `[NEW]` | `find_call_path(from_func, to_func, max_depth=5, max_paths=10) -> Iterator[CallPath]` | Find call paths between functions |
| `get_metrics` | `[NEW]` | `get_metrics(func) -> FunctionMetrics` | Get complexity metrics |
| `find_by_pattern` | `[NEW]` | `find_by_pattern(pattern) -> Iterator[func_t]` | Find functions by name pattern |

**Rationale:**

- `get_call_graph`: Building call trees is a common workflow (see `test_build_call_tree_from_entry_point`). Currently requires manual BFS traversal combining `get_callees` calls.
- `find_call_path`: Finding how control flows from function A to function B is critical for vulnerability research (tracing input to dangerous sink). Currently requires manual graph traversal.
- `get_metrics`: Complexity analysis is common for identifying crypto/obfuscation. Currently requires manual flowchart iteration.
- `find_by_pattern`: Finding functions by name pattern (e.g., all `*_init` functions) currently requires iterating all functions.

**Review Notes (2026-01-02):**

- `get_call_graph`: Added `direction` parameter with values `"callees"` (default), `"callers"`, or `"both"` to clarify traversal direction. The name "call_graph" implies bidirectional capability.
- `find_call_path`: Moved from Xrefs entity. Call paths are fundamentally about function relationships, not raw cross-references. Renamed from `get_call_chain` to `find_call_path` for clarity.
- `find_by_pattern`: Renamed from `get_by_pattern` to follow `find_*` convention for search operations (consistent with `imports.find_by_name`).

**Return Types:**

```python
@dataclass
class CallGraph:
    root: int  # Root function EA
    depth: int  # How deep the graph goes
    direction: str  # "callees", "callers", or "both"
    nodes: Set[int]  # All function EAs in graph
    edges: Dict[int, Set[int]]  # caller -> set of callees

@dataclass
class CallPath:
    path: List[int]  # List of function EAs in call order

    def __len__(self) -> int: ...
    def __iter__(self) -> Iterator[int]: ...

@dataclass
class FunctionMetrics:
    block_count: int  # Number of basic blocks
    edge_count: int  # Number of control flow edges
    cyclomatic_complexity: int  # McCabe complexity
    instruction_count: int  # Total instructions
```

**Examples:**

```python
# Build call graph from main function
graph = db.functions.get_call_graph(main_func, depth=3, direction="callees")
print(f"Reachable functions: {len(graph.nodes)}")

# Find paths from recv() caller to strcpy() caller
recv_func = db.functions.get_at(db.imports.find_by_name('recv').address)
strcpy_func = db.functions.get_at(db.imports.find_by_name('strcpy').address)
for path in db.functions.find_call_path(recv_func, strcpy_func, max_depth=5):
    print(" -> ".join(hex(ea) for ea in path))
```

---

### 2. Strings Entity

**File:** `ida_domain/strings.py`

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| ~~`get_in_range`~~ | `[EXISTS]` | `get_between(start, end) -> Iterator[StringItem]` | Already implemented |
| `get_referenced_by` | `[NEW]` | `get_referenced_by(func) -> Iterator[StringItem]` | Strings referenced by function |
| `search_by_pattern` | `[NEW]` | `search_by_pattern(pattern, case_sensitive=False) -> Iterator[StringItem]` | Search string contents |

**Rationale:**

- ~~`get_in_range`~~: **Already exists as `get_between(start_ea, end_ea)`** in `strings.py:82-96`. No action needed.
- `get_referenced_by`: Finding strings used by a function is extremely common for malware analysis. Currently requires manual xref traversal.
- `search_by_pattern`: Searching for strings containing keywords (e.g., "password", "http://") is a core workflow.

**Review Notes (2026-01-02):**

- `get_in_range`: Dropped — already exists as `get_between`. Consider whether to alias for naming consistency across entities in a future pass.
- `search_by_pattern`: Renamed from `find` to match `imports.search_by_pattern()` convention.

---

### 3. Bytes Entity

**File:** `ida_domain/bytes.py`

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `find_constants` | `[NEW]` | `find_constants(start, end, values, sizes=[4,8]) -> Iterator[ConstantMatch]` | Find known constants |

**Rationale:**

- `find_constants`: Identifying crypto by magic constants (SHA init values, CRC polynomials) is a standard workflow.

**Return Type:**

```python
@dataclass
class ConstantMatch:
    address: int  # EA where constant was found
    value: int    # The matched value
    size: int     # Size in bytes (4 for dword, 8 for qword)
```

**Example:**
```python
# Find SHA-1 initialization constants
sha1_constants = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
for match in db.bytes.find_constants(start, end, sha1_constants):
    print(f"Found SHA-1 constant {hex(match.value)} at {hex(match.address)} ({match.size} bytes)")
```

**Review Notes (2026-01-02):**

- Changed return type from `Tuple[int, int]` to `ConstantMatch` dataclass to include size information.
- Added `sizes` parameter (default `[4, 8]`) to specify which sizes to search (dword, qword). Same constant may appear at different sizes.

---

### 4. Imports Entity

**File:** `ida_domain/imports.py`

| Method | Status | Signature | Description |
|--------|--------|-----------|-------------|
| `get_callers` | `[NEW]` | `get_callers(entry) -> Iterator[func_t]` | Functions that call this import |

**Rationale:**

- `get_callers`: Finding all functions that use a specific import is extremely common. Currently requires xref traversal.

**Example:**
```python
# Find all functions using CreateFileW
entry = db.imports.find_by_name("CreateFileW")
for func in db.imports.get_callers(entry):
    print(f"{db.functions.get_name(func)} uses CreateFileW")
```

---

## Methods NOT Proposed (Style Violations)

The following were considered but rejected as they violate the entity-centric pattern:

| Rejected | Reason | Correct Alternative |
|----------|--------|---------------------|
| `func.name` property | Methods on returned objects | `db.functions.get_name(func)` ✓ |
| `func.callees` property | Methods on returned objects | `db.functions.get_callees(func)` ✓ |
| `func.get_strings()` | Method on func_t | `db.strings.get_referenced_by(func)` ✓ |
| `db.find_crypto()` | Not on an entity | `db.bytes.find_constants(...)` ✓ |
| `db.callgraph` entity | Derived concept, not IDA primitive | `db.functions.get_call_graph(...)` ✓ |

**Note on CallGraph entity:** A separate `db.callgraph` entity was considered but rejected. Call graph operations are fundamentally about functions, so placing `get_call_graph` and `find_call_path` on the Functions entity maintains cohesion and avoids introducing a new top-level concept for just 2-3 methods. If call graph features grow significantly in the future, this decision can be revisited.

---

## Implementation Priority

| Priority | Method | Workflow Impact | Status |
|----------|--------|-----------------|--------|
| High | `strings.get_referenced_by` | Malware analysis, string hunting | Ready |
| High | `functions.get_call_graph` | Understanding program structure | Ready |
| High | `functions.find_call_path` | Vulnerability research, taint tracking | Ready |
| High | `imports.get_callers` | API usage analysis | Ready |
| Medium | `bytes.find_constants` | Crypto identification | Ready |
| Medium | `functions.get_metrics` | Complexity analysis | Ready |
| Medium | `strings.search_by_pattern` | String content search | Ready |
| Low | `functions.find_by_pattern` | Convenience, can use iteration | Ready |
| — | ~~`strings.get_in_range`~~ | Already exists as `get_between` | Dropped |
| — | ~~`imports.categorize`~~ | Application logic, not core API | Removed |
| — | ~~`xrefs.get_call_chain`~~ | Moved to `functions.find_call_path` | Moved |

---

## Testing

Each new method should have:

1. **Unit tests** in `tests/test_<entity>.py` - validates method works correctly
2. **Workflow tests** in `tests/workflows/` - validates method enables real RE tasks

The workflow tests in `tests/workflows/test_workflow_examples.py` demonstrate the use cases these methods would simplify.

---

## Review Summary (2026-01-02)

### Key Findings

1. **`strings.get_in_range` dropped** — Already exists as `get_between(start_ea, end_ea)` in `strings.py:82-96`.

2. **Naming consistency improvements:**
   - `functions.get_by_pattern` → `functions.find_by_pattern` (matches `find_*` search convention)
   - `strings.find` → `strings.search_by_pattern` (matches `imports.search_by_pattern`)

3. **Enhanced signatures:**
   - `get_call_graph`: Added `direction` parameter (`"callees"`, `"callers"`, `"both"`)
   - `find_constants`: Changed return to `ConstantMatch` dataclass with size info; added `sizes` param
   - `find_call_path`: Added `max_paths` limit; returns `Iterator[CallPath]`

4. **`imports.categorize` removed** — Application-level logic, not suitable for core API.

5. **`xrefs.get_call_chain` moved to Functions** — Call paths are about function relationships, not raw xrefs. Renamed to `find_call_path` and placed on Functions entity for cohesion with `get_call_graph`.

### Ready for Implementation (8 methods)

| Entity | Method | Notes |
|--------|--------|-------|
| Functions | `get_call_graph` | With direction param |
| Functions | `find_call_path` | Moved from Xrefs, renamed |
| Functions | `get_metrics` | As designed |
| Functions | `find_by_pattern` | Renamed |
| Strings | `get_referenced_by` | As designed |
| Strings | `search_by_pattern` | Renamed |
| Bytes | `find_constants` | With ConstantMatch return |
| Imports | `get_callers` | As designed |
