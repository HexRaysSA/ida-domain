# IDA Domain API Workshop Materials

This directory contains materials for the "Practical Binary Analysis with the IDA Domain API" workshop.

## Contents

### Sample Binary

- `license_checker.zig` - Source code for the analysis target

**Build instructions:**
```bash
# Compile for Linux x86-64 with symbols stripped
zig build-exe license_checker.zig -target x86_64-linux -O ReleaseSafe -fno-PIE -fstrip

# Result: ~45KB stripped ELF executable
```

### Analysis Scripts

Run these in order within IDA to follow the workshop progression:

| Script | Purpose |
|--------|---------|
| `01_find_strings.py` | Find license-related strings in the binary |
| `02_trace_xrefs.py` | Trace cross-references to those strings |
| `03_identify_functions.py` | Map code addresses to function boundaries |
| `04_call_graph.py` | Build and visualize the call hierarchy |
| `05_control_flow.py` | Analyze basic blocks and branch points |
| `06_byte_patterns.py` | Search for XOR constants and magic values |
| `07_annotate.py` | Rename functions and add comments |
| `08_full_report.py` | Generate a complete analysis report |

### Running the Scripts

1. Load the stripped `license_checker` binary in IDA
2. Wait for auto-analysis to complete
3. Open File → Script file... (Alt+F7)
4. Run each script in sequence

Or from the IDA Python console:
```python
exec(open("/path/to/workshop/01_find_strings.py").read())
```

## Workshop Presentation

The full slide outline is available at:
`docs/plans/2025-12-27-ida-domain-api-workshop-presentation.md`

## Prerequisites

- IDA Pro 9.1.0 or later
- ida-domain package installed (`pip install ida-domain`)
- Zig compiler (for building the sample binary)
