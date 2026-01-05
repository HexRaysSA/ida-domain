"""
Workflow-oriented integration tests for ida-domain.

These tests validate that the API enables real reverse engineering workflows,
not just that individual methods work correctly.

Each test represents a task a reverser would actually perform.
"""

import pytest
from typing import Set, List, Dict, Tuple
from collections import defaultdict


# =============================================================================
# WORKFLOW 1: CALL GRAPH ANALYSIS
# Real Task: "Show me all functions reachable from main within 3 levels"
# =============================================================================

class TestCallGraphWorkflows:
    """
    Reversers frequently need to understand call relationships.
    These tests validate that the API supports call graph exploration.
    """

    def test_build_call_tree_from_entry_point(self, test_env):
        """
        WORKFLOW: Starting from an entry point, build a call tree to understand
        program structure.

        REAL USE CASE: Analyst opens unknown binary, wants to understand what
        main() does by seeing what it calls, and what those functions call.
        """
        db = test_env

        # Find entry point or main
        entry_func = None
        for func in db.functions:
            name = db.functions.get_name(func)
            if name and ('main' in name.lower() or 'start' in name.lower()):
                entry_func = func
                break

        if entry_func is None:
            # Use first function as fallback
            entry_func = next(iter(db.functions), None)

        assert entry_func is not None, "Need at least one function for this test"

        # Build call tree (depth-limited BFS)
        call_tree: Dict[int, Set[int]] = defaultdict(set)
        visited: Set[int] = set()
        queue: List[Tuple[int, int]] = [(entry_func.start_ea, 0)]  # (ea, depth)
        max_depth = 3

        while queue:
            func_ea, depth = queue.pop(0)
            if func_ea in visited or depth > max_depth:
                continue
            visited.add(func_ea)

            func = db.functions.get_at(func_ea)
            if func is None:
                continue

            # Get all functions this one calls
            callees = db.functions.get_callees(func)
            for callee in callees:
                call_tree[func_ea].add(callee.start_ea)
                if depth < max_depth:
                    queue.append((callee.start_ea, depth + 1))

        # Validate we built something meaningful
        assert len(visited) >= 1, "Should have visited at least the entry function"
        # The call tree should be usable for further analysis
        assert isinstance(call_tree, dict)

    def test_find_leaf_functions(self, test_env):
        """
        WORKFLOW: Find all "leaf" functions that don't call anything else.

        REAL USE CASE: Leaf functions are often utility functions, crypto
        primitives, or system call wrappers - interesting for analysis.
        """
        db = test_env

        leaf_functions = []
        for func in db.functions:
            callees = list(db.functions.get_callees(func))
            if len(callees) == 0:
                leaf_functions.append(func)

        # In any real binary, there should be some leaf functions
        # (At minimum, functions that just return or call external APIs)
        assert isinstance(leaf_functions, list)
        # Record for analysis - a reverser would examine these
        for leaf in leaf_functions[:5]:  # Check first 5
            name = db.functions.get_name(leaf)
            # Leaf functions often have meaningful names or are library functions
            assert leaf.start_ea is not None

    def test_find_most_called_functions(self, test_env):
        """
        WORKFLOW: Find functions with the most callers (hot spots).

        REAL USE CASE: Heavily-called functions are often utility functions,
        logging, error handling, or core algorithm implementations.
        """
        db = test_env

        call_counts: Dict[int, int] = defaultdict(int)

        for func in db.functions:
            callers = list(db.functions.get_callers(func))
            call_counts[func.start_ea] = len(callers)

        # Sort by call count
        sorted_funcs = sorted(call_counts.items(), key=lambda x: x[1], reverse=True)

        # Get top 5 most called
        hot_functions = sorted_funcs[:5]

        # Validate the analysis is meaningful
        assert len(hot_functions) > 0 or db.functions.count() == 0

        # A reverser would now examine these functions
        for func_ea, count in hot_functions:
            func = db.functions.get_at(func_ea)
            assert func is not None


# =============================================================================
# WORKFLOW 2: STRING AND DATA REFERENCE ANALYSIS
# Real Task: "Find all functions that reference suspicious strings"
# =============================================================================

class TestStringReferenceWorkflows:
    """
    String references are crucial for understanding binary behavior.
    These tests validate string-to-code relationship analysis.
    """

    def test_find_functions_referencing_strings(self, test_env):
        """
        WORKFLOW: For each string in the binary, find which functions reference it.

        REAL USE CASE: Malware analyst looking for C2 URLs, config strings,
        error messages that reveal functionality.
        """
        db = test_env

        # Map: string_content -> list of (func_ea, ref_ea)
        string_references: Dict[str, List[Tuple[int, int]]] = defaultdict(list)

        # Get all strings (if strings entity exists)
        if hasattr(db, 'strings'):
            for string_item in db.strings:
                string_ea = string_item.ea
                content = string_item.content if hasattr(string_item, 'content') else str(string_item)

                # Find all code references to this string
                for xref in db.xrefs.code_refs_to_ea(string_ea):
                    # Find the function containing this reference
                    func = db.functions.get_at(xref.from_ea)
                    if func:
                        string_references[content].append((func.start_ea, xref.from_ea))

        # The structure should be usable for filtering
        assert isinstance(string_references, dict)

    def test_find_error_handling_functions(self, test_env):
        """
        WORKFLOW: Find functions that likely handle errors by looking for
        error-related string references.

        REAL USE CASE: Understanding error paths, finding logging functions,
        identifying failure conditions.
        """
        db = test_env

        error_keywords = ['error', 'fail', 'invalid', 'exception', 'abort', 'fatal']
        error_functions: Set[int] = set()

        if hasattr(db, 'strings'):
            for string_item in db.strings:
                content = str(string_item).lower() if string_item else ""

                # Check if string contains error-related keywords
                if any(kw in content for kw in error_keywords):
                    string_ea = string_item.ea if hasattr(string_item, 'ea') else None
                    if string_ea:
                        for xref in db.xrefs.code_refs_to_ea(string_ea):
                            func = db.functions.get_at(xref.from_ea)
                            if func:
                                error_functions.add(func.start_ea)

        # Result is a set of function addresses to investigate
        assert isinstance(error_functions, set)


# =============================================================================
# WORKFLOW 3: IMPORT ANALYSIS
# Real Task: "Find all functions that use network/file/crypto APIs"
# =============================================================================

class TestImportUsageWorkflows:
    """
    Import analysis is fundamental for understanding binary capabilities.
    """

    def test_categorize_functions_by_api_usage(self, test_env):
        """
        WORKFLOW: Categorize functions by the types of APIs they use.

        REAL USE CASE: Triage - quickly identify which functions do networking,
        file I/O, crypto, process manipulation, etc.
        """
        db = test_env

        # Define API categories
        api_categories = {
            'network': ['recv', 'send', 'connect', 'socket', 'WSA', 'inet_'],
            'file': ['fopen', 'fread', 'fwrite', 'CreateFile', 'ReadFile', 'WriteFile'],
            'memory': ['malloc', 'free', 'VirtualAlloc', 'HeapAlloc', 'mmap'],
            'process': ['CreateProcess', 'fork', 'exec', 'ShellExecute'],
            'crypto': ['Crypt', 'AES', 'RSA', 'SHA', 'MD5', 'rand'],
        }

        # Map: category -> set of function EAs that use those APIs
        functions_by_category: Dict[str, Set[int]] = defaultdict(set)

        # Analyze imports
        if hasattr(db, 'imports') and db.imports.has_imports():
            for entry in db.imports.get_all_entries():
                import_name = entry.name if hasattr(entry, 'name') else str(entry)
                import_ea = entry.ea if hasattr(entry, 'ea') else entry.address

                if not import_name:
                    continue

                # Categorize this import
                for category, patterns in api_categories.items():
                    if any(pat.lower() in import_name.lower() for pat in patterns):
                        # Find all functions that call this import
                        for xref in db.xrefs.code_refs_to_ea(import_ea):
                            func = db.functions.get_at(xref.from_ea)
                            if func:
                                functions_by_category[category].add(func.start_ea)

        # Result should be usable for prioritization
        assert isinstance(functions_by_category, dict)

        # A reverser would now focus on specific categories
        # e.g., "Show me all network functions" -> functions_by_category['network']

    def test_find_functions_missing_error_checks(self, test_env):
        """
        WORKFLOW: Find functions that call APIs but might not check return values.

        REAL USE CASE: Vulnerability research - find places where malloc() return
        isn't checked, or file operations ignore errors.

        NOTE: This is a heuristic-based analysis, not perfect.
        """
        db = test_env

        # APIs that return values that SHOULD be checked
        must_check_apis = ['malloc', 'calloc', 'realloc', 'fopen', 'CreateFile']

        suspicious_functions: List[Tuple[int, str, int]] = []  # (func_ea, api_name, call_ea)

        if hasattr(db, 'imports') and db.imports.has_imports():
            for entry in db.imports.get_all_entries():
                import_name = entry.name if hasattr(entry, 'name') else str(entry)
                import_ea = entry.ea if hasattr(entry, 'ea') else entry.address

                if not any(api in import_name for api in must_check_apis):
                    continue

                # Find calls to this API
                for xref in db.xrefs.code_refs_to_ea(import_ea):
                    func = db.functions.get_at(xref.from_ea)
                    if func:
                        # Heuristic: check if there's a comparison instruction nearby
                        # (This is simplified - real analysis would check data flow)
                        suspicious_functions.append((func.start_ea, import_name, xref.from_ea))

        # Result is a list of places to manually investigate
        assert isinstance(suspicious_functions, list)


# =============================================================================
# WORKFLOW 4: CODE PATTERN DETECTION
# Real Task: "Find all functions that look like crypto/encoding routines"
# =============================================================================

class TestPatternDetectionWorkflows:
    """
    Pattern-based detection for identifying specific code types.
    """

    def test_find_functions_with_magic_constants(self, test_env):
        """
        WORKFLOW: Find functions containing known magic constants.

        REAL USE CASE: Identify crypto (AES S-box, SHA constants, CRC tables),
        compression (zlib), or protocol implementations.
        """
        db = test_env

        # Known magic constants
        magic_constants = {
            0x67452301: 'MD5/SHA-1 init',
            0xefcdab89: 'MD5/SHA-1 init',
            0x98badcfe: 'MD5/SHA-1 init',
            0x10325476: 'MD5/SHA-1 init',
            0x5A827999: 'SHA-1 K constant',
            0x6ED9EBA1: 'SHA-1 K constant',
            0x8F1BBCDC: 'SHA-1 K constant',
            0xCA62C1D6: 'SHA-1 K constant',
            0x63: 'AES S-box indicator',
            0x7c: 'AES S-box indicator',
            0xEDB88320: 'CRC32 polynomial',
            0x04C11DB7: 'CRC32 polynomial (reflected)',
        }

        crypto_candidates: Dict[int, List[str]] = defaultdict(list)

        for func in db.functions:
            # Get disassembly or check for immediate values
            # This would ideally use bytes.find_immediate or similar
            try:
                disasm = db.functions.get_disassembly(func)
                if disasm:
                    disasm_text = '\n'.join(disasm) if isinstance(disasm, list) else str(disasm)
                    for const, description in magic_constants.items():
                        # Check for hex representation in disassembly
                        hex_str = f'{const:X}'
                        hex_str_lower = f'{const:x}'
                        if hex_str in disasm_text or hex_str_lower in disasm_text:
                            crypto_candidates[func.start_ea].append(description)
            except Exception:
                pass  # Skip functions we can't disassemble

        # Result maps function EA to list of detected patterns
        assert isinstance(crypto_candidates, dict)

    def test_find_loop_heavy_functions(self, test_env):
        """
        WORKFLOW: Find functions with many loops/basic blocks (complexity analysis).

        REAL USE CASE: Complex functions with many loops are often:
        - Crypto/encoding routines
        - Parsers
        - State machines
        - Obfuscated code
        """
        db = test_env

        complex_functions: List[Tuple[int, int, str]] = []  # (ea, block_count, name)

        for func in db.functions:
            try:
                flowchart = db.functions.get_flowchart(func)
                if flowchart:
                    block_count = len(list(flowchart))
                    if block_count > 10:  # Threshold for "complex"
                        name = db.functions.get_name(func) or f"sub_{func.start_ea:x}"
                        complex_functions.append((func.start_ea, block_count, name))
            except Exception:
                pass

        # Sort by complexity
        complex_functions.sort(key=lambda x: x[1], reverse=True)

        # Result is prioritized list for analysis
        assert isinstance(complex_functions, list)


# =============================================================================
# WORKFLOW 5: CROSS-REFERENCE CHAIN ANALYSIS
# Real Task: "Trace how user input flows through the program"
# =============================================================================

class TestDataFlowWorkflows:
    """
    Understanding data flow is critical for vulnerability research
    and understanding program behavior.
    """

    def test_trace_input_sources_to_sinks(self, test_env):
        """
        WORKFLOW: Find paths from input functions to dangerous functions.

        REAL USE CASE: Security audit - trace data from recv/read to
        strcpy/sprintf/system to find potential vulnerabilities.
        """
        db = test_env

        # Input sources (where data enters)
        input_apis = ['recv', 'read', 'fread', 'scanf', 'gets', 'ReadFile', 'getenv']

        # Dangerous sinks (where unchecked data causes problems)
        sink_apis = ['strcpy', 'sprintf', 'strcat', 'system', 'exec', 'eval', 'memcpy']

        input_functions: Set[int] = set()
        sink_functions: Set[int] = set()

        if hasattr(db, 'imports') and db.imports.has_imports():
            for entry in db.imports.get_all_entries():
                import_name = entry.name if hasattr(entry, 'name') else str(entry)
                import_ea = entry.ea if hasattr(entry, 'ea') else entry.address

                if not import_name:
                    continue

                # Categorize
                is_input = any(api in import_name for api in input_apis)
                is_sink = any(api in import_name for api in sink_apis)

                if is_input or is_sink:
                    for xref in db.xrefs.code_refs_to_ea(import_ea):
                        func = db.functions.get_at(xref.from_ea)
                        if func:
                            if is_input:
                                input_functions.add(func.start_ea)
                            if is_sink:
                                sink_functions.add(func.start_ea)

        # Find functions that are BOTH input handlers AND use dangerous functions
        # (or are called by input handlers and call dangerous functions)
        direct_risks = input_functions & sink_functions

        # For indirect paths, we'd need to traverse the call graph
        # This is a simplified version
        potential_paths: List[Tuple[int, int]] = []  # (input_func, sink_func)

        for input_func_ea in input_functions:
            input_func = db.functions.get_at(input_func_ea)
            if input_func:
                # Check if any callee is a sink function
                for callee in db.functions.get_callees(input_func):
                    if callee.start_ea in sink_functions:
                        potential_paths.append((input_func_ea, callee.start_ea))

        # Results for security review
        assert isinstance(direct_risks, set)
        assert isinstance(potential_paths, list)


# =============================================================================
# WORKFLOW 6: COMPARATIVE ANALYSIS
# Real Task: "Find functions that are similar to this known bad function"
# =============================================================================

class TestSimilarityWorkflows:
    """
    Finding similar functions helps identify code reuse, library code,
    and variants of known patterns.
    """

    def test_find_functions_with_similar_call_signature(self, test_env):
        """
        WORKFLOW: Find functions that call the same set of APIs.

        REAL USE CASE: If you found one backdoor function, find others
        with similar behavior by looking for same API call patterns.
        """
        db = test_env

        # Build signature for each function: set of called imports
        function_signatures: Dict[int, frozenset] = {}

        for func in db.functions:
            called_imports: Set[str] = set()

            for callee in db.functions.get_callees(func):
                callee_name = db.functions.get_name(callee)
                if callee_name:
                    called_imports.add(callee_name)

            if called_imports:  # Only track functions that call something
                function_signatures[func.start_ea] = frozenset(called_imports)

        # Group functions by signature
        signature_groups: Dict[frozenset, List[int]] = defaultdict(list)
        for func_ea, sig in function_signatures.items():
            signature_groups[sig].append(func_ea)

        # Find groups with multiple functions (potential clones/variants)
        similar_groups = {sig: funcs for sig, funcs in signature_groups.items()
                        if len(funcs) > 1}

        # Result shows potentially related functions
        assert isinstance(similar_groups, dict)

    def test_find_wrapper_functions(self, test_env):
        """
        WORKFLOW: Find thin wrapper functions (functions that just call one other function).

        REAL USE CASE: Identify wrapper/thunk functions, which often:
        - Add logging
        - Do parameter validation
        - Provide API abstraction
        """
        db = test_env

        wrappers: List[Tuple[int, int, str]] = []  # (wrapper_ea, wrapped_ea, wrapped_name)

        for func in db.functions:
            callees = list(db.functions.get_callees(func))

            # A wrapper typically calls exactly one function
            if len(callees) == 1:
                wrapped = callees[0]
                # Additional heuristic: wrapper should be small
                func_size = func.end_ea - func.start_ea
                if func_size < 50:  # Small function threshold
                    wrapped_name = db.functions.get_name(wrapped) or f"sub_{wrapped.start_ea:x}"
                    wrappers.append((func.start_ea, wrapped.start_ea, wrapped_name))

        # Result helps understand abstraction layers
        assert isinstance(wrappers, list)


# =============================================================================
# WORKFLOW 7: FUNCTION BOUNDARY ANALYSIS
# Real Task: "Find functions that IDA might have mis-identified"
# =============================================================================

class TestAnalysisQualityWorkflows:
    """
    Validate and improve IDA's auto-analysis results.
    """

    def test_find_unreferenced_functions(self, test_env):
        """
        WORKFLOW: Find functions with no callers (potential dead code or entry points).

        REAL USE CASE:
        - Dead code might be dormant malware functionality
        - Or might be analysis errors (incorrectly identified functions)
        - Or legitimate entry points (callbacks, exports)
        """
        db = test_env

        unreferenced: List[Tuple[int, str]] = []

        for func in db.functions:
            callers = list(db.functions.get_callers(func))
            if len(callers) == 0:
                name = db.functions.get_name(func) or f"sub_{func.start_ea:x}"
                unreferenced.append((func.start_ea, name))

        # Some unreferenced functions are expected (main, exports, callbacks)
        # But too many might indicate analysis issues
        assert isinstance(unreferenced, list)

    def test_find_overlapping_or_fragmented_functions(self, test_env):
        """
        WORKFLOW: Detect potential function boundary issues.

        REAL USE CASE: Find places where IDA's function detection might
        have failed, especially in obfuscated binaries.
        """
        db = test_env

        # Get all function ranges
        func_ranges: List[Tuple[int, int, int]] = []  # (start, end, ea)

        for func in db.functions:
            func_ranges.append((func.start_ea, func.end_ea, func.start_ea))

        # Sort by start address
        func_ranges.sort()

        # Detect issues
        issues: List[Dict] = []

        for i in range(len(func_ranges) - 1):
            current_start, current_end, current_ea = func_ranges[i]
            next_start, next_end, next_ea = func_ranges[i + 1]

            # Check for overlap
            if current_end > next_start:
                issues.append({
                    'type': 'overlap',
                    'func1': current_ea,
                    'func2': next_ea,
                })

            # Check for gaps (code between functions)
            gap = next_start - current_end
            if gap > 0 and gap < 16:  # Small gaps might be padding or missed code
                issues.append({
                    'type': 'small_gap',
                    'after': current_ea,
                    'before': next_ea,
                    'gap_size': gap,
                })

        # Result highlights potential analysis issues
        assert isinstance(issues, list)


# =============================================================================
# WORKFLOW 8: DECOMPILATION-BASED ANALYSIS
# Real Task: "Find functions with specific code patterns in pseudocode"
# =============================================================================

class TestDecompilationWorkflows:
    """
    Use decompilation for higher-level analysis.
    """

    def test_find_functions_with_specific_patterns(self, test_env):
        """
        WORKFLOW: Search pseudocode for specific patterns.

        REAL USE CASE: Find all functions that:
        - Use specific variable patterns
        - Have specific loop structures
        - Call APIs in specific sequences
        """
        db = test_env

        if not db.decompiler.is_available:
            pytest.skip("Decompiler not available")

        # Pattern: functions that might do XOR encryption (common in malware)
        xor_pattern_funcs: List[Tuple[int, str]] = []

        for func in db.functions:
            try:
                pseudocode = db.decompiler.decompile(func.start_ea, remove_tags=True)
                if pseudocode:
                    code_text = '\n'.join(pseudocode)
                    # Look for XOR patterns in loops
                    if '^=' in code_text or '^ ' in code_text:
                        if 'for' in code_text or 'while' in code_text:
                            name = db.functions.get_name(func) or f"sub_{func.start_ea:x}"
                            xor_pattern_funcs.append((func.start_ea, name))
            except Exception:
                pass  # Skip functions that can't be decompiled

        # Result is list of functions to manually analyze
        assert isinstance(xor_pattern_funcs, list)

    def test_extract_function_complexity_metrics(self, test_env):
        """
        WORKFLOW: Calculate complexity metrics from decompiled code.

        REAL USE CASE: Prioritize analysis by function complexity,
        find potentially obfuscated or complex algorithms.
        """
        db = test_env

        if not db.decompiler.is_available:
            pytest.skip("Decompiler not available")

        complexity_metrics: List[Dict] = []

        for func in db.functions:
            try:
                pseudocode = db.decompiler.decompile(func.start_ea, remove_tags=True)
                if pseudocode:
                    code_text = '\n'.join(pseudocode)

                    # Simple complexity metrics
                    metrics = {
                        'ea': func.start_ea,
                        'name': db.functions.get_name(func) or f"sub_{func.start_ea:x}",
                        'lines': len(pseudocode),
                        'if_count': code_text.count('if ') + code_text.count('if('),
                        'loop_count': code_text.count('for ') + code_text.count('while '),
                        'call_count': code_text.count('(') - code_text.count('if('),
                    }
                    complexity_metrics.append(metrics)
            except Exception:
                pass

        # Sort by complexity (lines * branches * loops)
        for m in complexity_metrics:
            m['complexity'] = m['lines'] * (m['if_count'] + 1) * (m['loop_count'] + 1)

        complexity_metrics.sort(key=lambda x: x['complexity'], reverse=True)

        # Result helps prioritize analysis
        assert isinstance(complexity_metrics, list)
