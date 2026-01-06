#!/usr/bin/env python3
"""
Auto-generate ida-domain skill reference documentation from source code.

This script parses the ida-domain source using AST (no runtime needed)
and generates reference markdown files (api-handlers.md, enums-types.md).
The main SKILL.md is maintained manually.

Usage:
    python generate_skill_docs.py [--ida-domain-path PATH] [--output-dir DIR]

If --ida-domain-path not provided, tries to clone from GitHub to temp dir.
"""

import argparse
import ast
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class MethodInfo:
    name: str
    signature: str
    returns: str
    docstring: str = ""
    is_property: bool = False


@dataclass
class EnumValue:
    name: str
    description: str = ""


@dataclass
class EnumInfo:
    name: str
    module: str
    values: list[EnumValue] = field(default_factory=list)
    docstring: str = ""


@dataclass
class HandlerInfo:
    name: str
    class_name: str
    purpose: str = ""
    methods: list[MethodInfo] = field(default_factory=list)
    supports_iteration: bool = False
    iteration_type: str = ""


def get_ida_domain_source(path: str | None) -> Path:
    """Get the ida-domain source, cloning if necessary."""
    if path:
        p = Path(path)
        if p.exists():
            return p
        raise ValueError(f"Path does not exist: {path}")

    # Try current directory
    cwd = Path.cwd()
    if (cwd / "ida_domain").exists():
        return cwd

    # Clone to temp directory
    print("Cloning ida-domain from GitHub...")
    temp_dir = Path(tempfile.mkdtemp(prefix="ida-domain-"))
    subprocess.run(
        ["git", "clone", "--depth", "1",
         "https://github.com/hex-rays/ida-domain.git", str(temp_dir)],
        check=True,
        capture_output=True
    )
    return temp_dir


def parse_python_file(filepath: Path) -> ast.Module:
    """Parse a Python file and return its AST."""
    with open(filepath, 'r') as f:
        return ast.parse(f.read(), filename=str(filepath))


def extract_docstring(node: ast.AST) -> str:
    """Extract docstring from an AST node."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        if (node.body and isinstance(node.body[0], ast.Expr) and
                isinstance(node.body[0].value, ast.Constant) and
                isinstance(node.body[0].value.value, str)):
            return node.body[0].value.value.strip()
    return ""


def get_return_annotation(node: ast.FunctionDef) -> str:
    """Extract return type annotation as string."""
    if node.returns:
        return ast.unparse(node.returns)
    return ""


def get_function_signature(node: ast.FunctionDef) -> str:
    """Build a simplified signature string."""
    args = []
    for arg in node.args.args:
        if arg.arg == 'self':
            continue
        arg_str = arg.arg
        if arg.annotation:
            arg_str += f": {ast.unparse(arg.annotation)}"
        args.append(arg_str)

    # Add defaults
    num_defaults = len(node.args.defaults)
    if num_defaults:
        offset = len(args) - num_defaults
        for i, default in enumerate(node.args.defaults):
            default_val = ast.unparse(default)
            args[offset + i] += f"={default_val}"

    return f"({', '.join(args)})"


def extract_enum_values(class_node: ast.ClassDef) -> list[EnumValue]:
    """Extract enum values from a class definition."""
    values = []
    for node in class_node.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.isupper():
                    values.append(EnumValue(name=target.id))
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                values.append(EnumValue(name=node.target.id))
    return values


def extract_class_methods(class_node: ast.ClassDef) -> list[MethodInfo]:
    """Extract public methods from a class."""
    methods = []
    for node in class_node.body:
        if isinstance(node, ast.FunctionDef):
            # Skip private methods
            if node.name.startswith('_') and not node.name.startswith('__'):
                continue
            # Skip dunder methods except __iter__
            if node.name.startswith('__') and node.name != '__iter__':
                continue

            is_property = any(
                isinstance(d, ast.Name) and d.id == 'property'
                for d in node.decorator_list
            )

            methods.append(MethodInfo(
                name=node.name,
                signature=get_function_signature(node),
                returns=get_return_annotation(node),
                docstring=extract_docstring(node),
                is_property=is_property
            ))
    return methods


def find_handlers_in_database(db_path: Path) -> dict[str, str]:
    """Find all handler properties in database.py."""
    tree = parse_python_file(db_path / "ida_domain" / "database.py")
    handlers = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "Database":
            for item in node.body:
                if isinstance(item, ast.FunctionDef):
                    # Check if it's a property
                    is_property = any(
                        isinstance(d, ast.Name) and d.id == 'property'
                        for d in item.decorator_list
                    )
                    if is_property:
                        # Get return type to find handler class
                        ret = get_return_annotation(item)
                        if ret and ret not in ('str', 'int', 'bool', 'float'):
                            handlers[item.name] = ret
    return handlers


def analyze_handler_file(filepath: Path, handler_name: str) -> HandlerInfo | None:
    """Analyze a handler file and extract its API."""
    if not filepath.exists():
        return None

    tree = parse_python_file(filepath)

    # Expected class names for handlers
    expected_class_names = [
        handler_name.title().replace('_', ''),  # e.g., functions -> Functions
        handler_name.title().replace('_', '') + 's',  # in case singular
        handler_name.replace('_', ' ').title().replace(' ', ''),  # e.g., stack_frames -> StackFrames
    ]

    # Find all classes and look for the handler class
    all_classes = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            all_classes.append(node)

    # Try to find the best matching class
    handler_class = None

    # First, look for exact name match
    for cls in all_classes:
        if cls.name in expected_class_names:
            handler_class = cls
            break

    # If not found, look for class inheriting from DatabaseEntity
    if not handler_class:
        for cls in all_classes:
            for base in cls.bases:
                base_name = ast.unparse(base)
                if 'DatabaseEntity' in base_name or 'Entity' in base_name:
                    handler_class = cls
                    break
            if handler_class:
                break

    # If still not found, take the largest class (most methods)
    if not handler_class and all_classes:
        handler_class = max(all_classes, key=lambda c: len([
            n for n in c.body if isinstance(n, ast.FunctionDef)
        ]))

    if not handler_class:
        return None

    methods = extract_class_methods(handler_class)
    has_iter = any(m.name == '__iter__' for m in methods)

    return HandlerInfo(
        name=handler_name,
        class_name=handler_class.name,
        purpose=extract_docstring(handler_class),
        methods=[m for m in methods if m.name != '__iter__'],
        supports_iteration=has_iter
    )


def extract_enums_from_file(filepath: Path, module_name: str) -> list[EnumInfo]:
    """Extract all Enum classes from a file."""
    if not filepath.exists():
        return []

    tree = parse_python_file(filepath)
    enums = []

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            # Check if it inherits from Enum, Flag, IntEnum, etc.
            for base in node.bases:
                base_name = ast.unparse(base)
                if 'Enum' in base_name or 'Flag' in base_name:
                    values = extract_enum_values(node)
                    enums.append(EnumInfo(
                        name=node.name,
                        module=module_name,
                        values=values,
                        docstring=extract_docstring(node)
                    ))
                    break
    return enums


def generate_handlers_markdown(handlers: list[HandlerInfo]) -> str:
    """Generate the api-handlers.md content."""
    lines = [
        "# IDA Domain API Handlers Reference",
        "",
        "Auto-generated from source code. Do not edit manually.",
        "",
        "---",
        ""
    ]

    for handler in sorted(handlers, key=lambda h: h.name):
        lines.append(f"## {handler.name.title().replace('_', ' ')}")
        lines.append("")
        lines.append(f"`db.{handler.name}` - {handler.purpose.split('.')[0] if handler.purpose else 'Handler'}")
        lines.append("")

        if handler.supports_iteration:
            lines.append(f"**Iteration**: `for item in db.{handler.name}`")
            lines.append("")

        lines.append("| Method | Returns | Description |")
        lines.append("|--------|---------|-------------|")

        for method in sorted(handler.methods, key=lambda m: m.name):
            desc = method.docstring.split('\n')[0] if method.docstring else ""
            desc = desc.replace('|', '\\|')[:60]
            sig = f"`{method.name}{method.signature}`" if not method.is_property else f"`{method.name}` (property)"
            ret = method.returns or "None"
            lines.append(f"| {sig} | `{ret}` | {desc} |")

        lines.append("")
        lines.append("---")
        lines.append("")

    return '\n'.join(lines)


def generate_enums_markdown(enums: list[EnumInfo]) -> str:
    """Generate the enums-types.md content."""
    lines = [
        "# IDA Domain Enums and Types Reference",
        "",
        "Auto-generated from source code. Do not edit manually.",
        "",
        "---",
        ""
    ]

    for enum in sorted(enums, key=lambda e: e.name):
        lines.append(f"## {enum.name}")
        lines.append("")
        lines.append(f"```python")
        lines.append(f"from ida_domain.{enum.module} import {enum.name}")
        lines.append(f"```")
        lines.append("")

        if enum.docstring:
            lines.append(enum.docstring.split('\n')[0])
            lines.append("")

        lines.append("| Value | Description |")
        lines.append("|-------|-------------|")

        for value in enum.values:
            lines.append(f"| `{enum.name}.{value.name}` | {value.description} |")

        lines.append("")
        lines.append("---")
        lines.append("")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description="Generate ida-domain skill docs")
    parser.add_argument("--ida-domain-path", type=str, help="Path to ida-domain source")
    parser.add_argument("--output-dir", type=str, help="Output directory for skill files")
    args = parser.parse_args()

    # Get source
    source_path = get_ida_domain_source(args.ida_domain_path)
    ida_domain_path = source_path / "ida_domain"

    print(f"Using source at: {source_path}")

    # Output directory
    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        output_dir = Path(__file__).parent
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "references").mkdir(exist_ok=True)

    # Find all handlers
    print("Analyzing database.py for handlers...")
    handler_map = find_handlers_in_database(source_path)
    print(f"Found {len(handler_map)} handlers")

    # Analyze each handler
    handlers = []
    handler_files = {
        'functions': 'functions.py',
        'instructions': 'instructions.py',
        'xrefs': 'xrefs.py',
        'callgraph': 'callgraph.py',
        'decompiler': 'decompiler.py',
        'bytes': 'bytes_.py',  # Note: bytes_.py to avoid conflict with builtin
        'strings': 'strings.py',
        'names': 'names.py',
        'comments': 'comments.py',
        'types': 'types.py',
        'segments': 'segments.py',
        'entries': 'entries.py',
        'imports': 'imports.py',
        'stack_frames': 'stack_frames.py',
        'search': 'search.py',
        'switches': 'switches.py',
        'try_blocks': 'try_blocks.py',
        'fixups': 'fixups.py',
        'problems': 'problems.py',
        'exporter': 'exporter.py',
        'signature_files': 'signature_files.py',
        'analysis': 'analysis.py',
        'heads': 'heads.py',
        'hooks': 'hooks.py',
        'flowchart': 'flowchart.py',
    }

    for handler_name, filename in handler_files.items():
        filepath = ida_domain_path / filename
        if filepath.exists():
            info = analyze_handler_file(filepath, handler_name)
            if info:
                handlers.append(info)
                print(f"  {handler_name}: {len(info.methods)} methods")

    # Extract enums
    print("\nExtracting enums...")
    all_enums = []
    enum_files = [
        ('xrefs', 'xrefs.py'),
        ('operands', 'operands.py'),
        ('functions', 'functions.py'),
        ('search', 'search.py'),
    ]
    for module, filename in enum_files:
        filepath = ida_domain_path / filename
        enums = extract_enums_from_file(filepath, module)
        all_enums.extend(enums)
        for e in enums:
            print(f"  {e.name}: {len(e.values)} values")

    # Generate markdown files
    print("\nGenerating reference documentation...")

    # Handlers reference
    handlers_md = generate_handlers_markdown(handlers)
    (output_dir / "references" / "api-handlers.md").write_text(handlers_md)
    print(f"  Written: references/api-handlers.md")

    # Enums reference
    enums_md = generate_enums_markdown(all_enums)
    (output_dir / "references" / "enums-types.md").write_text(enums_md)
    print(f"  Written: references/enums-types.md")

    print(f"\nDone! Generated docs for {len(handlers)} handlers and {len(all_enums)} enums")


if __name__ == "__main__":
    main()
