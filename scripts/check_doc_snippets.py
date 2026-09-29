"""
Type check the Python snippets in the documentation with mypy.

Collects ```python fences from docs/**/*.md and fenced or ``>>>`` examples from
ida_domain/*.py docstrings, writes each one to its own module and runs mypy on
them with mypy-examples.ini. Errors are reported against the original lines.

Each snippet can use the public names of the ida_domain modules without
importing them, and ``db`` is always a ``Database``. Any other object a snippet
uses has to be declared, e.g. ``func: PseudocodeFunction``.

Put ``<!-- snippet: skip -->`` on the line before a fence to exclude it (e.g.
"before" examples written against the legacy IDA Python SDK). Fences that only
include an example file (``--8<--``) are skipped; examples are checked on their own.

Usage: uv run python scripts/check_doc_snippets.py
"""

import ast
import re
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_MARKER = '<!-- snippet: skip -->'
FENCE_OPEN = re.compile(r'^\s*```python\s*$')
FENCE_CLOSE = re.compile(r'^\s*```\s*$')


def _strip_prompts(lines):
    """Turn ``>>>`` / ``...`` prompt lines into plain code."""
    out = []
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith(('>>>', '...')):
            out.append(stripped[4:] if stripped[3:4] == ' ' else '')
        else:
            out.append(line)
    return out


def _is_prompt(line):
    return line.lstrip().startswith(('>>>', '... ')) or line.strip() == '...'


def _extract(lines, first_line, prompts):
    """Yield (line of the first code line, code) for each snippet in `lines`."""
    i = 0
    while i < len(lines):
        if FENCE_OPEN.match(lines[i]):
            prev = next((ln.strip() for ln in reversed(lines[:i]) if ln.strip()), '')
            start = end = i + 1
            while end < len(lines) and not FENCE_CLOSE.match(lines[end]):
                end += 1
            body = lines[start:end]
            if prev != SKIP_MARKER and not any('--8<--' in ln for ln in body):
                if any(ln.lstrip().startswith('>>>') for ln in body):
                    body = _strip_prompts(body)
                yield first_line + start, textwrap.dedent('\n'.join(body))
            i = end + 1
        elif prompts and lines[i].lstrip().startswith('>>>'):
            start = i
            while i < len(lines) and _is_prompt(lines[i]):
                i += 1
            yield first_line + start, '\n'.join(_strip_prompts(lines[start:i]))
        else:
            i += 1


def collect():
    """Return a list of (path, line, code) for every snippet."""
    snippets = []
    for md in sorted((ROOT / 'docs').rglob('*.md')):
        rel = md.relative_to(ROOT).as_posix()
        lines = md.read_text(encoding='utf-8').splitlines()
        snippets += [(rel, line, code) for line, code in _extract(lines, 1, prompts=False)]

    for py in sorted((ROOT / 'ida_domain').glob('*.py')):
        rel = py.relative_to(ROOT).as_posix()
        tree = ast.parse(py.read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if not isinstance(
                node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                continue
            if ast.get_docstring(node, clean=False) is None:
                continue
            doc = node.body[0].value
            lines = doc.value.splitlines()
            snippets += [
                (rel, line, code) for line, code in _extract(lines, doc.lineno, prompts=True)
            ]
    return snippets


def _preamble():
    modules = sorted(
        p.stem for p in (ROOT / 'ida_domain').glob('*.py') if not p.stem.startswith('_')
    )
    lines = ['from ida_domain import *']
    lines += [f'from ida_domain.{name} import *' for name in modules]
    lines += ['', 'db: Database', '', '', 'def _snippet():']
    return '\n'.join(lines) + '\n'


def main():
    snippets = collect()
    preamble = _preamble()
    offset = preamble.count('\n')  # snippet line 1 is file line offset + 1
    error = re.compile(r'^(?P<file>.+?):(?P<line>\d+): (?P<rest>.*)$')

    reported = 0
    with tempfile.TemporaryDirectory() as tmp:
        origin = {}
        for n, (path, line, code) in enumerate(snippets):
            # A syntax error stops mypy from checking any other file
            try:
                ast.parse(code)
            except SyntaxError as e:
                print(f'{path}:{line + (e.lineno or 1) - 1}: error: {e.msg}  [syntax]')
                reported += 1
                continue
            module = Path(tmp) / f'snippet_{n:03d}.py'
            body = textwrap.indent(code, '    ', lambda ln: True) or '    ...'
            module.write_text(preamble + body + '\n    ...\n', encoding='utf-8')
            origin[module.name] = (path, line)

        result = subprocess.run(
            [
                sys.executable,
                '-m',
                'mypy',
                '--config-file',
                str(ROOT / 'mypy-examples.ini'),
                '--no-error-summary',
                *sorted(str(p) for p in Path(tmp).glob('*.py')),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    for out_line in result.stdout.splitlines():
        m = error.match(out_line)
        if m and Path(m['file']).name in origin:
            path, first = origin[Path(m['file']).name]
            print(f'{path}:{first + int(m["line"]) - offset - 1}: {m["rest"]}')
            reported += ': error:' in out_line
        elif out_line.strip():
            print(out_line)
    print(result.stderr, end='', file=sys.stderr)

    print(f'{len(snippets)} snippets checked, {reported} errors')
    return 1 if result.returncode or reported else 0


if __name__ == '__main__':
    sys.exit(main())
