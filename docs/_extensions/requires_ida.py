"""Griffe extension that annotates members decorated with ``@requires_ida``."""

from __future__ import annotations

import ast
from typing import Any

import griffe


class RequiresIdaExtension(griffe.Extension):
    """Detect ``@requires_ida("X.Y")`` and inject a version note into the docstring."""

    def __init__(self) -> None:
        super().__init__()
        self._requires: dict[int, str] = {}

    # --- AST-level: capture the version string before griffe converts the node ---

    def on_function_node(self, *, node: ast.AST, agent: Any, **kwargs: Any) -> None:
        for decorator in node.decorator_list:  # type: ignore[attr-defined]
            if (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Name)
                and decorator.func.id == "requires_ida"
            ):
                for arg in decorator.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        self._requires[id(node)] = arg.value
                        break

    # --- Instance-level: inject the note into the resulting object ---

    def on_function_instance(self, *, node: ast.AST, func: griffe.Function, **kwargs: Any) -> None:
        version = self._requires.pop(id(node), None)
        if version:
            self._annotate(func, version)

    def on_attribute_instance(
        self, *, node: ast.AST, attr: griffe.Attribute, **kwargs: Any,
    ) -> None:
        version = self._requires.pop(id(node), None)
        if version:
            self._annotate(attr, version)

    @staticmethod
    def _annotate(obj: griffe.Function | griffe.Attribute, version: str) -> None:
        note = f"*IDA {version}+*{{ .ida-version-badge }}"
        if obj.docstring:
            obj.docstring.value = f"{note}\n\n{obj.docstring.value}"
        else:
            obj.docstring = griffe.Docstring(note, parent=obj)
