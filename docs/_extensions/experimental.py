"""Griffe extension that annotates members decorated with ``@experimental``."""

from __future__ import annotations

import ast
from typing import Any

import griffe

_ADMONITION = (
    '!!! example "Experimental"\n    This API is experimental and may change in future releases.'
)


class ExperimentalExtension(griffe.Extension):
    """Detect ``@experimental`` and prepend an admonition to the docstring."""

    def __init__(self) -> None:
        super().__init__()
        self._experimental: set[int] = set()

    def on_function_node(self, *, node: ast.AST, agent: Any, **kwargs: Any) -> None:
        for decorator in node.decorator_list:  # type: ignore[attr-defined]
            if isinstance(decorator, ast.Name) and decorator.id == 'experimental':
                self._experimental.add(id(node))

    def on_function_instance(self, *, node: ast.AST, func: griffe.Function, **kwargs: Any) -> None:
        if id(node) in self._experimental:
            self._experimental.discard(id(node))
            self._annotate(func)

    @staticmethod
    def _annotate(func: griffe.Function) -> None:
        if func.docstring:
            func.docstring.value = f'{_ADMONITION}\n\n{func.docstring.value}'
        else:
            func.docstring = griffe.Docstring(_ADMONITION, parent=func)
