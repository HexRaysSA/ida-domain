"""
Helpers for IDA's tagged text lines.

Disassembly and pseudocode lines produced by IDA carry invisible *tags*:
escape sequences that give each piece of text a color and, through address
tags, link it to an address or a ctree item. The functions in this
module build, strip, measure and parse such text.

Example:
    ```python
    from ida_domain.lines import Color, colorize, parse_sections, remove_tags

    line = colorize('mov', Color.INSN) + ' ' + colorize('eax', Color.REG)
    print(remove_tags(line))  # mov eax
    for section in parse_sections(line):
        print(f'{section.color!r} {section.start} {section.text}')
    ```
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

import ida_kernwin
import ida_lines
from ida_idaapi import ea_t
from typing_extensions import List, Optional

from .base import InvalidParameterError, requires_ida


class Color(IntEnum):
    """Colors a piece of tagged text can have (``ida_lines.COLOR_*``)."""

    DEFAULT = ida_lines.COLOR_DEFAULT
    """Default"""
    REGCMT = ida_lines.COLOR_REGCMT
    """Regular comment"""
    RPTCMT = ida_lines.COLOR_RPTCMT
    """Repeatable comment"""
    AUTOCMT = ida_lines.COLOR_AUTOCMT
    """Automatic comment"""
    INSN = ida_lines.COLOR_INSN
    """Instruction"""
    DATNAME = ida_lines.COLOR_DATNAME
    """Dummy data name"""
    DNAME = ida_lines.COLOR_DNAME
    """Regular data name"""
    DEMNAME = ida_lines.COLOR_DEMNAME
    """Demangled name"""
    SYMBOL = ida_lines.COLOR_SYMBOL
    """Punctuation"""
    CHAR = ida_lines.COLOR_CHAR
    """Char constant in instruction"""
    STRING = ida_lines.COLOR_STRING
    """String constant in instruction"""
    NUMBER = ida_lines.COLOR_NUMBER
    """Numeric constant in instruction"""
    VOIDOP = ida_lines.COLOR_VOIDOP
    """Void operand"""
    CREF = ida_lines.COLOR_CREF
    """Code reference"""
    DREF = ida_lines.COLOR_DREF
    """Data reference"""
    CREFTAIL = ida_lines.COLOR_CREFTAIL
    """Code reference to tail byte"""
    DREFTAIL = ida_lines.COLOR_DREFTAIL
    """Data reference to tail byte"""
    ERROR = ida_lines.COLOR_ERROR
    """Error or problem"""
    PREFIX = ida_lines.COLOR_PREFIX
    """Line prefix"""
    BINPREF = ida_lines.COLOR_BINPREF
    """Binary line prefix bytes"""
    EXTRA = ida_lines.COLOR_EXTRA
    """Extra line"""
    ALTOP = ida_lines.COLOR_ALTOP
    """Alternative operand"""
    HIDNAME = ida_lines.COLOR_HIDNAME
    """Hidden name"""
    LIBNAME = ida_lines.COLOR_LIBNAME
    """Library function name"""
    LOCNAME = ida_lines.COLOR_LOCNAME
    """Local variable name"""
    CODNAME = ida_lines.COLOR_CODNAME
    """Dummy code name"""
    ASMDIR = ida_lines.COLOR_ASMDIR
    """Assembler directive"""
    MACRO = ida_lines.COLOR_MACRO
    """Macro"""
    DSTR = ida_lines.COLOR_DSTR
    """String constant in data directive"""
    DCHAR = ida_lines.COLOR_DCHAR
    """Char constant in data directive"""
    DNUM = ida_lines.COLOR_DNUM
    """Numeric constant in data directive"""
    KEYWORD = ida_lines.COLOR_KEYWORD
    """Keyword"""
    REG = ida_lines.COLOR_REG
    """Register name"""
    IMPNAME = ida_lines.COLOR_IMPNAME
    """Imported name"""
    SEGNAME = ida_lines.COLOR_SEGNAME
    """Segment name"""
    UNKNAME = ida_lines.COLOR_UNKNAME
    """Dummy unknown name"""
    CNAME = ida_lines.COLOR_CNAME
    """Regular code name"""
    UNAME = ida_lines.COLOR_UNAME
    """Regular unknown name"""
    COLLAPSED = ida_lines.COLOR_COLLAPSED
    """Collapsed line"""


@dataclass(frozen=True)
class LineSection:
    """A tagged section of a line, as returned by :func:`parse_sections`."""

    tag: int
    """Raw tag code (``ida_lines.COLOR_*``): a :class:`Color` value or a structural tag."""
    start: int
    """Column of the first character of the section in the visible text."""
    length: int
    """Number of visible characters covered. Always 0 for an address tag."""
    text: str
    """Visible text of the section, with all tags removed."""
    value: Optional[ea_t] = None
    """Value carried by an address tag, None for any other section."""

    @property
    def color(self) -> Optional[Color]:
        """The color of this section, or None if its tag is a structural one."""
        try:
            return Color(self.tag)
        except ValueError:
            return None


def colorize(text: str, color: Color) -> str:
    """
    Wraps text in the tags that give it a color.

    The text may already contain tags, so calls can be nested.

    Args:
        text: The text to color.
        color: The color to apply.

    Returns:
        The tagged text.

    Raises:
        InvalidParameterError: If color is not a valid :class:`Color`.
    """
    try:
        code = chr(Color(color))
    except ValueError:
        raise InvalidParameterError('color', color, 'must be a Color value') from None
    return ida_lines.COLSTR(text, code)


def remove_tags(text: str) -> str:
    """
    Removes all tags from a tagged string.

    Args:
        text: The tagged text.

    Returns:
        The visible text.
    """
    return ida_lines.tag_remove(text)


def visible_length(text: str) -> int:
    """
    Gets the length of a tagged string in visible characters (Unicode
    code points), tags excluded.

    Same as ``len(remove_tags(text))``, without building the string.

    Args:
        text: The tagged text.

    Returns:
        The number of visible characters.
    """
    return ida_lines.tag_strlen(text)


def make_address_tag(ea: ea_t) -> str:
    """
    Builds an address tag: a hidden mark that embeds a value in a line.

    Args:
        ea: The value to encode.

    Returns:
        The address tag.
    """
    return ida_lines.tag_addr(ea)


@requires_ida('9.4')
def parse_sections(text: str) -> List[LineSection]:
    """
    Splits a tagged line into its tagged sections.

    Each pair of opening and closing tags, and each address tag, yields one
    section. Positions are expressed in visible characters.

    Args:
        text: The tagged line.

    Returns:
        The sections of the line, in the order their tags open.

    Example:
        ```python
        line = db.instructions.get_disassembly(insn, remove_tags=False)
        for section in parse_sections(line or ''):
            if section.color == Color.REG:
                print(f'register {section.text} at column {section.start}')
            elif section.value is not None:
                print(f'refers to {section.value:#x}')
        ```
    """
    raw_sections = ida_kernwin.tagged_line_sections_t()
    ida_kernwin.parse_tagged_line_sections(raw_sections, text)

    sections: List[LineSection] = []
    for raw in raw_sections:
        if not raw.valid():
            continue
        sections.append(
            LineSection(
                tag=raw.tag,
                start=raw.start,
                length=raw.length,
                text=remove_tags(raw.substr(text)),
                value=raw.get_addr(text) if raw.tag == ida_lines.COLOR_ADDR else None,
            )
        )
    return sections
