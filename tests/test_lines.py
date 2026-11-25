import pytest

import ida_domain  # isort: skip
import ida_lines
from conftest import max_ida_version, min_ida_version

from ida_domain.base import InvalidParameterError
from ida_domain.lines import (
    Color,
    LineSection,
    colorize,
    make_address_tag,
    parse_sections,
    remove_tags,
    visible_length,
)


def test_color_matches_sdk():
    # Every member mirrors the SDK constant of the same name
    for color in Color:
        assert color.value == getattr(ida_lines, f'COLOR_{color.name}')

    # All real colors are covered, and nothing else
    assert sorted(c.value for c in Color) == list(range(1, ida_lines.COLOR_FG_MAX))
    assert ida_lines.COLOR_ADDR not in set(Color)
    assert ida_lines.COLOR_OPND1 not in set(Color)


def test_colorize():
    assert colorize('eax', Color.REG) == ida_lines.COLSTR('eax', ida_lines.SCOLOR_REG)
    assert colorize('', Color.REG) == ida_lines.SCOLOR_ON + ida_lines.SCOLOR_REG + (
        ida_lines.SCOLOR_OFF + ida_lines.SCOLOR_REG
    )

    # Plain ints that are valid colors are accepted
    assert colorize('eax', ida_lines.COLOR_REG) == colorize('eax', Color.REG)

    # Nesting keeps the inner tags intact
    nested = colorize(colorize('eax', Color.REG) + ', 1', Color.DEFAULT)
    assert remove_tags(nested) == 'eax, 1'
    assert colorize('eax', Color.REG) in nested

    for bad in (0, ida_lines.COLOR_ADDR, ida_lines.COLOR_OPND1, 0x100, -1):
        with pytest.raises(InvalidParameterError):
            colorize('eax', bad)


def test_remove_tags_and_visible_length():
    line = colorize('mov', Color.INSN) + ' ' + colorize('héllo', Color.STRING)
    assert remove_tags(line) == 'mov héllo'
    assert visible_length(line) == len('mov héllo')

    assert remove_tags('') == ''
    assert visible_length('') == 0
    assert remove_tags('plain') == 'plain'
    assert visible_length('plain') == 5

    # Address tags are invisible
    line = make_address_tag(0x401000) + colorize('loc_401000', Color.CODNAME)
    assert remove_tags(line) == 'loc_401000'
    assert visible_length(line) == 10


def test_make_address_tag():
    for value in (0, 0x401000, 0x40000009, 0x80000000, 0xFFFFFFFFFFFFFFFF):
        tag = make_address_tag(value)
        assert tag == ida_lines.SCOLOR_ON + ida_lines.SCOLOR_ADDR + f'{value:016X}'
        assert remove_tags(tag) == ''


@min_ida_version('9.4')
def test_parse_sections():
    line = (
        colorize('mov', Color.INSN)
        + ' '
        + ida_lines.COLSTR(colorize('héx', Color.REG), ida_lines.SCOLOR_OPND1)
        + colorize(',', Color.SYMBOL)
        + ' '
        + ida_lines.COLSTR(
            colorize(make_address_tag(0x401000) + 'sink', Color.DNAME), ida_lines.SCOLOR_OPND2
        )
    )
    plain = remove_tags(line)
    assert plain == 'mov héx, sink'

    sections = parse_sections(line)
    assert sections == [
        LineSection(tag=Color.INSN, start=0, length=3, text='mov'),
        LineSection(tag=ida_lines.COLOR_OPND1, start=4, length=3, text='héx'),
        LineSection(tag=Color.REG, start=4, length=3, text='héx'),
        LineSection(tag=Color.SYMBOL, start=7, length=1, text=','),
        LineSection(tag=ida_lines.COLOR_OPND2, start=9, length=4, text='sink'),
        LineSection(tag=Color.DNAME, start=9, length=4, text='sink'),
        LineSection(tag=ida_lines.COLOR_ADDR, start=9, length=0, text='', value=0x401000),
    ]

    # Positions index into the visible text
    for section in sections:
        assert plain[section.start : section.start + section.length] == section.text

    assert [s.color for s in sections] == [
        Color.INSN,
        None,
        Color.REG,
        Color.SYMBOL,
        None,
        Color.DNAME,
        None,
    ]

    assert parse_sections('') == []
    assert parse_sections('plain') == []


@min_ida_version('9.4')
def test_parse_sections_disassembly(tiny_c_env):
    db = tiny_c_env

    checked = 0
    for func in db.functions.get_all():
        for insn in db.functions.get_instructions(func):
            tagged = db.instructions.get_disassembly(insn, remove_tags=False)
            if not tagged:
                continue
            plain = remove_tags(tagged)
            assert plain == db.instructions.get_disassembly(insn)
            assert visible_length(tagged) == len(plain)

            sections = parse_sections(tagged)
            for section in sections:
                assert plain[section.start : section.start + section.length] == section.text

            for section in sections:
                if section.value is not None:
                    assert section.tag == ida_lines.COLOR_ADDR
                    assert section.length == 0

            # The mnemonic is the first instruction-colored section. Lines of
            # extern functions are assembler directives and have none.
            mnemonic = next((s for s in sections if s.color == Color.INSN), None)
            if mnemonic is not None:
                assert mnemonic.text == db.instructions.get_mnemonic(insn)
                checked += 1
    assert checked > 0


@min_ida_version('9.4')
def test_parse_sections_pseudocode(tiny_c_env):
    db = tiny_c_env

    func = next(iter(db.functions.get_all()))
    decompiled = db.pseudocode.decompile(func)
    tagged_lines = decompiled.to_text(remove_tags=False)
    plain_lines = decompiled.to_text()
    assert len(tagged_lines) == len(plain_lines)

    anchors = 0
    for tagged, plain in zip(tagged_lines, plain_lines):
        assert remove_tags(tagged) == plain
        for section in parse_sections(tagged):
            assert plain[section.start : section.start + section.length] == section.text
            if section.value is not None:
                anchors += 1
    # Pseudocode lines link their text to ctree items through address tags
    assert anchors > 0


@max_ida_version('9.3')
def test_parse_sections_requires_ida_94():
    with pytest.raises(NotImplementedError):
        parse_sections(colorize('eax', Color.REG))
