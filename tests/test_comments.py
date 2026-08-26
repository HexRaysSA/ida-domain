import ida_lines
import pytest

import ida_domain  # isort: skip
import ida_domain.base
import ida_domain.comments


def test_comments(test_env):
    db = test_env

    all_comments = list(db.comments.get_all())
    assert len(all_comments) == 10

    # Validate expected comments and their addresses
    expected_comments = [
        (0x16, 'LINUX - sys_write'),
        (0x46, 'LINUX - sys_write'),
        (0x67, 'LINUX - sys_write'),
        (0x92, 'LINUX - sys_write'),
        (0xB3, 'LINUX - sys_write'),
        (0xC2, 'LINUX - sys_exit'),
        (0x2D6, 'buf'),
        (0x2E5, 'fd'),
        (0x2ED, 'count'),
        (0x2F0, 'LINUX - sys_write'),
    ]

    for i, comment_info in enumerate(db.comments):
        assert expected_comments[i][0] == comment_info.ea
        assert expected_comments[i][1] == comment_info.comment
        assert False == comment_info.repeatable

    assert db.comments.set_at(0xAE, 'Testing adding regular comment')
    assert db.comments.get_at(0xAE).comment == 'Testing adding regular comment'
    assert not db.comments.get_at(0xAE, ida_domain.comments.CommentKind.REPEATABLE)
    assert (
        db.comments.get_at(0xAE, ida_domain.comments.CommentKind.ALL).comment
        == 'Testing adding regular comment'
    )

    assert db.comments.set_at(
        0xD1, 'Testing adding repeatable comment', ida_domain.comments.CommentKind.REPEATABLE
    )
    assert (
        db.comments.get_at(0xD1, ida_domain.comments.CommentKind.REPEATABLE).comment
        == 'Testing adding repeatable comment'
    )
    assert not db.comments.get_at(0xD1, ida_domain.comments.CommentKind.REGULAR)
    assert (
        db.comments.get_at(0xD1, ida_domain.comments.CommentKind.ALL).comment
        == 'Testing adding repeatable comment'
    )

    db.comments.delete_at(0xD1, ida_domain.comments.CommentKind.ALL)
    assert db.comments.get_at(0xD1, ida_domain.comments.CommentKind.REPEATABLE) is None
    assert db.comments.get_at(0xD1, ida_domain.comments.CommentKind.REGULAR) is None
    assert db.comments.get_at(0xD1, ida_domain.comments.CommentKind.ALL) is None

    test_ea = 0x100
    assert db.comments.set_extra_at(
        test_ea, 0, 'First anterior comment', ida_domain.comments.ExtraCommentKind.ANTERIOR
    )
    assert db.comments.set_extra_at(
        test_ea, 1, 'Second anterior comment', ida_domain.comments.ExtraCommentKind.ANTERIOR
    )

    assert (
        db.comments.get_extra_at(test_ea, 0, ida_domain.comments.ExtraCommentKind.ANTERIOR)
        == 'First anterior comment'
    )
    assert (
        db.comments.get_extra_at(test_ea, 1, ida_domain.comments.ExtraCommentKind.ANTERIOR)
        == 'Second anterior comment'
    )
    assert (
        db.comments.get_extra_at(test_ea, 2, ida_domain.comments.ExtraCommentKind.ANTERIOR) is None
    )

    assert db.comments.set_extra_at(
        test_ea, 0, 'First posterior comment', ida_domain.comments.ExtraCommentKind.POSTERIOR
    )
    assert db.comments.set_extra_at(
        test_ea, 1, 'Second posterior comment', ida_domain.comments.ExtraCommentKind.POSTERIOR
    )

    anterior_comments = list(
        db.comments.get_all_extra_at(test_ea, ida_domain.comments.ExtraCommentKind.ANTERIOR)
    )
    assert len(anterior_comments) == 2
    assert anterior_comments[0] == 'First anterior comment'
    assert anterior_comments[1] == 'Second anterior comment'

    posterior_comments = list(
        db.comments.get_all_extra_at(test_ea, ida_domain.comments.ExtraCommentKind.POSTERIOR)
    )
    assert len(posterior_comments) == 2
    assert posterior_comments[0] == 'First posterior comment'
    assert posterior_comments[1] == 'Second posterior comment'

    assert db.comments.delete_extra_at(test_ea, 1, ida_domain.comments.ExtraCommentKind.ANTERIOR)
    remaining_anterior = list(
        db.comments.get_all_extra_at(test_ea, ida_domain.comments.ExtraCommentKind.ANTERIOR)
    )
    assert len(remaining_anterior) == 1
    assert remaining_anterior[0] == 'First anterior comment'

    # Note: if you delete an extra comment at a position,
    # all the subsequent ones are becoming "invisible" also
    assert db.comments.delete_extra_at(test_ea, 0, ida_domain.comments.ExtraCommentKind.POSTERIOR)
    remaining_posterior = list(
        db.comments.get_all_extra_at(test_ea, ida_domain.comments.ExtraCommentKind.POSTERIOR)
    )
    assert len(remaining_posterior) == 0

    with pytest.raises(ida_domain.base.InvalidEAError):
        db.comments.get_at(0xFFFFFFFF)
    with pytest.raises(ida_domain.base.InvalidEAError):
        db.comments.set_at(0xFFFFFFFF, 'Invalid comment')
    with pytest.raises(ida_domain.base.InvalidEAError):
        db.comments.delete_at(0xFFFFFFFF)
    with pytest.raises(ida_domain.base.InvalidEAError):
        db.comments.set_extra_at(
            0xFFFFFFFF, 0, 'Invalid', ida_domain.comments.ExtraCommentKind.ANTERIOR
        )
    with pytest.raises(ida_domain.base.InvalidEAError):
        db.comments.get_extra_at(0xFFFFFFFF, 0, ida_domain.comments.ExtraCommentKind.ANTERIOR)
    with pytest.raises(ida_domain.base.InvalidEAError):
        list(
            db.comments.get_all_extra_at(0xFFFFFFFF, ida_domain.comments.ExtraCommentKind.ANTERIOR)
        )
    with pytest.raises(ida_domain.base.InvalidEAError):
        db.comments.delete_extra_at(0xFFFFFFFF, 0, ida_domain.comments.ExtraCommentKind.ANTERIOR)


HEAD_EA = 0xAE  # Instruction head with no pre-existing comments
TAIL_EA = 0x100  # Tail byte of the 8-byte instruction at 0xFF
FUNC_EA = 0xC4  # Function start address
INVALID_EA = 0xFFFFFFFF
EXTRA_LINE_KINDS = [
    pytest.param(ida_domain.comments.ExtraCommentKind.ANTERIOR, 999, id='anterior'),
    pytest.param(ida_domain.comments.ExtraCommentKind.POSTERIOR, 1000, id='posterior'),
]


def _extra_lines(db, kind, ea=HEAD_EA):
    return list(db.comments.get_all_extra_at(ea, kind))


def test_append_at(test_env):
    db = test_env

    assert db.comments.append_at(HEAD_EA, 'Regular first')
    assert db.comments.append_at(HEAD_EA, 'Regular second')
    assert db.comments.get_at(HEAD_EA).comment == 'Regular first\nRegular second'

    assert db.comments.append_at(
        HEAD_EA, 'Repeatable first', ida_domain.comments.CommentKind.REPEATABLE
    )
    assert (
        db.comments.get_at(HEAD_EA, ida_domain.comments.CommentKind.REPEATABLE).comment
        == 'Repeatable first'
    )
    assert db.comments.get_at(HEAD_EA).comment == 'Regular first\nRegular second'


def test_append_at_validation(test_env):
    db = test_env
    assert db.comments.append_at(HEAD_EA, 'Existing')

    with pytest.raises(ida_domain.base.InvalidParameterError):
        db.comments.append_at(HEAD_EA, 'Both', ida_domain.comments.CommentKind.ALL)
    with pytest.raises(ida_domain.base.InvalidParameterError):
        db.comments.append_at(TAIL_EA, 'Tail comment')
    with pytest.raises(ida_domain.base.InvalidEAError):
        db.comments.append_at(INVALID_EA, 'Invalid')

    assert db.comments.get_at(HEAD_EA).comment == 'Existing'


def test_comments_are_rendered(test_env):
    db = test_env

    assert db.comments.append_at(HEAD_EA, 'Regular comment')
    assert 'Regular comment' in db.bytes.get_disassembly_at(HEAD_EA)

    db.comments.delete_at(HEAD_EA)
    assert db.comments.set_at(
        HEAD_EA, 'Repeatable comment', ida_domain.comments.CommentKind.REPEATABLE
    )
    assert 'Repeatable comment' in db.bytes.get_disassembly_at(HEAD_EA)

    assert db.comments.set_extra_lines_at(
        HEAD_EA, ['Anterior line'], ida_domain.comments.ExtraCommentKind.ANTERIOR
    )
    assert db.comments.set_extra_lines_at(
        HEAD_EA, ['Posterior line'], ida_domain.comments.ExtraCommentKind.POSTERIOR
    )
    _, lines = ida_lines.generate_disassembly(HEAD_EA, 10, False, False)
    rendered = [ida_lines.tag_remove(line) for line in lines]
    assert any('Anterior line' in line for line in rendered)
    assert any('Posterior line' in line for line in rendered)


def test_append_at_function_start(test_env):
    db = test_env
    func = db.functions.get_at(FUNC_EA)
    assert func is not None and func.start_ea == FUNC_EA
    assert db.functions.set_comment(func, 'Function comment')

    # append_at works on the item comment and leaves the function comment alone.
    assert db.comments.append_at(FUNC_EA, 'Item first')
    assert db.comments.append_at(FUNC_EA, 'Item second')
    assert db.comments.get_at(FUNC_EA).comment == 'Item first\nItem second'
    assert db.functions.get_comment(func) == 'Function comment'


@pytest.mark.parametrize('kind,max_lines', EXTRA_LINE_KINDS)
def test_set_extra_lines_at(test_env, kind, max_lines):
    db = test_env

    assert db.comments.set_extra_lines_at(
        HEAD_EA, (line for line in ['Line A', 'Line B', 'Line C']), kind
    )
    assert _extra_lines(db, kind) == ['Line A', 'Line B', 'Line C']

    # Replacement removes all previous lines, not just the overwritten ones.
    assert db.comments.set_extra_lines_at(HEAD_EA, ['Replacement'], kind)
    assert _extra_lines(db, kind) == ['Replacement']
    assert db.comments.get_extra_at(HEAD_EA, 1, kind) is None

    assert db.comments.set_extra_lines_at(HEAD_EA, [], kind)
    assert _extra_lines(db, kind) == []


@pytest.mark.parametrize('kind,max_lines', EXTRA_LINE_KINDS)
def test_set_extra_lines_at_validation(test_env, kind, max_lines):
    db = test_env
    assert db.comments.set_extra_lines_at(HEAD_EA, ['Existing line'], kind)

    with pytest.raises(ida_domain.base.InvalidParameterError):
        db.comments.set_extra_lines_at(HEAD_EA, ['New line', 42], kind)
    with pytest.raises(ida_domain.base.InvalidParameterError):
        db.comments.set_extra_lines_at(HEAD_EA, 'abc', kind)
    with pytest.raises(ida_domain.base.InvalidParameterError):
        db.comments.set_extra_lines_at(HEAD_EA, ['line'] * (max_lines + 1), kind)
    with pytest.raises(ida_domain.base.InvalidEAError):
        db.comments.set_extra_lines_at(INVALID_EA, [], kind)

    # Rejected calls must not touch the existing lines.
    assert _extra_lines(db, kind) == ['Existing line']


def test_set_extra_lines_at_splits_line_breaks(test_env):
    db = test_env
    anterior = ida_domain.comments.ExtraCommentKind.ANTERIOR

    # Embedded line breaks split into separate lines; empty lines are preserved.
    assert db.comments.set_extra_lines_at(
        HEAD_EA, ['Split 1\nSplit 2', '', 'Split 3\r\nSplit 4'], anterior
    )
    expected = ['Split 1', 'Split 2', '', 'Split 3', 'Split 4']
    assert _extra_lines(db, anterior) == expected

    # The slot capacity applies to the line count after splitting.
    with pytest.raises(ida_domain.base.InvalidParameterError):
        db.comments.set_extra_lines_at(HEAD_EA, ['x\ny'] * 500, anterior)
    assert _extra_lines(db, anterior) == expected


@pytest.mark.parametrize('kind,max_lines', EXTRA_LINE_KINDS)
def test_delete_extra_lines_at(test_env, kind, max_lines):
    db = test_env

    assert db.comments.set_extra_lines_at(HEAD_EA, ['Visible line'], kind)
    # A line stored after a gap is invisible to get_all_extra_at but must be deleted too.
    assert db.comments.set_extra_at(HEAD_EA, 3, 'Hidden line', kind)

    assert db.comments.delete_extra_lines_at(HEAD_EA, kind)
    assert _extra_lines(db, kind) == []
    assert db.comments.get_extra_at(HEAD_EA, 3, kind) is None

    with pytest.raises(ida_domain.base.InvalidEAError):
        db.comments.delete_extra_lines_at(INVALID_EA, kind)


def test_get_combined_at(test_env):
    db = test_env

    assert db.comments.get_combined_at(HEAD_EA) is None

    assert db.comments.set_at(HEAD_EA, 'Regular')
    assert db.comments.set_at(HEAD_EA, 'Repeatable', ida_domain.comments.CommentKind.REPEATABLE)
    assert db.comments.set_extra_lines_at(
        HEAD_EA, ['Anterior 1', 'Anterior 2'], ida_domain.comments.ExtraCommentKind.ANTERIOR
    )
    assert db.comments.set_extra_lines_at(
        HEAD_EA, ['Posterior 1'], ida_domain.comments.ExtraCommentKind.POSTERIOR
    )

    # Listing order: anterior, regular or repeatable, posterior.
    assert db.comments.get_combined_at(HEAD_EA) == ('Anterior 1\nAnterior 2\nRegular\nPosterior 1')

    assert (
        db.comments.get_combined_at(
            HEAD_EA, include_repeatable=False, include_anterior=False, include_posterior=False
        )
        == 'Regular'
    )
    assert (
        db.comments.get_combined_at(
            HEAD_EA, include_regular=False, include_anterior=False, include_posterior=False
        )
        == 'Repeatable'
    )

    db.comments.delete_at(HEAD_EA)
    assert db.comments.get_combined_at(HEAD_EA) == (
        'Anterior 1\nAnterior 2\nRepeatable\nPosterior 1'
    )
    assert (
        db.comments.get_combined_at(
            HEAD_EA,
            include_regular=False,
            include_repeatable=False,
            include_anterior=False,
            include_posterior=False,
        )
        is None
    )

    with pytest.raises(ida_domain.base.InvalidEAError):
        db.comments.get_combined_at(INVALID_EA)
    with pytest.raises(ida_domain.base.InvalidEAError):
        db.comments.set_extra_lines_at(
            0xFFFFFFFF, [], ida_domain.comments.ExtraCommentKind.ANTERIOR
        )
    with pytest.raises(ida_domain.base.InvalidEAError):
        db.comments.delete_extra_lines_at(
            0xFFFFFFFF, ida_domain.comments.ExtraCommentKind.POSTERIOR
        )
    with pytest.raises(ida_domain.base.InvalidEAError):
        db.comments.append_at(0xFFFFFFFF, 'Invalid')
    with pytest.raises(ida_domain.base.InvalidEAError):
        db.comments.get_combined_at(0xFFFFFFFF)
