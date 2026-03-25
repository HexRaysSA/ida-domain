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
