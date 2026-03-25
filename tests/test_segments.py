from ida_domain.segments import (
    AddressingMode,
    AddSegmentFlags,
    PredefinedClass,
    SegmentPermissions,
)


def test_segment(test_env):
    db = test_env

    seg = db.segments.append(0, 0x100, '.test', PredefinedClass.CODE, AddSegmentFlags.NONE)
    assert seg is not None
    assert (
        db.segments.set_permissions(seg, SegmentPermissions.READ | SegmentPermissions.EXEC) == True
    )
    assert db.segments.add_permissions(seg, SegmentPermissions.WRITE) == True
    assert db.segments.remove_permissions(seg, SegmentPermissions.EXEC) == True
    assert db.segments.set_addressing_mode(seg, AddressingMode.BIT64) == True

    assert len(db.segments) == 5
    for segment in db.segments:
        assert db.segments.get_name(segment)

    for idx, seg in enumerate(db.segments):
        if idx == 0:
            assert seg is not None
            assert db.segments.get_name(seg) == '.text'
            assert seg.start_ea == 0
            assert db.segments.set_name(seg, 'testing_segment_rename')
            assert db.segments.get_name(seg) == 'testing_segment_rename'
        elif idx == 1:
            assert seg is not None
            assert db.segments.get_name(seg) == '.data'
            assert seg.start_ea == 0x330

    # Test segment comment methods
    test_segment = db.segments.get_at(0x330)  # Use .data segment
    assert test_segment is not None
    test_comment = 'Test segment comment'
    test_repeatable_comment = 'Test repeatable segment comment'

    # Test non-repeatable segment comment
    assert db.segments.set_comment(test_segment, test_comment, False)
    retrieved_comment = db.segments.get_comment(test_segment, False)
    assert retrieved_comment == test_comment

    # Test repeatable segment comment
    assert db.segments.set_comment(test_segment, test_repeatable_comment, True)
    retrieved_repeatable_comment = db.segments.get_comment(test_segment, True)
    assert retrieved_repeatable_comment == test_repeatable_comment

    # Test getting non-existent comment returns empty string
    text_segment = db.segments.get_at(0x0)  # Use .text segment
    empty_comment = db.segments.get_comment(text_segment, False)
    assert empty_comment == ''
