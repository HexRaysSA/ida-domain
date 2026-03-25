from pathlib import Path

import ida_domain  # isort: skip


def test_signature_files(test_env):
    db = test_env

    # Get available signatures
    available_sigs = db.signature_files.get_files()
    assert len(available_sigs) > 0, 'No signature files found'

    sig_files = db.signature_files.create(pat_only=True)
    assert len(sig_files) == 1
    assert sig_files[0] == f'{db.path}.pat'

    sig_files = db.signature_files.create()
    assert len(sig_files) == 2
    assert sig_files[0] == f'{db.path}.sig'
    assert sig_files[1] == f'{db.path}.pat'

    # Test applying a single signature file
    sig_path = Path(sig_files[0])
    assert sig_path.exists()
    results = db.signature_files.apply(sig_path)
    assert isinstance(results, list)
    assert len(results) == 1

    file_info = results[0]
    assert isinstance(file_info, ida_domain.signature_files.FileInfo)
    assert file_info.path == str(sig_path)
    assert isinstance(file_info.matches, int)
    assert isinstance(file_info.functions, list)
    assert file_info.matches == 6
    match_info = file_info.functions[0]
    assert isinstance(match_info, ida_domain.signature_files.MatchInfo)
    assert isinstance(match_info.addr, int)
    assert isinstance(match_info.name, str)
    assert 'tiny_asm.bin.i64' in match_info.lib

    # Apply with probe_only=True
    results_probe = db.signature_files.apply(sig_path, probe_only=True)
    assert isinstance(results_probe, list)
    assert len(results_probe) == 1

    index = db.signature_files.get_index(sig_path)
    assert isinstance(index, int)
    assert index >= 0
