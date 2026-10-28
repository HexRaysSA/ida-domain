import time
from contextlib import contextmanager

import ida_hexrays
import pytest

import ida_domain  # isort: skip

from conftest import max_ida_version, min_ida_version  # noqa: E402

from ida_domain.base import (  # noqa: E402
    DecompilerError,
    InvalidParameterError,
    NotSupportedWarning,
)
from ida_domain.microcode import (  # noqa: E402
    DecompilationFlags,
    MicrocodeError,
    MicroError,
    MicroInstructionOptimizer,
    MicroMaturity,
    decompiler_timeout,
)
from ida_domain.pseudocode import PseudocodeError  # noqa: E402


class _SlowOptimizer(MicroInstructionOptimizer):
    """Sleeps on every instruction the optimizer visits.

    Decompiling complex_assignments visits ~800 instructions, so without a
    timeout this takes several seconds. Any timeout far below that fails
    reliably.
    """

    def optimize(self, block, insn, optflags):
        time.sleep(0.01)
        return 0


@contextmanager
def _slow_decompiler():
    opt = _SlowOptimizer()
    opt.install()
    try:
        yield
    finally:
        opt.uninstall()


def _current_timeout_ms() -> int:
    return ida_hexrays.get_decompiler_timeout()


@min_ida_version('9.5')
def test_decompile_times_out(tiny_c_env):
    func = tiny_c_env.functions.get_by_name('complex_assignments')

    start = time.monotonic()
    with _slow_decompiler(), decompiler_timeout(0.05):
        with pytest.raises(PseudocodeError) as exc:
            tiny_c_env.pseudocode.decompile(func, DecompilationFlags.NO_CACHE)

    assert exc.value.code == MicroError.TIMEOUT
    assert 'TIMEOUT' in str(exc.value)
    assert time.monotonic() - start < 3


@min_ida_version('9.5')
def test_microcode_generate_times_out(tiny_c_env):
    func = tiny_c_env.functions.get_by_name('complex_assignments')

    with _slow_decompiler(), decompiler_timeout(0.05):
        with pytest.raises(MicrocodeError) as exc:
            tiny_c_env.microcode.generate(func, maturity=MicroMaturity.LVARS)

    assert exc.value.code == MicroError.TIMEOUT


@min_ida_version('9.5')
def test_microcode_from_decompilation_times_out(tiny_c_env):
    func = tiny_c_env.functions.get_by_name('complex_assignments')

    with _slow_decompiler(), decompiler_timeout(0.05):
        with pytest.raises(MicrocodeError) as exc:
            tiny_c_env.microcode.from_decompilation(func)

    assert exc.value.code == MicroError.TIMEOUT


@min_ida_version('9.5')
def test_timeout_requires_decompiler(tiny_c_env):
    # The timeout lives in the Hex-Rays plugin, which is only loaded while a
    # database is open. Setting it without one would be silently dropped.
    tiny_c_env.close(False)

    with pytest.raises(DecompilerError):
        with decompiler_timeout(5):
            pass


@min_ida_version('9.5')
def test_decompile_within_timeout_succeeds(tiny_c_env):
    func = tiny_c_env.functions.get_by_name('complex_assignments')

    with decompiler_timeout(60):
        cfunc = tiny_c_env.pseudocode.decompile(func, DecompilationFlags.NO_CACHE)

    assert cfunc.body is not None


@min_ida_version('9.5')
def test_timeout_restored_on_exit(tiny_c_env):
    before = _current_timeout_ms()

    with decompiler_timeout(1.5):
        assert _current_timeout_ms() == 1500

    assert _current_timeout_ms() == before


@min_ida_version('9.5')
def test_timeout_nesting(tiny_c_env):
    before = _current_timeout_ms()

    with decompiler_timeout(5):
        assert _current_timeout_ms() == 5000
        with decompiler_timeout(0.25):
            assert _current_timeout_ms() == 250
        assert _current_timeout_ms() == 5000
        with decompiler_timeout(None):
            assert _current_timeout_ms() == 0
        assert _current_timeout_ms() == 5000

    assert _current_timeout_ms() == before


@min_ida_version('9.5')
def test_timeout_restored_on_exception(tiny_c_env):
    before = _current_timeout_ms()

    with pytest.raises(RuntimeError):
        with decompiler_timeout(5):
            with decompiler_timeout(1):
                raise RuntimeError('boom')

    assert _current_timeout_ms() == before


@min_ida_version('9.5')
def test_timeout_rounds_up_to_one_millisecond(tiny_c_env):
    # 0 means "no timeout" to the SDK, so a tiny positive timeout must not
    # round down to it.
    with decompiler_timeout(0.0001):
        assert _current_timeout_ms() == 1


@pytest.mark.parametrize(
    'seconds', [-1, -0.001, float('nan'), float('inf'), 2**31 / 1000, True, '5']
)
def test_timeout_rejects_invalid_values(tiny_c_env, seconds):
    with pytest.raises(InvalidParameterError):
        with decompiler_timeout(seconds):
            pass


@max_ida_version('9.4')
def test_timeout_is_noop_before_9_5(tiny_c_env):
    func = tiny_c_env.functions.get_by_name('complex_assignments')

    with pytest.warns(NotSupportedWarning):
        with decompiler_timeout(0.001):
            cfunc = tiny_c_env.pseudocode.decompile(func, DecompilationFlags.NO_CACHE)

    assert cfunc.body is not None
