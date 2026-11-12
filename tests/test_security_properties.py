"""No-network, property-based checks for the local security scanner."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from hypothesis import given, settings, strategies as st

from security_agents import CHECKS, check_scope, check_shell, load_context


def test_fifteen_modules_configured():
    assert len(CHECKS) == 15


@given(st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=20)))
@settings(max_examples=30)
def test_external_scanning_must_be_exactly_false(value):
    with TemporaryDirectory() as folder:
        root = Path(folder)
        (root / 'scope-config.json').write_text(
            json.dumps({'external_scanning': value}), encoding='utf-8'
        )
        findings = check_scope(load_context(root))
        assert bool(findings) is (value is not False)


@given(st.sampled_from(['os.system', 'os.popen']))
def test_dangerous_shell_calls_are_flagged(function):
    with TemporaryDirectory() as folder:
        root = Path(folder)
        (root / 'training.py').write_text(
            f'import os\n{function}("echo isolated")\n', encoding='utf-8'
        )
        findings = check_shell(load_context(root))
        assert findings and findings[0].severity == 'HIGH'


@given(st.text(alphabet=st.characters(min_codepoint=32, max_codepoint=126), max_size=70))
@settings(max_examples=40)
def test_printing_static_text_is_not_shell_execution(value):
    with TemporaryDirectory() as folder:
        root = Path(folder)
        (root / 'safe.py').write_text('print(' + repr(value) + ')\n', encoding='utf-8')
        assert check_shell(load_context(root)) == []
