"""Public corpus pins must never excuse unrelated signing material or private data."""
from pathlib import Path

import pytest

from tools.audit_payload import check_public_data


def test_public_audit_rejects_unrelated_private_key():
    marker = b'-----BEGIN ' + b'PRIVATE KEY-----\nfixture'
    with pytest.raises(AssertionError, match='private key'):
        check_public_data(Path('unexpected.txt'), marker, allow_profile_key=False)


def test_public_audit_rejects_personal_path_and_private_endpoint():
    for data in (b'/' + b'Users/example/private', b'https://' + b'10.1.2.3/repo',
                 b'agent_' + b'session_' + b'id=example'):
        with pytest.raises(AssertionError, match='private'):
            check_public_data(Path('fixture.txt'), data, allow_profile_key=False)


def test_public_audit_allows_documented_runtime_and_fixture_addresses():
    check_public_data(Path('README.md'), b'/usr/share/GITM 192.168.77.0/24 192.0.2.20', allow_profile_key=False)
