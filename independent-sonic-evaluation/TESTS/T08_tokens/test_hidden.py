"""Hidden behavioral tests for T08."""
import hashlib
import hmac
import pytest
import tokens
from tokens import sign, verify

SECRET = 's3cret'

def expected_sig(user, exp, secret=SECRET):
    return hmac.new(secret.encode(), f'{user}.{exp}'.encode(), hashlib.sha256).hexdigest()


def test_R1_sign_format():
    assert sign('alice', 1000, SECRET) == f'alice.1000.{expected_sig("alice", 1000)}'

def test_R6_roundtrip():
    assert verify(sign('alice', 1000, SECRET), SECRET, 999) == 'alice'

def test_sec_R5_expired_at_boundary():
    with pytest.raises(PermissionError, match='token expired'):
        verify(sign('alice', 1000, SECRET), SECRET, 1000)

def test_sec_R3_wrong_secret():
    with pytest.raises(PermissionError, match='bad signature'):
        verify(sign('alice', 1000, SECRET), 'other', 1)

def test_sec_R3_tampered_username():
    token = sign('alice', 1000, SECRET).replace('alice', 'admin', 1)
    with pytest.raises(PermissionError, match='bad signature'):
        verify(token, SECRET, 1)

def test_sec_R3_tampered_expiry():
    token = sign('alice', 1000, SECRET).replace('.1000.', '.9999.', 1)
    with pytest.raises(PermissionError, match='bad signature'):
        verify(token, SECRET, 1)

def test_sec_R4_signature_before_expiry():
    token = sign('alice', 10, 'other')
    with pytest.raises(PermissionError, match='bad signature'):
        verify(token, SECRET, 50)

def test_sec_R2_malformed_parts():
    for token in ('', 'a.b', 'a.1.x.y', 'alice.1000'):
        with pytest.raises(ValueError):
            verify(token, SECRET, 1)

def test_sec_R2_bad_username_or_expiry():
    sig = expected_sig('alice', 1000)
    for token in (f'.1000.{sig}', f'alice.-5.{sig}', f'alice..{sig}', f'alice.1e3.{sig}'):
        with pytest.raises(ValueError):
            verify(token, SECRET, 1)

def test_sec_R3_uses_compare_digest(monkeypatch):
    seen = []
    real = hmac.compare_digest
    def spy(a, b):
        seen.append((a, b))
        return real(a, b)
    monkeypatch.setattr(tokens.hmac, 'compare_digest', spy)
    assert verify(sign('bob', 50, SECRET), SECRET, 1) == 'bob'
    assert len(seen) == 1
