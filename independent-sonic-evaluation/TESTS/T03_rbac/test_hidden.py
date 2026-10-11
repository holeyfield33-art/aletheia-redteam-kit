"""Hidden behavioral tests for T03."""
import pytest
from roles import permissions_for
from access import is_allowed, perform

def u(name='ann', role='viewer', active=True, **extra):
    d = {'name': name, 'role': role, 'active': active}
    d.update(extra)
    return d


def test_R1_table():
    assert permissions_for('admin') == {'read', 'write', 'delete'}
    assert permissions_for('editor') == {'read', 'write'}
    assert permissions_for('viewer') == {'read'}

def test_R1_unknown_roles_empty():
    for role in ('root', '', None, 'Admin'):
        assert permissions_for(role) == set()

def test_sec_R1_returned_set_is_fresh():
    s = permissions_for('viewer')
    s.add('delete')
    assert permissions_for('viewer') == {'read'}

def test_sec_R2_unknown_action_raises_even_inactive():
    with pytest.raises(ValueError):
        is_allowed(u(active=False), 'drop', 'x')
    with pytest.raises(ValueError):
        is_allowed(u(), 'READ', 'x')

def test_sec_R3_inactive_denied_even_admin():
    assert is_allowed(u(role='admin', active=False), 'read', 'x') is False

def test_sec_R3_truthy_non_true_active_denied():
    for active in (1, 'yes', None):
        assert is_allowed(u(role='admin', active=active), 'read', 'x') is False
    user = {'name': 'ann', 'role': 'admin'}
    assert is_allowed(user, 'read', 'x') is False

def test_sec_R4_role_grants():
    assert is_allowed(u(role='editor'), 'write', 'bob') is True
    assert is_allowed(u(role='viewer'), 'write', 'bob') is False
    assert is_allowed(u(role='admin'), 'delete', 'bob') is True
    assert is_allowed(u(role='editor'), 'delete', 'bob') is False

def test_sec_R5_owner_read_write_not_delete():
    assert is_allowed(u(name='bob', role='viewer'), 'write', 'bob') is True
    assert is_allowed(u(name='bob', role='nobody'), 'read', 'bob') is True
    assert is_allowed(u(name='bob', role='editor'), 'delete', 'bob') is False

def test_R5_missing_role_owner_still_reads():
    assert is_allowed({'name': 'bob', 'active': True}, 'read', 'bob') is True
    assert is_allowed({'name': 'bob', 'active': True}, 'read', 'carl') is False

def test_R6_returns_bool_type():
    assert type(is_allowed(u(role='editor'), 'read', 'z')) is bool
    assert type(is_allowed(u(role='viewer'), 'delete', 'z')) is bool

def test_sec_R7_perform_denied_no_audit():
    audit = []
    with pytest.raises(PermissionError):
        perform(u(role='viewer'), 'delete', 'bob', audit)
    assert audit == []

def test_sec_R7_perform_unknown_action_no_audit():
    audit = []
    with pytest.raises(ValueError):
        perform(u(role='admin'), 'purge', 'bob', audit)
    assert audit == []

def test_R8_perform_success():
    audit = ['prior']
    assert perform(u(name='ann', role='admin'), 'delete', 'bob', audit) == 'ok'
    assert audit == ['prior', 'ann:delete:bob']
