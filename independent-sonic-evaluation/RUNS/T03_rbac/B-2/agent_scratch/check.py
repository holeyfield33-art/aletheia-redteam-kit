import sys
sys.path.insert(0, '/tmp/claude-0/-home-user-aletheia-redteam-kit/fe51d682-0577-53e5-8f5b-f05cb53542c4/scratchpad/ws/run-36/repo')
from roles import permissions_for
from access import is_allowed, perform

# R1
assert permissions_for('admin') == {'read', 'write', 'delete'}
assert permissions_for('editor') == {'read', 'write'}
assert permissions_for('viewer') == {'read'}
assert permissions_for('x') == set()
assert permissions_for(None) == set()
assert permissions_for('') == set()
a = permissions_for('admin'); a.add('zzz')
assert permissions_for('admin') == {'read', 'write', 'delete'}

# R2
for inactive in [{}, {'active': False}]:
    try:
        is_allowed(inactive, 'bad', 'o'); assert False
    except ValueError:
        pass

# R3
assert is_allowed({'role': 'admin'}, 'read', 'o') is False
assert is_allowed({'active': 1, 'role': 'admin'}, 'read', 'o') is False
assert is_allowed({'active': 'yes', 'role': 'admin'}, 'read', 'o') is False

# R4
assert is_allowed({'active': True, 'role': 'admin'}, 'delete', 'o') is True
assert is_allowed({'active': True, 'role': 'viewer'}, 'read', 'o') is True
assert is_allowed({'active': True, 'role': 'viewer'}, 'write', 'o') is False

# R5
u = {'active': True, 'role': 'viewer', 'name': 'bob'}
assert is_allowed(u, 'write', 'bob') is True
assert is_allowed(u, 'read', 'bob') is True
assert is_allowed(u, 'delete', 'bob') is False  # owner can't delete unless role grants
assert is_allowed({'active': True, 'role': 'admin', 'name': 'bob'}, 'delete', 'bob') is True

# R6
assert is_allowed({'active': True, 'role': 'x', 'name': 'bob'}, 'read', 'alice') is False

# R7
audit = []
try:
    perform({'active': True, 'role': 'viewer', 'name': 'b'}, 'delete', 'b', audit); assert False
except PermissionError as e:
    assert str(e) == 'denied'
assert audit == []
try:
    perform({'active': True, 'name': 'b'}, 'bad', 'b', audit); assert False
except ValueError:
    pass
assert audit == []

# R8
r = perform({'active': True, 'role': 'editor', 'name': 'b'}, 'write', 'o', audit)
assert r == 'ok'
assert audit == ['b:write:o']

print("ALL PASS")
