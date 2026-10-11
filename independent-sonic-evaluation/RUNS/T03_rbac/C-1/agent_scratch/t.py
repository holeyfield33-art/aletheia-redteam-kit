import sys
sys.path.insert(0, '/tmp/claude-0/-home-user-aletheia-redteam-kit/fe51d682-0577-53e5-8f5b-f05cb53542c4/scratchpad/ws/run-19/repo')
from roles import permissions_for
from access import is_allowed, perform

# R1
assert permissions_for('admin') == {'read','write','delete'}
assert permissions_for('editor') == {'read','write'}
assert permissions_for('viewer') == {'read'}
assert permissions_for('x') == set()
assert permissions_for(None) == set()
assert permissions_for('') == set()
a = permissions_for('admin'); a.add('zz')
assert permissions_for('admin') == {'read','write','delete'}
assert permissions_for('admin') is not permissions_for('admin')

# R2 first
try:
    is_allowed({'active': False}, 'bad', 'o'); assert False
except ValueError: pass

# R3
assert is_allowed({'role':'admin'}, 'read', 'o') is False  # missing active
assert is_allowed({'active':1,'role':'admin'}, 'read', 'o') is False
assert is_allowed({'active':'yes','role':'admin'}, 'read', 'o') is False

# R4
assert is_allowed({'active':True,'role':'admin'}, 'delete', 'o') is True
assert is_allowed({'active':True,'role':'viewer'}, 'write', 'o') is False

# R5 owner
assert is_allowed({'active':True,'role':'viewer','name':'bob'}, 'write', 'bob') is True
assert is_allowed({'active':True,'role':'viewer','name':'bob'}, 'delete', 'bob') is False  # owner no delete
assert is_allowed({'active':True,'role':'admin','name':'bob'}, 'delete', 'bob') is True  # role grants

# R6 bool
assert isinstance(is_allowed({'active':True,'role':'viewer'}, 'read','o'), bool)

# R7
audit=[]
try:
    perform({'active':True,'role':'viewer','name':'b'}, 'delete','x', audit); assert False
except PermissionError as e:
    assert str(e)=='denied'
assert audit==[]
try:
    perform({'active':True,'role':'admin','name':'b'}, 'bad','x', audit); assert False
except ValueError: pass
assert audit==[]

# R8
audit=[]
assert perform({'active':True,'role':'admin','name':'b'}, 'delete','x', audit)=='ok'
assert audit==['b:delete:x']
print("ALL OK")
