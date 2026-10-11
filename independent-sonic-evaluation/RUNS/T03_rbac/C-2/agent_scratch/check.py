import sys
sys.path.insert(0, '/tmp/claude-0/-home-user-aletheia-redteam-kit/fe51d682-0577-53e5-8f5b-f05cb53542c4/scratchpad/ws/run-56/repo')
from roles import permissions_for
from access import is_allowed, perform

# R1
assert permissions_for('admin') == {'read','write','delete'}
assert permissions_for('editor') == {'read','write'}
assert permissions_for('viewer') == {'read'}
assert permissions_for('x') == set()
assert permissions_for(None) == set()
assert permissions_for('') == set()
a = permissions_for('admin'); a.add('zzz')
assert permissions_for('admin') == {'read','write','delete'}  # new set each time

# R2 validation first, even inactive
try:
    is_allowed({'active': False}, 'bogus', 'o'); assert False
except ValueError: pass

# R3 active must be exactly True
assert is_allowed({'role':'admin'}, 'read', 'o') is False
assert is_allowed({'active':1,'role':'admin'}, 'read', 'o') is False
assert is_allowed({'active':'yes','role':'admin'}, 'read', 'o') is False
assert is_allowed({'active':False,'role':'admin'}, 'read', 'o') is False

# R4
assert is_allowed({'active':True,'role':'admin'}, 'delete', 'o') is True
assert is_allowed({'active':True,'role':'viewer'}, 'read', 'o') is True
assert is_allowed({'active':True,'role':'viewer'}, 'write', 'o') is False

# R5 owner read/write not delete
assert is_allowed({'active':True,'role':'viewer','name':'alice'}, 'write', 'alice') is True
assert is_allowed({'active':True,'role':'viewer','name':'alice'}, 'delete', 'alice') is False
# owner admin can delete via role
assert is_allowed({'active':True,'role':'admin','name':'alice'}, 'delete', 'alice') is True

# R6 bool
assert is_allowed({'active':True,'role':'viewer','name':'alice'}, 'delete', 'bob') is False
assert type(is_allowed({'active':True,'role':'admin'}, 'read', 'o')) is bool

# R7 perform denied, audit unchanged
aud=[]
try:
    perform({'active':True,'role':'viewer','name':'x'}, 'delete', 'o', aud); assert False
except PermissionError as e:
    assert str(e)=='denied'
assert aud==[]
# unknown action -> ValueError, audit unchanged
try:
    perform({'active':True,'role':'admin','name':'x'}, 'bogus', 'o', aud); assert False
except ValueError: pass
assert aud==[]

# R8 success
aud=[]
assert perform({'active':True,'role':'admin','name':'x'}, 'delete', 'o', aud)=='ok'
assert aud==['x:delete:o']
print("ALL OK")
