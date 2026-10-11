import sys
sys.path.insert(0, "/tmp/claude-0/-home-user-aletheia-redteam-kit/fe51d682-0577-53e5-8f5b-f05cb53542c4/scratchpad/ws/run-30/repo")
from limiter import allow

# R1
for bad in [(0,5),(5,0),(-1,5),(5,-1)]:
    st={"a":[1]}
    try:
        allow(st,"a",10,*bad); print("R1 FAIL no raise")
    except ValueError:
        assert st=={"a":[1]}, "R1 state changed"
print("R1 ok")

# R2/R4 no entry
st={}
assert allow(st,"a",100,2,10) is True
assert st=={"a":[100]}
print("R4 ok", st)

# R3 boundary: t == now-window expired
st={"a":[90]}
# now=100 window=10 -> now-window=90, 90>90 False expired
assert allow(st,"a",100,1,10) is True  # recent empty, append 100
assert st=={"a":[100]}
print("R3 boundary ok")

# R3 strictly greater kept
st={"a":[91]}  # 91>90 kept, limit1 -> recent full -> False
r=allow(st,"a",100,1,10)
assert r is False, r
assert st=={"a":[91]}, st  # now not recorded, pruned
print("R5 ok", st)

# R5 prune in reject
st={"a":[80,95,96]}  # now=100 window=10 keep >90 -> [95,96], limit2 full -> False
r=allow(st,"a",100,2,10)
assert r is False
assert st=={"a":[95,96]}
print("R5 prune ok", st)

# R6 other clients untouched
st={"a":[100],"b":[1,2]}
allow(st,"a",101,5,10)
assert st["b"]==[1,2]
print("R6 ok")

# R7 no mutate original list
orig=[100]
st={"a":orig}
allow(st,"a",101,5,10)
assert orig==[100], orig
assert st["a"] is not orig
print("R7 ok")
print("ALL PASS")
