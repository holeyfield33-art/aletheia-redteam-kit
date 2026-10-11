import sys
sys.path.insert(0, "/tmp/claude-0/-home-user-aletheia-redteam-kit/fe51d682-0577-53e5-8f5b-f05cb53542c4/scratchpad/ws/run-06/repo")
from limiter import allow

# R1
s={"a":[1]}
try:
    allow(s,"a",10,0,5); print("FAIL R1 limit")
except ValueError: assert s=={"a":[1]}, "R1 state changed"
try:
    allow(s,"a",10,2,0); print("FAIL R1 window")
except ValueError: assert s=={"a":[1]}

# R2 no entry
s={}
assert allow(s,"x",100,2,10) is True
assert s=={"x":[100]}

# R3 boundary: t == now-window expired
s={"c":[90,95]}  # now=100 window=10 -> now-window=90; 90 expired, 95 recent
r=allow(s,"c",100,5,10)
assert r is True
assert s["c"]==[95,100], s["c"]

# R4 below limit append and True
s={"c":[95]}
assert allow(s,"c",100,2,10) is True
assert s["c"]==[95,100]

# R5 at limit -> False, pruned stored, now not recorded
s={"c":[91,92,93]}  # now=100 window=10 all recent (>90), limit 3
r=allow(s,"c",100,3,10)
assert r is False
assert s["c"]==[91,92,93], s["c"]  # pruned (none expired), now not added

# R5 with expired pruned
s={"c":[80,91,92,93]}  # 80 expired
r=allow(s,"c",100,3,10)
assert r is False
assert s["c"]==[91,92,93]

# R6 other clients untouched
s={"c":[95],"other":[1,2]}
allow(s,"c",100,2,10)
assert s["other"]==[1,2]

# R7 original list not mutated
orig=[95]
s={"c":orig}
allow(s,"c",100,2,10)
assert orig==[95], orig

print("ALL PASS")
