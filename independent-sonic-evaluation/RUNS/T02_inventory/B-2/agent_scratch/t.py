import sys; sys.path.insert(0, "/tmp/claude-0/-home-user-aletheia-redteam-kit/fe51d682-0577-53e5-8f5b-f05cb53542c4/scratchpad/ws/run-35/repo")
import inventory as inv

# check_qty
assert inv.check_qty(5) is None
for bad in (True, 1.0, "x"):
    try: inv.check_qty(bad); assert False
    except TypeError: pass
try: inv.check_qty(0); assert False
except ValueError: pass

# reserve ok
s={"a":10,"b":5}
assert inv.reserve(s,"a",3)==7 and s=={"a":7,"b":5}
# reserve insufficient leaves unchanged
s2={"a":2}
try: inv.reserve(s2,"a",5); assert False
except ValueError: pass
assert s2=={"a":2}
# KeyError
try: inv.reserve({"a":1},"z",1); assert False
except KeyError: pass
# check_qty before KeyError
try: inv.reserve({"a":1},"z",0); assert False
except ValueError: pass
# release
s3={"a":1}
assert inv.release(s3,"a",4)==5 and s3=={"a":1+4}
try: inv.release({"a":1},"z",1); assert False
except KeyError: pass
print("ALL PASS")
