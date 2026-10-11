Done. Wrote `repo/limiter.py` containing exactly the `allow(state, client, now, limit, window)` function.

Implementation:
- R1: raises ValueError before touching state when limit<=0 or window<=0.
- R2/R3: reads state.get(client, []); keeps timestamps where t > now - window (boundary t == now-window treated as expired).
- R4: if len(recent) < limit, append now, store as state[client], return True.
- R5: otherwise store pruned recent (without now) as state[client], return False.
- R6: only state[client] is assigned; other clients untouched.
- R7: `recent` is a fresh list from a comprehension, so the previously stored list is never mutated in place.

Checks: wrote and ran one script in scratch covering all R1-R7 (including boundary expiry, no-mutation, other-client isolation). Ran checks 1 time; ALL PASS.

No requirements conflict with the materials.
