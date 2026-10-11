Done. Filled the single `__SONIC_HOLE__` in the Sonic Code Studio bundle.

Files written in repo/:
- orders.py — replaced `raise NotImplementedError('__SONIC_HOLE__:Set receipt to amount * 100')` with `receipt = amount * 100`. All other structure preserved exactly: docstring, both imports, signature, the `require_positive(amount)` and `require_authorized(role)` calls before implementation, and the final `return receipt`.
- validation.py and authorization.py — already complete and correct in the scaffold (no holes); left unchanged.

Checks: I wrote and ran one behavioral test (1 check run) covering all stated requirements. All passed.

No requirement conflicts with the provided materials.
