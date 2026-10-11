Completed. Filled both TODO placeholders in place, preserving signatures, imports, and statement order.

Files written in repo/:
- roles.py — permissions_for: builds a fresh set via `set()`/`set([...])` per role (admin/editor/viewer), empty set for anything else (incl. None/''). New set each call, so mutation is isolated (R1). Used only the allowed `set` call.
- access.py — is_allowed: kept the two spec branches (ValueError-first on bad action R2, deny unless active is exactly True R3), then `granted = action in permissions_for(user.get('role','')) or (user.get('name') == owner and action in ('read','write'))` (R4/R5, owners cannot delete). Expression is boolean-valued so returns bool (R6). perform: raises PermissionError('denied') when not allowed with audit untouched, and ValueError propagates before any append (R7); on success appends exactly one f"{user['name']}:{action}:{owner}" and returns 'ok' (R8). Used only allowed calls (permissions_for, user.get, audit.append).

Own checks: wrote one behavioral test covering R1-R8; ran checks 1 time; all passed ("ALL OK").

No requirement conflicts with the provided materials.
