Done. Wrote two flat modules in repo/:

- `roles.py` — `permissions_for(role)` returning a fresh set each call (admin/editor/viewer mappings, empty set for anything else including None/''; never raises; mutation-safe via `set(table.get(...))`).
- `access.py` — `is_allowed(user, action, owner)` and `perform(user, action, owner, audit)`, importing via `from roles import permissions_for`.

Logic ordering matches the spec: is_allowed validates action first (ValueError, even for inactive users), then requires `active is True` exactly, then grants by role permissions, then owner read/write (not delete). Always returns a real bool. perform raises PermissionError('denied') when not allowed and leaves audit untouched on both denial and ValueError; on success appends exactly `name:action:owner` and returns 'ok'.

My own checks: ran 1 time, all assertions passed (R1–R8 covered, including mutation-safety, active-key strictness for 1/'yes'/missing, owner-delete denial, bool type, and audit-unchanged-on-failure).

No conflicts between requirements and the materials.
