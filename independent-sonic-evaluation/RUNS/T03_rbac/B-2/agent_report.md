Completed. Filled both scaffold modules in run-36/repo/:

- roles.py: `permissions_for` returns a fresh set each call via `set((...))` branches (admin -> {read,write,delete}, editor -> {read,write}, viewer -> {read}, else empty set). Preserved the `return perms` statement; only the `set` call is used.
- access.py: `is_allowed` fills the TODO with `granted = action in permissions_for(user.get('role', '')) or (user.get('name') == owner and action in ('read', 'write'))` — a bool expression. `perform` fills the TODO with `audit.append(f"{user['name']}:{action}:{owner}")`. All pre-existing branches, the ValueError-first check, the active-is-True check, signatures and imports were preserved unchanged.

My own checks: wrote scratch/check.py covering R1-R8 (new-set independence, ValueError-before-active, exact `is True` active check, role perms, owner read/write-only, owner-cannot-delete, bool returns, denied PermissionError leaving audit unchanged for both PermissionError and ValueError paths, and success append + 'ok'). Ran checks once; result: ALL PASS.

No requirement conflicts with the provided scaffold — everything fit within the allowed calls and statement order.
