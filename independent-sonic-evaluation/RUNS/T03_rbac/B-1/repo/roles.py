"""Scaffold. Verify behavior before use."""

def permissions_for(role: str) -> set:
    perms = set()
    if role == 'admin':
        perms = set(['read', 'write', 'delete'])
    elif role == 'editor':
        perms = set(['read', 'write'])
    elif role == 'viewer':
        perms = set(['read'])
    return perms
