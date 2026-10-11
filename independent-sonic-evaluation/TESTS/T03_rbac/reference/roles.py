def permissions_for(role: str) -> set:
    perms = set()
    if role == 'admin':
        perms = {'read', 'write', 'delete'}
    elif role == 'editor':
        perms = {'read', 'write'}
    elif role == 'viewer':
        perms = {'read'}
    return perms
