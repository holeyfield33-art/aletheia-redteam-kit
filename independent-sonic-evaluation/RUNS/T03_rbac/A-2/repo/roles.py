def permissions_for(role: str) -> set:
    mapping = {
        'admin': {'read', 'write', 'delete'},
        'editor': {'read', 'write'},
        'viewer': {'read'},
    }
    return set(mapping.get(role, set()))
