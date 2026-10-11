def permissions_for(role: str) -> set:
    table = {
        'admin': {'read', 'write', 'delete'},
        'editor': {'read', 'write'},
        'viewer': {'read'},
    }
    return set(table.get(role, set()))
