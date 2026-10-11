from roles import permissions_for

_VALID_ACTIONS = {'read', 'write', 'delete'}


def is_allowed(user: dict, action: str, owner: str) -> bool:
    if action not in _VALID_ACTIONS:
        raise ValueError(action)
    if user.get('active') is not True:
        return False
    if action in permissions_for(user.get('role', '')):
        return True
    if user.get('name') == owner and action in ('read', 'write'):
        return True
    return False


def perform(user: dict, action: str, owner: str, audit: list) -> str:
    if not is_allowed(user, action, owner):
        raise PermissionError('denied')
    audit.append(f"{user['name']}:{action}:{owner}")
    return 'ok'
