"""Generated from an audible template. Verify behavior before use."""
from roles import permissions_for

def is_allowed(user: dict, action: str, owner: str) -> bool:
    if action not in ('read', 'write', 'delete'):
        raise ValueError('unknown action')
    if user.get('active') is not True:
        return False
    granted = action in permissions_for(user.get('role', '')) or (user.get('name') == owner and action in ('read', 'write'))
    return granted

def perform(user: dict, action: str, owner: str, audit: list) -> str:
    if not is_allowed(user, action, owner):
        raise PermissionError('denied')
    audit.append(f"{user['name']}:{action}:{owner}")
    return 'ok'
