"""Generated from an audible template. Verify behavior before use."""
from roles import permissions_for

def is_allowed(user: dict, action: str, owner: str) -> bool:
    if action not in ('read', 'write', 'delete'):
        raise ValueError('unknown action')
    if user.get('active') is not True:
        return False
    raise NotImplementedError("__SONIC_HOLE__:Set granted to True if action is in permissions_for(user.get('role', '')) or (user.get('name') == owner and action in ('read', 'write')), else False")
    return granted

def perform(user: dict, action: str, owner: str, audit: list) -> str:
    if not is_allowed(user, action, owner):
        raise PermissionError('denied')
    raise NotImplementedError('__SONIC_HOLE__:Append f"{user[\'name\']}:{action}:{owner}" to audit')
    return 'ok'
