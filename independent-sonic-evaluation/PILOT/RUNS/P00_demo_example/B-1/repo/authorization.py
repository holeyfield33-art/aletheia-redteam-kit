"""Scaffold. Verify behavior before use."""

def require_authorized(role: str) -> None:
    if role != 'admin':
        raise PermissionError('admin required')
    return None
