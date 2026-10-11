def require_authorized(role: str) -> None:
    if role != "admin":
        raise PermissionError("role must be admin")
