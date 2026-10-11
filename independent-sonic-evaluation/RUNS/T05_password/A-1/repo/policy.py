"""Password policy checks."""


def check_password(password: str, username: str) -> list:
    """Return a list of violation codes for the given password.

    Codes appear in a fixed order, each at most once. Raises TypeError if
    password or username is not a str.
    """
    if not isinstance(password, str) or not isinstance(username, str):
        raise TypeError("password and username must be str")

    violations = []

    if len(password) < 12:
        violations.append('too_short')
    if not any(c.isdigit() for c in password):
        violations.append('no_digit')
    if not any(c.isupper() for c in password):
        violations.append('no_upper')
    if not any(c.islower() for c in password):
        violations.append('no_lower')
    if username and username.lower() in password.lower():
        violations.append('contains_username')

    return violations


def is_acceptable(password: str, username: str) -> bool:
    """Return True only when check_password returns an empty list."""
    return check_password(password, username) == []
