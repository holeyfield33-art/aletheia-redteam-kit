## Task (natural-language specification)

Create one module, `policy.py`, containing exactly these functions:

- `check_password(password: str, username: str) -> list`
- `is_acceptable(password: str, username: str) -> bool`

No other modules, top-level statements or third-party dependencies are required.

## Requirements

- R1 (security/validation): check_password raises TypeError if password or username is not a str.
- R2: check_password returns a list of violation codes in this fixed order, each at most once: 'too_short' if len(password) < 12; 'no_digit' if no character is a digit (str.isdigit); 'no_upper' if no character is uppercase (str.isupper); 'no_lower' if no character is lowercase (str.islower); 'contains_username' if username is non-empty and username.lower() occurs in password.lower().
- R3: A password of exactly 12 characters is long enough. An empty username never triggers 'contains_username'.
- R4: check_password returns [] for a compliant password.
- R5 (security/validation): is_acceptable returns True only when check_password(password, username) returns an empty list; it must call check_password and propagate its TypeError.
