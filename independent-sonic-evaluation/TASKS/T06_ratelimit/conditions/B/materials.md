## Materials (structured specification and scaffold)

Your workspace contains HANDOFF.md, spec.json and repo/ (the scaffold to fill in place).

### HANDOFF.md

# Implement this Python scaffold

The accompanying spec.json is the exact structural plan.

Fill only the TODO placeholders. Preserve module paths, function
signatures, imports, required expressions, branch/loop nesting and statement
order. Each TODO lists its allowed calls. If a requirement cannot be met within
this plan, explain the conflict and propose an explicit spec revision.
Do not silently remove a check or widen the allowed calls/imports.

Run behavioral tests for the stated requirements. A structural comparison
checks syntax; passing it does not prove behavior, security or correctness.

## Requirements

- R1 (security/validation): If limit <= 0 or window <= 0, raise ValueError and leave state unchanged.
- R2: state maps client ids to lists of request timestamps (ints). A client with no entry has no history.
- R3: A previous timestamp t counts as recent only if t > now - window (a timestamp exactly window seconds old has expired).
- R4 (security/authorization): If the number of recent timestamps is below limit, append now, store the recent list as state[client], and return True.
- R5 (security/authorization): Otherwise return False without recording now; state[client] must still be replaced by the pruned recent list.
- R6: Other clients' entries in state are never modified.
- R7: The list previously stored for the client must not be mutated in place (build a new list).

## Exact scaffold

### limiter.py

```python
"""Scaffold. Verify behavior before use."""

def allow(state: dict, client: str, now: int, limit: int, window: int) -> bool:
    if limit <= 0 or window <= 0:
        raise ValueError('limit and window must be positive')
    raise NotImplementedError("TODO:Set recent to a new list of the client's timestamps in state that are strictly greater than now - window")
    if len(recent) < limit:
        recent.append(now)
        raise NotImplementedError('TODO:Store recent as state[client]')
        return True
    else:
        raise NotImplementedError('TODO:Store recent as state[client]')
        return False
```

### spec.json

```json
{
  "format": "structured-spec-v1",
  "title": "T06 sliding-window rate limiter",
  "requirements": [
    "R1 (security/validation): If limit <= 0 or window <= 0, raise ValueError and leave state unchanged.",
    "R2: state maps client ids to lists of request timestamps (ints). A client with no entry has no history.",
    "R3: A previous timestamp t counts as recent only if t > now - window (a timestamp exactly window seconds old has expired).",
    "R4 (security/authorization): If the number of recent timestamps is below limit, append now, store the recent list as state[client], and return True.",
    "R5 (security/authorization): Otherwise return False without recording now; state[client] must still be replaced by the pruned recent list.",
    "R6: Other clients' entries in state are never modified.",
    "R7: The list previously stored for the client must not be mutated in place (build a new list)."
  ],
  "modules": [
    {
      "path": "limiter.py",
      "imports": [],
      "functions": [
        {
          "name": "allow",
          "parameters": [
            {
              "name": "state",
              "type": "dict"
            },
            {
              "name": "client",
              "type": "str"
            },
            {
              "name": "now",
              "type": "int"
            },
            {
              "name": "limit",
              "type": "int"
            },
            {
              "name": "window",
              "type": "int"
            }
          ],
          "returns": "bool",
          "body": [
            {
              "kind": "branch",
              "condition": "limit <= 0 or window <= 0",
              "body": [
                {
                  "kind": "raise",
                  "expression": "ValueError('limit and window must be positive')"
                }
              ],
              "otherwise": []
            },
            {
              "kind": "todo",
              "label": "Set recent to a new list of the client's timestamps in state that are strictly greater than now - window",
              "allowed_calls": [
                "state.get"
              ]
            },
            {
              "kind": "branch",
              "condition": "len(recent) < limit",
              "body": [
                {
                  "kind": "call",
                  "expression": "recent.append(now)"
                },
                {
                  "kind": "todo",
                  "label": "Store recent as state[client]",
                  "allowed_calls": []
                },
                {
                  "kind": "return",
                  "expression": "True"
                }
              ],
              "otherwise": [
                {
                  "kind": "todo",
                  "label": "Store recent as state[client]",
                  "allowed_calls": []
                },
                {
                  "kind": "return",
                  "expression": "False"
                }
              ]
            }
          ],
          "requirements": []
        }
      ]
    }
  ]
}
```
