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

- R1 (security/validation): check_qty raises TypeError if qty is not an int or is a bool, and ValueError if qty <= 0; otherwise it returns None.
- R2 (security/validation): reserve and release must call check_qty(qty) before doing anything else.
- R3 (security/validation): If sku is not a key of stock, reserve and release raise KeyError.
- R4 (security/validation): reserve raises ValueError if stock[sku] < qty, and must leave stock completely unchanged in that case.
- R5: reserve decreases stock[sku] by qty in place and returns the new level for that sku.
- R6: release increases stock[sku] by qty in place and returns the new level for that sku.
- R7: Neither function may add or remove keys of stock or change other skus.

## Exact scaffold

### inventory.py

```python
"""Scaffold. Verify behavior before use."""

def check_qty(qty: int) -> None:
    if not isinstance(qty, int) or isinstance(qty, bool):
        raise TypeError('qty must be an int')
    if qty <= 0:
        raise ValueError('qty must be positive')
    return None

def reserve(stock: dict, sku: str, qty: int) -> int:
    check_qty(qty)
    if sku not in stock:
        raise KeyError(sku)
    if stock[sku] < qty:
        raise ValueError('insufficient stock')
    raise NotImplementedError('TODO:Decrease stock[sku] by qty in place and set remaining to the new level')
    return remaining

def release(stock: dict, sku: str, qty: int) -> int:
    check_qty(qty)
    if sku not in stock:
        raise KeyError(sku)
    raise NotImplementedError('TODO:Increase stock[sku] by qty in place and set remaining to the new level')
    return remaining
```

### spec.json

```json
{
  "format": "structured-spec-v1",
  "title": "T02 inventory reserve and release",
  "requirements": [
    "R1 (security/validation): check_qty raises TypeError if qty is not an int or is a bool, and ValueError if qty <= 0; otherwise it returns None.",
    "R2 (security/validation): reserve and release must call check_qty(qty) before doing anything else.",
    "R3 (security/validation): If sku is not a key of stock, reserve and release raise KeyError.",
    "R4 (security/validation): reserve raises ValueError if stock[sku] < qty, and must leave stock completely unchanged in that case.",
    "R5: reserve decreases stock[sku] by qty in place and returns the new level for that sku.",
    "R6: release increases stock[sku] by qty in place and returns the new level for that sku.",
    "R7: Neither function may add or remove keys of stock or change other skus."
  ],
  "modules": [
    {
      "path": "inventory.py",
      "imports": [],
      "functions": [
        {
          "name": "check_qty",
          "parameters": [
            {
              "name": "qty",
              "type": "int"
            }
          ],
          "returns": "None",
          "body": [
            {
              "kind": "branch",
              "condition": "not isinstance(qty, int) or isinstance(qty, bool)",
              "body": [
                {
                  "kind": "raise",
                  "expression": "TypeError('qty must be an int')"
                }
              ],
              "otherwise": []
            },
            {
              "kind": "branch",
              "condition": "qty <= 0",
              "body": [
                {
                  "kind": "raise",
                  "expression": "ValueError('qty must be positive')"
                }
              ],
              "otherwise": []
            },
            {
              "kind": "return",
              "expression": "None"
            }
          ],
          "requirements": []
        },
        {
          "name": "reserve",
          "parameters": [
            {
              "name": "stock",
              "type": "dict"
            },
            {
              "name": "sku",
              "type": "str"
            },
            {
              "name": "qty",
              "type": "int"
            }
          ],
          "returns": "int",
          "body": [
            {
              "kind": "validate",
              "expression": "check_qty(qty)"
            },
            {
              "kind": "branch",
              "condition": "sku not in stock",
              "body": [
                {
                  "kind": "raise",
                  "expression": "KeyError(sku)"
                }
              ],
              "otherwise": []
            },
            {
              "kind": "branch",
              "condition": "stock[sku] < qty",
              "body": [
                {
                  "kind": "raise",
                  "expression": "ValueError('insufficient stock')"
                }
              ],
              "otherwise": []
            },
            {
              "kind": "todo",
              "label": "Decrease stock[sku] by qty in place and set remaining to the new level",
              "allowed_calls": []
            },
            {
              "kind": "return",
              "expression": "remaining"
            }
          ],
          "requirements": []
        },
        {
          "name": "release",
          "parameters": [
            {
              "name": "stock",
              "type": "dict"
            },
            {
              "name": "sku",
              "type": "str"
            },
            {
              "name": "qty",
              "type": "int"
            }
          ],
          "returns": "int",
          "body": [
            {
              "kind": "validate",
              "expression": "check_qty(qty)"
            },
            {
              "kind": "branch",
              "condition": "sku not in stock",
              "body": [
                {
                  "kind": "raise",
                  "expression": "KeyError(sku)"
                }
              ],
              "otherwise": []
            },
            {
              "kind": "todo",
              "label": "Increase stock[sku] by qty in place and set remaining to the new level",
              "allowed_calls": []
            },
            {
              "kind": "return",
              "expression": "remaining"
            }
          ],
          "requirements": []
        }
      ]
    }
  ]
}
```
