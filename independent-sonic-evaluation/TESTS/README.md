# Hidden behavioral tests

`<task>/test_hidden.py` holds the frozen tests. Names encode requirement IDs (`R3`), and the
`test_sec_` prefix marks validation and authorization tests. `<task>/reference/` holds the
evaluator's reference solution, which is conformant with the score and passes every test.

These files were kept outside the repository until all 60 attempts had been collected. Their
SHA-256 hashes were committed beforehand in `../FREEZE.json`, and they match byte for byte.
