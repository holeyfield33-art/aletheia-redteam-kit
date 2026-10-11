# Benchmark tasks

Each `Txx_*` directory holds the following:
- `score.json`: the exact `sonic-template-v1` score. Its `requirements` are the shared requirement
  bullets, used verbatim in all three conditions.
- `interface.md`: the plain-English module and signature description given to condition A.
- `conditions/A|B|C/materials.md`: exactly what was inlined into the prompt after the common
  wrapper.
- `conditions/A|B|C/workspace/`: the files copied into every attempt's fresh workspace. Condition C
  is the unmodified output of Sonic's `write_project()`, including `template.wav`.

`_validation.json` holds the pre-freeze check: valid score, conformant reference, reference passes
every hidden test, and the number of tests the unfilled scaffold already passes.
`_condition_sizes.json` holds material sizes.
