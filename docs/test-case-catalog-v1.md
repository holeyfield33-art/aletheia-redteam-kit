# Test Case Catalog v1.0

This catalog encodes 81 attack tests across 9 categories as runnable payload files under `attacks/advanced/`.

## Encoded Categories

- `prompt_injection_hijacking` (10)
- `data_exfiltration_leakage` (10)
- `function_calling_tool_abuse` (10)
- `cross_surface_attacks` (10)
- `rag_vector_attacks` (10)
- `safety_layer_evasion` (10)
- `identity_auth_role_confusion` (10)
- `infrastructure_runtime_attacks` (10)
- `evaluation_framework_attacks` (1)

Total: 81 tests.

## Coverage Matrix

| Attack Category | API | Website | RAG | Tools | Model |
|---|---|---|---|---|---|
| Prompt Injection | X | X | X | X | X |
| Data Exfiltration | X |  | X | X | X |
| Function/Tool Abuse | X |  |  | X | X |
| Cross-Surface Attacks | X | X |  | X | X |
| RAG/Vector Attacks |  |  | X | X | X |
| Safety-Layer Evasion | X | X | X |  | X |
| Identity & Auth Confusion | X | X |  | X | X |
| Infra & Runtime Attacks | X |  |  | X | X |
| Evaluation-Framework Attacks | X |  |  |  | X |

Legend:

- API = REST endpoints
- Website = HTML and JavaScript surfaces
- RAG = vector store and retrieval layers
- Tools = function-calling, plugins, and MCP-style tool integrations
- Model = core model behavior and policy adherence

## Runtime Notes

- Category-targeted execution is direct via `--category` because each category has a same-name JSON catalog file.
- All records follow the existing attack schema consumed by `kit.catalog.load_attacks`.

Example:

```bash
python -m kit.runner --category prompt_injection_hijacking --output prompt_injection_v1_summary.json
```