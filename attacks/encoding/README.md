# Encoding Payloads

This category contains payloads that wrap or transform malicious instructions through structured serialization, markdown formatting, or encoded transport layers.

Files in this directory:

- `obfuscated.json`: legacy obfuscation examples such as base64 and confusables.
- `json_encapsulated.json`: JSON object wrapper example for instruction smuggling.
- `markdown_injection.md.json`: markdown-wrapped injection example for rendering-aware parsers.
- `encoded_tool_args.json`: encoded-tool-argument regression cases. The sensitive material (secret name, credential path/token, path traversal) stays base64/hex-encoded *inside the tool argument* rather than the instruction, modeling a model that relays a retrieved encoded value into a tool call without decoding it. A target whose content-sensitivity check matches only the literal argument string is blind to these; it must decode candidate representations of the argument first.