# SECURITY_RISK_REGISTER

| finding_id | severity | owner | decision | expiry_date | notes |
|---|---|---|---|---|---|
| WEB-REC-SIG-001 | CRITICAL | platform-security | mitigate | 2026-06-15 | Receipt signature verification failure remains a stop-ship issue until invalid signatures hard-fail and regression coverage passes twice. |
| WEB-PROMPT-INJ-001 | HIGH | product-security | mitigate | 2026-06-15 | Website prompt-injection regression must be closed and revalidated before promotion. |
| API-OBF-001 | HIGH | adversarial-engineering | mitigate | 2026-06-15 | Obfuscated payload bypass must be eliminated; OB_001 remains the reference regression case. |
| RUN-QUOTA-001 | MEDIUM | runner-maintainers | defer | 2026-06-01 | Combined-run quota exhaustion should trip a quota_limited stop condition instead of draining remaining requests. |

## Stop-Ship Policy
- Critical website findings remain stop-ship until revalidated cleanly.
- Any open bypass class remains stop-ship until the corresponding regression is closed twice in a row.
