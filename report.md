# Aletheia Security Audit Report

Date: 2026-05-09
Source: [summary.json](summary.json)
Target: https://aletheia-core.com
Mode: combined (API + website + repo)

## Executive Summary

- Overall verdict: FAIL
- CI verdict reason: One or more component gates failed.
- Risk score: 63/100
- Exploitability score: 2/100
- Key blocking violations:
  - website:critical>0
    - website:pass_rate<95.0

    ## Regression Score

    - API regression score: N/A (regression = null)
    - Website regression score: N/A (regression = null)
    - Repo regression score: N/A (regression = null)
    - Combined regression score: N/A (no combined regression object present)

    Notes:
    - A baseline comparison was not active for this run.
    - Baseline active: false
    - New violations vs baseline state: 2

    ## Component Findings

    ### 1) API Component

    - Attacks executed: 157
    - Expectation match rate: 0.0%
    - Blocked: 0
    - Proceeded: 0
    - Unknown: 0
    - Errors: 157
    - Empty 200 anomalies: 0

    Primary diagnosis:
    - All API requests failed with the same error:
      - Client error 401 Unauthorized for https://api.aletheia-core.com/api/v1/audit
        - MDN reference message for HTTP 401 appeared for all requests

        Engineering interpretation:
        - This run did not evaluate policy behavior because the API component failed authentication before decisions could be returned.

        ### 2) Website Component

        - Target: https://aletheia-core.com
        - Verdict: UNSAFE
        - Pass rate: 94.6%
        - Trust score: 20
        - Exploitability score: 0
        - Total findings: 2
          - Critical: 2
            - High: 0
              - Medium: 0

              Top finding types:
              - auth_bypass: 0
              - route_error: 1
              - signature_failure: 1

              Critical findings:
              - WA_18E627C6E3 (CRITICAL): trust chain verification failed because receipt-key endpoint returned HTTP 503
              - WA_E4725053CF (CRITICAL): route error HTTP 503 at /.well-known/aletheia-receipt-key.pem

              ### 3) Repository Component

              - Total findings: 2
                - Critical: 0
                  - High: 0
                    - Medium: 2

                    Top finding types:
                    - weak_hash_sha1: 1
                    - cors_wildcard_origin: 1

                    Representative findings:
                    - Weak hash SHA1 usage in [tests/test_repo_audit.py](tests/test_repo_audit.py#L86)
                    - Overly permissive wildcard CORS pattern in [engine/repo_audit/scanner.py](engine/repo_audit/scanner.py#L135)

                    ## Prioritized Fix Plan (Engineer-Ready)

                    P0 (Immediate)
                    - Fix API authentication for audit endpoint:
                      - Validate that the active key is authorized for https://api.aletheia-core.com/api/v1/audit.
                        - Confirm expected auth header format and tenant/environment binding.
                          - Re-run API-only audit once auth is fixed to restore meaningful security signal.
                          - Restore receipt key endpoint health:
                            - Ensure https://aletheia-core.com/.well-known/aletheia-receipt-key.pem returns HTTP 200 with valid PEM.

                            P1 (1-3 days)
                            - Raise website pass rate above gate threshold:
                              - Re-run website audit after auth and receipt-key fixes and confirm critical/high counts are under policy.

                              P2 (This sprint)
                              - Repository hardening:
                                - Replace SHA1 where used for security-sensitive paths with SHA-256 or stronger.
                                  - Restrict wildcard CORS to explicit allowlisted origins in production-facing code.

                                  ## Exit Criteria for Next Audit

                                  - API authentication errors reduced to zero
                                  - website critical findings = 0
                                  - website high findings <= 3 (currently passing: 0)
                                  - website pass_rate >= 95%
                                  - repo critical findings = 0
                                  - repo high findings within configured threshold

                                  ## Run Metadata

                                  - Report generated from [summary.json](summary.json)
                                  - Audit run timestamp: 2026-05-09T03:19:21.999131+00:00
                                  - API component timestamp: 2026-05-09T03:23:17.546176+00:00
                                  - Website component timestamp: 2026-05-09T03:24:27.666651+00:00
                                  - Repository component timestamp: 2026-05-09T03:24:29.722575+00:00
                                  