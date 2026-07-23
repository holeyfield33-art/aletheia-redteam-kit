---
description: Clone a repo into targets/ and run the full aletheia-redteam-kit audit pipeline against it
---

Target repo: $ARGUMENTS

Run the full audit pipeline against this repo, the same way it's been done for
`Aletheia-Lite` and `runtime-firewall-mvp` in this project's history. Steps:

1. **Clone.** `git clone <url>` into `targets/<repo-name>` (create `targets/` if
   missing). If it already exists there, `git -C targets/<repo-name> pull` instead
   of re-cloning.

2. **Static audit (always).** From the aletheia-redteam-kit root, with its `.venv`
   activated:
   ```
   python -m kit.runner --mode repo --repo-path targets/<repo-name> --output targets/<repo-name>-repo-summary.json
   ```
   Read the findings back with a small `python -c` snippet (see prior runs in this
   session for the pattern) — don't just report the one-line risk score. Break
   findings down by type/severity and **sanity-check them before reporting**:
   - `dependency_vulnerability` findings are real (they come from `npm audit` /
     `pip-audit`) — always report these as-is.
   - `javascript_eval` / `javascript_function_constructor` / similar pattern-match
     findings are frequently noise on security tooling repos, since the repo's own
     detection signatures and adversarial test corpora contain the literal strings
     being searched for. Check whether the hit is in `src/`/production code vs.
     `test/`, `corpus/`, `red-team/`, or a signature-definitions file before
     treating it as a real finding.
   - A private key or secret committed to the repo is worth flagging even if the
     project's own docs describe it as an intentional dev/CI convenience key —
     just report it with that context, don't alarm unnecessarily.

3. **Detect the project's own test/audit tooling** rather than assuming one stack.
   Check for (in rough priority order):
   - `pyproject.toml` / `requirements.txt` → Python. Create a venv, install (prefer
     an editable install with dev/test extras — check `pyproject.toml` for extras
     names like `[dev]`, `[test]`, `[verify]`), then run `pytest`.
   - `package.json` → Node. Run `npm install`, then check `package.json` scripts
     for a `test` script and any domain-specific adversarial/red-team script (look
     for script names containing `redteam`, `adversarial`, `attack`, `fuzz`,
     `security`). Run `npm test` AND any such red-team script — they are usually
     not the same thing and both matter.
   - Note: on Windows, npm's default shell doesn't support inline `VAR=1 command`
     env-var syntax even inside a script that itself runs fine on Linux CI. If an
     `npm test`-invoked sub-script fails with "'VAR' is not recognized as an
     internal or external command", that's this shell quirk, not a real failure —
     re-run the underlying command directly with the env var exported first before
     concluding it's broken.
   - If a file required by the project's own test/red-team suite goes missing
     between runs (`MODULE_NOT_FOUND` for a file `git status` shows as a local
     deletion, not an upstream removal) and the missing file's content looks like
     a malware/exploit test fixture (crypto-miner, reverse-shell, credential
     stealer signatures, etc.), suspect local antivirus/Defender quarantine, not
     a repo bug. Confirm via `git status --short` (shows ` D <path>` for a file
     still tracked upstream) and `git checkout -- <path>` to restore; if it
     disappears again on its own, that confirms AV interference — tell the user,
     don't debug it as a code issue.
   - Only fall back to feeding this kit's own `attacks/` catalog (prompt
     injection, jailbreak, exfil payloads) through the target if the target is
     itself an LLM/agent guardrail with a text-in/verdict-out interface (like
     Aletheia-Lite's `core check`). Do NOT do this for a target whose threat model
     is unrelated (e.g. supply-chain/malware detection, network security,
     unrelated web apps) — use whatever red-team harness the target ships with
     instead, or say plainly there isn't an applicable adversarial angle beyond
     the static audit.

4. **Report.** One clear summary: what passed cleanly, what's a real finding vs.
   noise (and why), and any environment gotchas hit along the way (AV quarantine,
   shell syntax, etc.) so they don't get mistaken for target-repo bugs next time.

Don't ask for confirmation before running read-only audit/test commands — this is
the user's own repo. Do check before anything that writes back to the remote
(commits, pushes, PRs) or installs anything outside the cloned repo's own venv/
node_modules.
