"""Example runner plugin for API and agentic execution hooks.

Usage:
    python -m kit.runner --mode api --plugin docs/example_runner_plugin.py
"""


name = "example-runner-plugin"


def transform_attacks(attacks, args):
    updated = [dict(attack) for attack in attacks]
    for attack in updated:
        attack.setdefault("plugin_tags", []).append("example")
    return updated


def transform_result(result, attack, args):
    updated = dict(result)
    updated["plugin_notes"] = [f"example hook touched {attack.get('id', 'unknown')}"]
    return updated


def finalize_summary(summary, results, args):
    updated = dict(summary)
    updated["example_plugin"] = {
        "results_seen": len(results),
        "mode": getattr(args, "mode", "api") if args is not None else "api",
    }
    return updated