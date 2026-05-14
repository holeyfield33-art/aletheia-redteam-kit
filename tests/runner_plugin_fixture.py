name = "fixture-plugin"


def transform_attacks(attacks, args):
    mutated = [dict(attack) for attack in attacks]
    for attack in mutated:
        attack["plugin_attack"] = True
    return mutated


def transform_result(result, attack, args):
    updated = dict(result)
    updated["plugin_result"] = attack.get("id")
    return updated


def finalize_summary(summary, results, args):
    updated = dict(summary)
    updated["plugin_result_count"] = len(results)
    return updated