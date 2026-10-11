"""Section 9: what does the musical layer actually carry?

All audio is rendered by the ORIGINAL sonic_templates.audio.render_score.
Probes:
  P1 change a branch condition in the score (qty <= 0 -> qty < 0)
  P2 change names, messages and an expression, keeping element kinds
  P3 nesting ambiguity: a raise inside a branch vs. a raise after an empty branch
  P4 branch body vs. otherwise placement
  P5 semantically opposite security plans (authorization check present vs. replaced by a no-op call)
  P6 blind decoding of every benchmark template.wav back to a note sequence; compare with
     the score's element kinds and count how much of the score is recoverable
Output: MUSIC/music_probe.json
"""

import copy
import hashlib
import json
import math
import tempfile
import wave
from pathlib import Path

from common import EVAL, TASK_IDS, load_score, sonic, write_json

OUT = EVAL / "MUSIC"


def render_hash(score, tmp, name):
    s = sonic()
    path = Path(tmp) / f"{name}.wav"
    events = s["audio"].render_score(score, path)
    return hashlib.sha256(path.read_bytes()).hexdigest(), events, path


def decode(path):
    """Goertzel energy at each role pitch per beat; returns the dominant role per beat."""
    s = sonic()
    notes = s["schema"].NOTES
    rate, beat = s["audio"].SAMPLE_RATE, s["audio"].BEAT_SECONDS
    with wave.open(str(path)) as handle:
        frames = handle.readframes(handle.getnframes())
    samples = [int.from_bytes(frames[i:i + 2], "little", signed=True) for i in range(0, len(frames), 2)]
    per_beat = round(rate * beat)
    decoded = []
    for start in range(0, len(samples) - per_beat + 1, per_beat):
        chunk = samples[start:start + per_beat]
        best, best_power = None, -1.0
        for kind, note in notes.items():
            freq = 440 * 2 ** ((note - 69) / 12)
            coeff = 2 * math.cos(2 * math.pi * freq / rate)
            s1 = s2 = 0.0
            for x in chunk:
                s1, s2 = x + coeff * s1 - s2, s1
            power = s1 * s1 + s2 * s2 - coeff * s1 * s2
            if power > best_power:
                best, best_power = kind, power
        decoded.append(best)
    return decoded


def main():
    s = sonic()
    OUT.mkdir(exist_ok=True)
    validate = s["schema"].validate_score
    results = {}
    with tempfile.TemporaryDirectory() as tmp:
        t02 = load_score("T02_inventory")
        base_hash, _, _ = render_hash(t02, tmp, "t02")

        # P1 condition change
        p1 = copy.deepcopy(t02)
        p1["modules"][0]["functions"][0]["body"][1]["condition"] = "qty < 0"
        results["P1_condition_change"] = {"change": "check_qty: 'qty <= 0' -> 'qty < 0' in the score",
                                          "wav_identical": render_hash(validate(p1), tmp, "p1")[0] == base_hash}

        # P2 names, messages, expressions changed; kinds unchanged
        p2 = copy.deepcopy(t02)
        fn = p2["modules"][0]["functions"][2]
        fn["name"] = "restock_anything"
        fn["body"][1]["condition"] = "False"
        fn["body"][1]["body"][0]["expression"] = "RuntimeError('never')"
        results["P2_names_and_expressions"] = {
            "change": "rename release -> restock_anything, its sku guard -> 'False', exception type changed",
            "wav_identical": render_hash(validate(p2), tmp, "p2")[0] == base_hash}

        # P3 nesting ambiguity (minimal two-function scores, same module path)
        def one(body):
            return validate({"format": "sonic-template-v1", "modules": [{"path": "m.py", "functions": [
                {"name": "f", "parameters": [{"name": "x", "type": "int"}], "returns": "int", "body": body}]}]})
        nested = one([{"kind": "branch", "condition": "x < 0", "body": [{"kind": "raise", "expression": "ValueError()"}]},
                      {"kind": "return", "expression": "x"}])
        flat = one([{"kind": "branch", "condition": "x < 0", "body": []},
                    {"kind": "raise", "expression": "ValueError()"},
                    {"kind": "return", "expression": "x"}])
        h_nested, h_flat = render_hash(nested, tmp, "nested")[0], render_hash(flat, tmp, "flat")[0]
        results["P3_nesting"] = {
            "a": "if x < 0: raise ValueError(); return x   (rejects negatives)",
            "b": "if x < 0: pass; raise ValueError(); return x   (always raises)",
            "wav_identical": h_nested == h_flat}

        # P4 body vs otherwise
        other = one([{"kind": "branch", "condition": "x < 0", "body": [],
                      "otherwise": [{"kind": "raise", "expression": "ValueError()"}]},
                     {"kind": "return", "expression": "x"}])
        results["P4_body_vs_otherwise"] = {
            "a": "if x < 0: raise   (rejects negatives)",
            "b": "if x < 0: pass  else: raise   (rejects non-negatives)",
            "wav_identical": render_hash(other, tmp, "other")[0] == h_nested}

        # P5 authorization present vs neutralised
        t03 = load_score("T03_rbac")
        p5 = copy.deepcopy(t03)
        p5["modules"][1]["functions"][1]["body"][0]["condition"] = "False"
        results["P5_authorization_neutralised"] = {
            "change": "perform: 'not is_allowed(user, action, owner)' -> 'False' (authorization never enforced)",
            "wav_identical": render_hash(validate(p5), tmp, "p5")[0] == render_hash(t03, tmp, "t03")[0]}

        # P6 blind decoding of each benchmark score's audio
        decoding = {}
        for task in TASK_IDS:
            score = load_score(task)
            _, events, path = render_hash(score, tmp, task)
            decoded = decode(path)
            expected = [e["kind"] for e in events]
            score_text = json.dumps(score, sort_keys=True)
            decoding[task] = {
                "events": len(events),
                "decoded_exactly": decoded == expected,
                "recoverable_from_audio": "ordered sequence of element kinds (and one of 3 harmonic classes per module)",
                "score_json_bytes": len(score_text.encode()),
                "audio_information_upper_bound_bits": round(len(events) * math.log2(len(s["schema"].NOTES) * 3), 1),
                "not_recoverable": ["module paths", "function names", "parameters and types", "conditions",
                                    "expressions", "nesting depth", "body vs otherwise", "hole labels",
                                    "allowed calls", "requirements"],
            }
        results["P6_blind_decoding"] = decoding
    results["summary"] = {
        "code_semantics_changes_with_identical_audio": sum(
            results[k]["wav_identical"] for k in ("P1_condition_change", "P2_names_and_expressions", "P3_nesting",
                                                  "P4_body_vs_otherwise", "P5_authorization_neutralised")),
        "of": 5,
        "benchmark_scores_whose_kind_sequence_decodes_exactly": sum(v["decoded_exactly"] for v in decoding.values()),
        "pitch_mapping": s["schema"].NOTES,
    }
    write_json(OUT / "music_probe.json", results)
    print(json.dumps(results["summary"], indent=2))
    for key in ("P1_condition_change", "P2_names_and_expressions", "P3_nesting", "P4_body_vs_otherwise",
                "P5_authorization_neutralised"):
        print(key, "identical WAV:", results[key]["wav_identical"])
    for task, d in decoding.items():
        print(task, d["events"], "decoded_exactly=", d["decoded_exactly"], "bytes=", d["score_json_bytes"],
              "audio_bits<=", d["audio_information_upper_bound_bits"])


if __name__ == "__main__":
    main()
