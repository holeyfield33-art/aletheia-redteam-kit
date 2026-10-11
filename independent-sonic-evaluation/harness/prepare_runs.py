"""Create a fresh workspace and the exact prompt for every planned attempt.

The schedule (10 tasks x 3 conditions x 2 attempts = 60) is shuffled with a fixed
seed and given opaque run ids. Each workspace is a clean copy of the condition's
frozen materials. The prompt is the identical WRAPPER plus that condition's
materials.md. Prompts are stored in RUNS/<task>/<cond>-<k>/prompt.txt and as TASK_PROMPT.md in the
workspace. Every agent is launched with the same one-line LAUNCHER pointing at that file.
"""

import random
import shutil
import sys
from pathlib import Path

from common import RUNS, TASK_IDS, TASKS, write_json

SEED = 20261011
ATTEMPTS = 2
TOOL_BUDGET = 25

WRAPPER = """You are the coding agent for one attempt in a controlled software experiment.

Workspace: {ws}
- Work ONLY inside the workspace. Do not read, list or search anything outside it. Other attempts and evaluation files exist elsewhere on this machine; looking at them invalidates the attempt.
- Put the deliverable Python modules directly in {ws}/repo/ (flat files, no packages). Do not put tests or any other files in repo/.
- You may write and run your own checks in {ws}/scratch/. Python interpreter: {python} (standard library and pytest available). Do not install packages; no network.
- Budget: at most {budget} tool calls in total. There is no second attempt. Independent hidden tests will be run against repo/ after you finish.
- Finish with a short report: files written in repo/, whether your own checks passed, how many times you ran checks, and any requirement you believe conflicts with the provided materials.

{materials}"""


LAUNCHER = "Your complete instructions are in the file {ws}/TASK_PROMPT.md. Read that file first and follow it exactly."


def main(workspace_root, python):
    workspace_root = Path(workspace_root)
    plan = [(t, c, k) for t in TASK_IDS for c in "ABC" for k in range(1, ATTEMPTS + 1)]
    random.Random(SEED).shuffle(plan)
    schedule = []
    for index, (task, cond, attempt) in enumerate(plan, start=1):
        run_id = f"run-{index:02d}"
        ws = workspace_root / run_id
        if ws.exists():
            raise SystemExit(f"{ws} exists; workspaces must be fresh")
        shutil.copytree(TASKS / task / "conditions" / cond / "workspace", ws)
        (ws / "scratch").mkdir()
        materials = (TASKS / task / "conditions" / cond / "materials.md").read_text(encoding="utf-8")
        prompt = WRAPPER.format(ws=ws, python=python, budget=TOOL_BUDGET, materials=materials)
        out = RUNS / task / f"{cond}-{attempt}"
        out.mkdir(parents=True, exist_ok=False)
        (out / "prompt.txt").write_text(prompt, encoding="utf-8")
        (ws / "TASK_PROMPT.md").write_text(prompt, encoding="utf-8")
        schedule.append({"run_id": run_id, "task": task, "condition": cond, "attempt": attempt,
                         "workspace": str(ws), "run_dir": str(out.relative_to(RUNS.parent)),
                         "prompt_chars": len(prompt)})
    write_json(RUNS / "schedule.json", {"seed": SEED, "tool_budget": TOOL_BUDGET, "attempts": schedule})
    print(f"prepared {len(schedule)} attempts")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
