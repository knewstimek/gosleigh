# Supervisor Guide

How to write effective goals and operate Gorchera as a supervisor agent.

## Goal Template

Goal quality determines job quality. Terse goals ("fix XSS") produce mechanical execution with subtle bugs. Structure your goals:

```
Objective: [what to achieve]
Why: [business/UX impact, real problems encountered]
In-scope: [files/modules/features to change]
Out-of-scope: [what NOT to touch]
Invariants: [things that must NOT break]
Constraints: [technical limits -- ASCII only, no new files, etc]
Done when: [completion criteria -- build passes, specific behavior verified]
```

## Ambition Levels

Control how much autonomy workers get via `ambition_level`.

### Default prompts

The exact text injected into executor and evaluator prompts:

| Level | Executor prompt | Evaluator prompt |
|-------|----------------|-----------------|
| low | "Do exactly what is described. Do not improve, refactor, or extend beyond the explicit task." | "Ambition level is low. Judge the result against the explicit task only. Do not require extra refactors, improvements, or scope expansion." |
| medium (default) | "Complete the task. If you notice directly related improvements (missing error handling, obvious edge cases), include them but stay within the stated scope." | "Ambition level is medium. Accept directly related improvements such as obvious error handling or edge-case fixes, but still enforce the stated scope." |
| high | "Achieve the goal and go further. Propose and implement structural improvements, suggest better patterns, flag risks the goal didn't mention. Expand scope if justified." | "Ambition level is high. Accept justified scope expansion when it materially supports the goal. Do not fail solely because the worker improved structure, proposed better patterns, or flagged adjacent risks beyond the original task." |
| custom | _(replaced by ambition_text; falls back to medium if ambition_text is blank)_ | _(same)_ |

### Custom ambition

Use `ambition_text` to fine-tune the injected guidance without writing code.

**custom level -- full replacement** (ambition_text replaces the default entirely):

```json
{
  "ambition_level": "custom",
  "ambition_text": "Fix only the reported bug. Zero scope expansion. Do not touch unrelated files."
}
```

**low/medium/high + ambition_text -- prepend** (ambition_text is prepended before the default):

```json
{
  "ambition_level": "high",
  "ambition_text": "Focus on performance optimization. Prefer algorithmic improvements over micro-optimizations."
}
```

The prepended text is rendered as:
```
Autonomy guidance:
<ambition_text>

<default level text>
```

Both executor and evaluator receive the same transformed guidance.

### Examples by ambition

- **low**: "H2: change token comparison to constant-time"
- **medium**: "Fix audit V2 CRITICAL/HIGH 5 items + build/test pass"
- **high**: "Status API is blind during execution, causing supervisor to kill healthy jobs. Fix the root cause and propose a structure that prevents similar visibility problems."
- **custom**: Surgical constraint or domain-specific rule that none of the presets express precisely.

Higher ambition = more context and autonomy needed in the goal.

## Writing Invariants

Invariants carry operational knowledge that the director cannot derive from code alone. The director reads code but has no operational experience.

Good invariants:
- "recovery logic (RecoverJobs, InterruptRecoverableJobs) runs on MCP restart -- watch for infinite resume loops"
- "addEvent() must update the in-memory cache immediately -- prevents status API stale data regression"
- "Cancel and runLoop can run concurrently -- consider race conditions"
- "evaluator gate must never be bypassed regardless of pipeline_mode"

Bad invariants (too vague):
- "don't break anything"
- "be careful with concurrency"

## Pipeline Modes

Choose based on task complexity:

| Mode | Pipeline | When to use |
|------|----------|------------|
| **light** (default) | director -> executor -> engine -> evaluator | Simple changes, low risk |
| **balanced** | + reviewer before evaluator | Moderate changes, code review needed |
| **full** | + fix loops, parallel workers | Complex/risky, multiple iterations expected |

## Provider Presets

See `examples/role-profiles.sample.json` for full presets. Recommended:

```json
{
  "provider": "codex",
  "pipeline_mode": "light",
  "role_overrides": {
    "executor": {"provider": "claude", "model": "sonnet"},
    "reviewer": {"provider": "claude", "model": "sonnet"}
  }
}
```

Result: director/evaluator = GPT 5.4, executor/reviewer = Claude Sonnet. ~$0.04/job in light mode.

## Job Submission Checklist

Before every `gorchera_start_job`:

1. role_overrides set? (default: executor/reviewer = claude sonnet)
2. workspace_mode = isolated? (shared causes scope violation accidents)
3. ambition_level appropriate?
4. context_mode set? (summary for large jobs)
5. max_steps sufficient? (16 for large, 6-8 for normal)
6. Goal has Why/Invariants/Constraints?
7. pipeline_mode appropriate? (light default, balanced for risky)

## Resuming Blocked Jobs

When a job enters the Blocked state it can be resumed from its current position -- not restarted from scratch.

| Situation | Action |
|-----------|--------|
| `max_steps_exceeded` | `gorchera_resume(job_id="...", extra_steps=N)` where N is 1-20 |
| `PendingApproval` | `gorchera_approve` or `gorchera_reject` (resume does NOT apply here) |
| Other recoverable block | `gorchera_resume(job_id="...")` without extra_steps |
| Failed job | `gorchera_retry` (different from resume) |

Example: `gorchera_resume(job_id="abc123", extra_steps=5)` gives 5 more steps and continues from the last checkpoint.

## Prompt Overrides

Role prompts can be customized without modifying source code.

### Workspace files

Place markdown files under `.gorchera/prompts/` named after the role:

- `director.md`, `executor.md`, `evaluator.md`, `reviewer.md`

Default behavior: the file content is prepended before the built-in base prompt.
If the first line is exactly `# REPLACE`, the base prompt is discarded entirely.

Warning: `# REPLACE` on evaluator removes the evaluator gate instructions. Only use it
if you are providing a fully equivalent gate constraint in the file.

### Job parameter

Pass `prompt_overrides` in `gorchera_start_job` (always prepend, no replace mode):

```json
{
  "prompt_overrides": {
    "executor": "Always write tests first.",
    "evaluator": "Reject if no tests are added."
  }
}
```

### Priority

job parameter > workspace file > default prompt

When both a job parameter and a workspace file exist for the same role, the job parameter
text is prepended first, then the workspace file text, then the base prompt.

## pre_build_commands

Run arbitrary setup commands in the workspace directory before engine verification
(`go build ./...` / `go test ./...`). Useful when the executor cannot write `go.sum`
(sandbox read-only) or when the project needs code generation before building.

**Best-effort**: a failing pre_build command is logged but does NOT skip build/test.

```json
{
  "goal": "...",
  "workspace_dir": "/path/to/project",
  "pre_build_commands": ["go mod tidy", "go generate ./..."]
}
```

Common examples:
- `"go mod tidy"` -- regenerate go.sum after dependency changes
- `"npm install"` -- install Node dependencies
- `"make generate"` -- run code generators
- `"pip install -e ."` -- install Python package in editable mode

Each entry is split on whitespace (no shell expansion). Use one command per entry.
For shell logic, wrap it: `"sh -c \"go mod tidy && go mod verify\""` is NOT supported --
use two separate entries instead: `["go mod tidy", "go mod verify"]`.

## engine_build_cmd / engine_test_cmd

Override the engine verification commands when the project is not a Go project.
By default, gorchera runs `go build ./...` and `go test ./...` after each executor step.
For non-Go projects, set these parameters to match the project toolchain.

```json
{
  "goal": "...",
  "workspace_dir": "/path/to/project",
  "engine_build_cmd": "npm run build",
  "engine_test_cmd": "npm test"
}
```

Common examples by language:

| Language | engine_build_cmd | engine_test_cmd |
|----------|-----------------|----------------|
| Go (default) | _(omit)_ | _(omit)_ |
| Node/npm | `npm run build` | `npm test` |
| Node/pnpm | `pnpm run build` | `pnpm test` |
| Python | `python -m py_compile src/main.py` | `pytest` |
| Make | `make build` | `make test` |
| Rust | `cargo build` | `cargo test` |

**Notes:**
- Commands are parsed via `strings.Fields` (split on whitespace). No shell expansion.
- When `engine_build_cmd` is set, the Go workspace check (`go.mod`/`go.work`) is bypassed.
- Both commands are independent; you can override only one (e.g. set `engine_test_cmd` only).
- Works with `gorchera_start_job` and per-goal in `gorchera_start_chain`.

## Operational Tips

- **Never cancel a job because status looks stuck.** Planner/executor can take 5-10 minutes. Check process list or worktree diff instead.
- **Monitor GPT usage.** Light mode + cross-provider = 70% cost reduction vs full pipeline.
- **Use gorchera_diff** to inspect worktree changes without manual patching.
- **Use extra_steps** to resume blocked jobs instead of restarting from scratch.
- **Simple tasks don't need gorchera.** Use sub-agents directly for one-file, one-function changes.
- **Use pre_build_commands** when go.sum is stale or code generation is needed before build.
