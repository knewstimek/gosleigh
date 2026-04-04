# Gorchera

Go stateful multi-agent orchestration engine / harness engineering with self-improvement capabilities.

**Gorchera** (Go + Orchestra) coordinates AI agents (GPT, Claude) to plan, implement, review, test, and evaluate software tasks autonomously. A supervisor agent (e.g., Claude Opus via MCP) monitors and steers the workflow. Inspired by harness engineering principles from Anthropic's multi-agent orchestration research.

## Features

- **3-agent pipeline**: director -> executor -> [engine build/test] -> evaluator
- **3 strictness levels**: lenient (core files, basic defects), normal (all changed files, domain standards), strict (adversarial reviewer, 3-input trace, senior engineer bar)
- **5 ambition levels**: low, medium, high, extreme, custom -- controls executor scope and evaluator leniency
- **3 context modes**: full, summary, minimal -- controls director prompt payload size
- **Job chaining**: sequential multi-goal execution with automatic advancement
- **Chain-level controls**: pause, resume, cancel, skip individual chain goals
- **Supervisor steering**: mid-flight directive injection via `gorchera_steer`
- **Provider adapters**: GPT/Codex, Claude, Mock (testing) -- with per-role model/provider selection
- **Role overrides**: per-job provider/model overrides from MCP (e.g., evaluator=opus, executor=sonnet)
- **Synchronous wait**: block on job/chain status with configurable timeout
- **Self-improvement**: Gorchera can modify its own codebase via orchestrated jobs
- **Schema retry**: up to 2 retries on schema validation failure per role (director/executor/evaluator)
- **Automated checks**: verification_contract automated_checks (grep, file_exists, file_unchanged, no_new_deps) run before evaluator; results injected into evaluator payload
- **Workspace change detection**: git diff --stat before/after worker execution; SHA-256 hash fallback when no git repo
- **pre_build_commands**: run setup commands (e.g. `go mod tidy`, `npm install`) before engine build/test
- **engine_build_cmd / engine_test_cmd**: override engine verification commands per job (e.g. `npm run build` / `npm test` for Node projects)
- **Error classification**: 12 error types with 3-strike retry policy
- **Token tracking**: rough per-job and per-step token/cost estimation
- **Security**: SUPERVISOR injection prevention, workspace validation, steer authorization
- **Prompt overrides**: customize role prompts via workspace files or job parameters
- **MCP server**: 17+ tools for supervisor agent integration (stdio JSON-RPC 2.0)

## Quick Start

```bash
go build ./...
go run ./cmd/gorchera mcp          # Start MCP server for Claude Code integration
go run ./cmd/gorchera run -goal "Add a hello function" -provider codex
go run ./cmd/gorchera status -all
```

## Pipeline Modes

Gorchera supports three pipeline modes to balance quality vs cost:

- **light**: director -> executor -> engine build/test -> evaluator. Fastest and cheapest. Evaluator performs QUICK verification. Good for simple changes.
- **balanced** (default): Evaluator performs THOROUGH verification including code review and contract checks. Good for moderate changes.
- **full**: Evaluator performs EXHAUSTIVE verification with fix loops and parallel workers. For complex, risky changes.

Light mode with cross-provider (director=GPT, executor=Claude Sonnet) costs ~$0.04 per job.

## MCP Tools

| Tool | Description |
|------|-------------|
| `gorchera_start_job` | Start a single job (with optional role_overrides) |
| `gorchera_start_chain` | Start sequential job chain |
| `gorchera_status` | Get job status (wait=true for sync blocking) |
| `gorchera_chain_status` | Get chain status (wait=true for sync blocking) |
| `gorchera_steer` | Inject supervisor directive |
| `gorchera_events` | Get job events |
| `gorchera_artifacts` | Get job artifacts |
| `gorchera_approve` | Approve blocked action |
| `gorchera_reject` | Reject blocked action |
| `gorchera_retry` | Retry failed job |
| `gorchera_cancel` | Cancel running job |
| `gorchera_resume` | Resume blocked job |
| `gorchera_list_jobs` | List all jobs |
| `gorchera_pause_chain` | Pause chain after current goal |
| `gorchera_resume_chain` | Resume paused chain |
| `gorchera_cancel_chain` | Cancel entire chain |
| `gorchera_skip_chain_goal` | Skip current chain goal |
| `gorchera_diff` | Inspect workspace diff (pathspec-injection-safe) |

## Prompt Overrides

Per-role prompt customization at two levels:

- **Job parameter**: pass `prompt_overrides` to `gorchera_start_job` with keys `director`, `executor`, `evaluator`. The text is prepended to the default role prompt.
- **Workspace file**: place `.gorchera/prompts/{role}.md` in the workspace. If the file starts with `# REPLACE`, the entire default prompt is replaced; otherwise it is prepended.

```json
{
  "prompt_overrides": {
    "executor": "Use idiomatic Rust. Avoid unsafe blocks.",
    "evaluator": "Focus on memory safety and API ergonomics."
  }
}
```

## Executor Self-Check

Before submitting results, the executor runs `engine_build_cmd` and `engine_test_cmd` from the prompt (e.g., `go build ./...` / `go test ./...`) and confirms success. The engine gate then re-runs the same commands independently -- the executor self-check does not replace the gate, it reduces wasted evaluator calls.

## Automated Checks

The director generates a `verification_contract.automated_checks` list in the plan. Before the evaluator is called, the engine runs each check mechanically:

| Check type | Description |
|------------|-------------|
| `grep` | Pattern must (or must not) appear in target files |
| `file_exists` | File path must exist in workspace |
| `file_unchanged` | File must not have been modified |
| `no_new_deps` | Dependency manifest must not add new packages |

Check results are injected into the evaluator payload so the evaluator can reference them.

## Workspace Change Detection

After each worker (executor/reviewer) runs, Gorchera computes the set of changed files:

- **Fast path**: `git diff --stat HEAD` between before/after snapshots
- **Fallback**: SHA-256 hash comparison when no git repo is present

The `changed_files` list is attached to the job artifact and used by automated checks.

## Evaluator Strictness

All strictness levels default to FAIL if requirements are not met.

| Level | Behavior |
|-------|----------|
| `lenient` | Core files only; flags obvious defects |
| `normal` | All changed files; domain standards apply |
| `strict` | Adversarial reviewer; senior engineer bar; 3-input trace; test expectations validated |

Strictness applies to any domain -- novel writing, reverse engineering, data pipelines, etc. The code-specific parts (build/test gates, fuzz/bench requirements) can be suppressed or replaced via `prompt_overrides.evaluator` when working in a non-code domain. For non-code projects, set `engine_build_cmd` and `engine_test_cmd` to a no-op command (e.g. `true`) to skip build/test verification.

## Ambition Levels

| Level | Executor behavior |
|-------|-------------------|
| `low` | Minimal change to meet the goal |
| `medium` | Clean implementation, basic tests |
| `high` | Full tests, docs, error handling |
| `extreme` | Production quality -- perf, edge cases, idiomatic style, security hardening |
| `custom` | Controlled by `ambition_text` job parameter |

`extreme` is appropriate for production-grade work. Use `strict` + `extreme` together for the highest quality bar.

## Provider Presets

`examples/role-profiles.sample.json` lists ready-made presets. The **production** preset uses `pipeline_mode=full`, `strictness_level=strict`, `ambition_level=extreme` with GPT director and Claude Sonnet executor/evaluator -- suitable for critical or customer-facing changes. The **production-spark-claude-eval** variant uses Spark models for speed while keeping Claude Sonnet as the evaluator for accurate judgment.

**Budget tip**: if you can only afford one strong model, put it on the **evaluator**. The evaluator is the final gate -- a weak evaluator passes flawed code that no one else catches. A weak executor can be compensated by fix loops, but a weak evaluator cannot be compensated by anything.

## Architecture

See [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md) for package structure, state machine, and core loop.

## Supervisor Guidelines

When using Gorchera with an AI supervisor (e.g., Claude Opus via MCP), the supervisor must follow these rules:

- **Never write code directly.** All code changes must go through `gorchera_start_job` or `gorchera_start_chain`. The supervisor writes goals, not code.
- **Never diagnose or investigate directly.** Spawning sub-agents to explore the codebase is still "doing it directly." Create a Gorchera audit/review job instead.
- **Steer, don't intervene.** If a job goes off track, use `gorchera_steer` to redirect. If it fails, use `gorchera_retry` or start a new fix job.
- **Reading code is allowed only for goal formulation.** The supervisor may read interfaces and types to write better goals, but not to debug or fix issues.
- **Monitor via status polling.** Use `gorchera_status` / `gorchera_chain_status` to track progress. Use `wait=true` for synchronous blocking.

This separation ensures that all work is auditable, artifact-tracked, and evaluator-gated -- the core value proposition of using an orchestration engine over direct AI coding.

For the full guide on goal writing, ambition levels, invariants, provider presets, and operational tips, see [docs/SUPERVISOR_GUIDE.md](./docs/SUPERVISOR_GUIDE.md).

## Documentation

1. [ARCHITECTURE.md](./docs/ARCHITECTURE.md) -- package structure, state machine, core loop
2. [IMPLEMENTATION_STATUS.md](./docs/IMPLEMENTATION_STATUS.md) -- current state, resolved issues
3. [PRINCIPLES.md](./docs/PRINCIPLES.md) -- inviolable design principles
4. [CODING_CONVENTIONS.md](./docs/CODING_CONVENTIONS.md) -- coding rules, extension guides
5. [SUPERVISOR_GUIDE.md](./docs/SUPERVISOR_GUIDE.md) -- goal writing, ambition levels, invariants, operational tips
6. [ORCHESTRATOR_SPEC_UPDATED.md](./docs/ORCHESTRATOR_SPEC_UPDATED.md) -- detailed design spec
7. [BLOG_COMPARISON.md](./docs/BLOG_COMPARISON.md) -- comparison with Anthropic's harness engineering blog
8. [API_REFERENCE.md](./docs/API_REFERENCE.md) -- MCP tools, HTTP API, CLI commands
9. [INSTALL.md](./docs/INSTALL.md) -- prerequisites, build, configuration, running modes

## Real-World Example

- **[chatrunner](https://github.com/knewstimek/chatrunner)** -- n:n WebSocket chat server + YAML task runner, 100% AI-generated by Gorchera using gpt-5.3-codex-spark. 1,817 lines of Go, 5 steps, ~5 min, $0.22. See [GENERATED_BY_GORCHERA.md](https://github.com/knewstimek/chatrunner/blob/master/GENERATED_BY_GORCHERA.md) for full provenance.

## License

MIT
