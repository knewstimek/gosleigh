# Gorchera Architecture

## Package Structure

```text
cmd/gorchera/main.go             -- CLI entrypoint and command routing
cmd/mcp-smoke/main.go            -- Isolated MCP stdio smoke runner for end-to-end subprocess checks
internal/
  api/
    server.go                    -- HTTP control plane for jobs and harness views
    harness.go                   -- Runtime harness HTTP helpers/views
    requests.go                  -- HTTP request DTOs
    views.go                     -- Verification/planning/profile/runtime views
  domain/types.go                -- Canonical domain types: Job, Step, JobChain, RoleProfiles, contracts
  mcp/server.go                  -- MCP stdio server, job/chain tools, wait polling, steer tool
  mcpsmoke/smoke.go              -- MCP subprocess client + isolated smoke scenarios
  orchestrator/
    service.go                   -- Core runLoop, job lifecycle, chain lifecycle, steer, harness ownership
                                 --   jobCache (sync.RWMutex + map[string]*domain.Job) for low-latency status reads
    planning.go                  -- Planner phase, strictness/context normalization, sprint contract build
    evaluator.go                 -- Completion gate, evaluator merge, strictness-aware verification
    verification.go              -- Verification contract build/load/prompt helpers
    parallel.go                  -- Parallel worker fan-out (max 2, disjoint target/scope checks)
    workspace.go                 -- Workspace path validation and isolated git-worktree preparation
  policy/policy.go               -- Approval decisions for workspace/network/delete/deploy/command actions
  provider/
    provider.go                  -- Registry and role-aware adapter selection
    protocol.go                  -- Prompt builders, context-mode payload shaping, JSON schemas
    errors.go                    -- Structured provider errors + recommended actions
    claude.go                    -- Claude CLI adapter
    codex.go                     -- Codex CLI adapter
    command.go                   -- Subprocess execution and CLI error classification
    mock/mock.go                 -- Mock provider for end-to-end tests
  runtime/
    runner.go                    -- Synchronous system command execution
    lifecycle.go                 -- Async process manager for harness processes
    policy.go                    -- Runtime executable allowlist per category
    types.go                     -- Runtime request/result/process types
  schema/validate.go             -- Leader/worker/planner/evaluator schema validation
  store/
    state_store.go               -- Atomic JSON persistence for jobs and chains
    artifact_store.go            -- Atomic artifact materialization
```

Notes:
- Token counts are estimated heuristically from serialized prompt/response size.
- Estimated cost is model-aware: the orchestrator prices input and output tokens separately using provider/model pricing tables, while still excluding caching, batch discounts, and tool-specific surcharges.

## Pipeline Topology

Target execution pipeline:
- `director -> executor -> [engine: go build ./... + go test ./...] -> reviewer -> evaluator`

Pipeline modes:
- `light`: skips reviewer but still requires the evaluator gate.
- `balanced`: default mode; keeps reviewer and evaluator.
- `full`: keeps reviewer/evaluator and enables heavier director orchestration patterns such as fix loops and parallel workers.

Control-plane compatibility notes:
- `gorchera_start_job` accepts `pipeline_mode`; omitted values are treated as `balanced`.
- `gorchera_start_job` and `gorchera_start_chain` both accept `role_overrides`.
- `gorchera_resume` accepts bounded optional `extra_steps` (1-20) for blocked `max_steps_exceeded` resumes.
- MCP clients receive terminal notifications through `notifications/job_terminal` with `{job_id, status, summary}` once the terminal state is persisted.

## State Model

```text
Job: starting -> planning -> waiting_leader -> waiting_worker -> running -> ... -> done / failed / blocked
Step: pending -> active -> succeeded / failed / blocked / skipped
ChainGoal: pending -> running -> done / failed / skipped
JobChain: running -> paused -> running -> done / failed / cancelled
```

Notes:
- `JobStatusQueued` exists in `types.go` but `Start` and `StartAsync` currently create jobs in `starting`.
- `JobStatusPlanning` is set during the planner phase (`ensurePlanning()`) so the UI shows a distinct planning state instead of collapsing it into `starting`.
- `complete` never transitions directly to `done`; `evaluateCompletion()` must pass first.
- `blockedReasonStrikeCount()` fails the job after the same blocked reason is recorded three times in a row.
- `runLoop()` is single-flight per job ID within a process. Duplicate `Resume()` / recovery attempts for the same job return the latest persisted snapshot instead of starting another provider turn.

## Recovery Semantics

- Startup recovery is disabled by default for both `gorchera serve` and `gorchera mcp`.
- Operators must opt in with `-recover` for all recoverable jobs or `-recover-jobs job1,job2` for selected job IDs.
- Recoverable jobs are the persisted non-terminal states: `starting`, `running`, `waiting_leader`, `waiting_worker`.
- Recovery schedules jobs oldest-first with a bounded concurrency of 2 so a restart cannot stampede the provider with every stale job at once.
- `RecoverSelectedJobs()` applies the same bounded scheduling, but only for the explicitly listed job IDs.
- Active runs maintain a lightweight lease file under `.gorchera/leases/<job>.json`.
- `InterruptRecoverableJobs()` only blocks stale recoverable jobs whose lease heartbeat has expired; fresh in-flight jobs are left alone.
- `Shutdown()` cancels background work, waits for in-flight goroutines to exit, and then blocks any still-owned recoverable jobs with an interruption reason.
- `gorchera serve` and `gorchera mcp` both run the stale-job sweep on startup before serving requests; one-shot CLI commands do not mutate job state just to inspect it.
- MCP terminal notifications are buffered until stdio output is ready, and startup wiring registers the callback only after the recovery sweep completes.

## Workspace Modes

- `workspace_mode=shared` keeps `job.WorkspaceDir` equal to the requested workspace.
- `workspace_mode=isolated` requires the requested workspace to be inside a git repository.
- Isolated mode creates a detached git worktree at repository `HEAD` under a sibling `.gorchera-worktrees/<repo>/<job-id>/` directory.
- If the requested workspace is a subdirectory inside the repo, the job workspace points at the matching subdirectory inside the detached worktree.
- `RequestedWorkspaceDir` preserves the operator-supplied path; `WorkspaceDir` becomes the actual path used by providers, system commands, and diff collection.
- Promotion is intentionally manual for now: review the detached worktree diff, then cherry-pick / copy / apply the approved changes back into the primary workspace.

## Core Loop

`Service.runLoop()` does the following:

1. `ensurePlanning()` generates `product_spec.md`, `execution_plan.json`, `sprint_contract.json`, and `verification_contract.json` when planning artifacts are missing.
2. Each leader turn persists `waiting_leader`, appends `leader_requested`, then calls `sessions.RunLeader`.
3. Provider calls go through `executeProviderPhase()`, which applies recommended provider actions:
   - retry: up to 3 attempts with exponential backoff starting at 250 ms
   - block: convert the job to `blocked`
   - fail: fail immediately
4. Leader output is JSON-unmarshaled and schema-validated. Invalid JSON or invalid schema currently fails the job immediately.
5. Leader actions:
   - `run_worker` and `run_workers`: dispatch worker tasks
   - `run_system`: run an allowlisted local command with approval checks
   - `summarize`: persist intermediate summary only
   - `complete`: run evaluator gate and only then mark `done`
   - `fail` / `blocked`: terminate accordingly
6. Consecutive `summarize` calls are capped. After two summarize turns, the service forces a completion evaluation path instead of allowing infinite summary loops.

## Chain System

Sequential chains are persisted as `JobChain` records under `.gorchera/state/chains`.

Start path:
- `StartChain()` validates the shared workspace directory.
- Each incoming `ChainGoal` is normalized:
  - `strictness_level`: `strict | normal | lenient`
  - `ambition_level`: `low | medium | high` (defaults to `medium`)
  - `context_mode`: `full | summary | minimal`
  - `max_steps`: defaults to 8
  - `provider`: defaults to `mock`
- The chain is saved before the first goal starts.
- `startChainGoal()` creates a normal `Job` with `ChainID` and `ChainGoalIndex`, records the new `JobID` on the goal, marks the goal `running`, and starts the job asynchronously.

Completion semantics:
- `handleChainCompletion()` runs only after evaluator-approved job completion.
- If the chain is `paused`, the current goal is marked `done` and no next goal is started.
- Otherwise `advanceChain()` marks the current goal `done` and starts the next pending goal in the same workspace.
- If the last goal finishes, the whole chain becomes `done`.

Chain result forwarding:
- When a chain goal completes as `done`, `advanceChain()` builds a `ChainContext{Summary, EvaluatorReportRef}` from the completed job.
- This context is passed to `startChainGoal()` and attached to the next job as `job.ChainContext`.
- The planner prompt includes a "Previous chain step results" section when `job.ChainContext` is non-nil, so each goal can build on prior work.
- First-goal jobs serialize without a `chain_context` field (pointer + omitempty).

Terminal propagation:
- A chained job ending in `blocked` or `failed` marks the current goal `failed` and the whole chain `failed`.
- `cancelled` is terminal for the chain and prevents later advancement.

## Chain Controls

Chain controls are implemented in `service.go` and exposed through MCP.

Available controls:
- `PauseChain`: sets chain status to `paused`. It does not interrupt the current job; it stops post-job advancement.
- `ResumeChain`: sets status back to `running`. If the current goal already finished while paused, it advances immediately.
- `CancelChain`: interrupts the current goal job by blocking it, marks the current goal failed if still active, then marks the chain `cancelled`.
- `SkipChainGoal`: interrupts the current goal job, marks the goal `skipped`, and starts the next goal. Skipping the final goal marks the chain `done`.

Current control surfaces:
- MCP only: `gorchera_start_chain`, `gorchera_chain_status`, `gorchera_pause_chain`, `gorchera_resume_chain`, `gorchera_cancel_chain`, `gorchera_skip_chain_goal`
- No CLI chain commands
- No HTTP chain routes

## Context Modes

Leader prompts are shaped by `job.ContextMode` through `buildLeaderJobPayload()`:

- `full`: full marshaled job JSON
- `summary`: compact summary with all steps, but only the last two steps retain full detail
- `minimal`: aggregate counters plus the last step only
- `auto`: passed through to the payload builder unchanged; the builder selects the actual mode at runtime based on current step count

Normalization:
- Empty or unrecognized values are normalized to `full`
- `auto` is passed through so the payload builder can resolve it at runtime
- Chain goals carry their own `context_mode`, which is copied into the job created for that goal

## Ambition Levels

Worker autonomy is shaped by `job.AmbitionLevel`:

- `low`: executor must stay mechanical and avoid refactors or scope expansion
- `medium`: executor may include directly related fixes such as obvious error handling or edge cases
- `high`: executor may make justified structural improvements and flag adjacent risks

Normalization:
- Empty or unrecognized values are normalized to `medium`
- Chain goals carry their own `ambition_level`, which is copied into the job created for that goal
- Planner prompts are unchanged by this field; only executor and evaluator prompts use it

## Auto Context Mode

When `context_mode` is set to `"auto"`, `normalizeContextMode()` in planning.go passes the value through unchanged. The leader payload builder (`buildLeaderJobPayload()` in protocol.go) then selects the actual mode at runtime via `autoContextMode()` (protocol.go):

Step-count thresholds used by `autoContextMode(model, stepCount)`:
- `stepCount < 10`: `full` -- full marshaled job JSON
- `10 <= stepCount <= 20`: `summary` -- compact summary, last two steps retain full detail
- `stepCount > 20`: `minimal` -- aggregate counters plus the last step only

The `model` parameter is accepted for forward compatibility (future per-model tuning) but is not used in the current threshold logic.

- This lets long-running jobs shift from `full` context to `summary` or `minimal` automatically as step count grows.
- The `auto` value is exposed in `gorchera_start_job` and per-goal in `gorchera_start_chain`.

Important detail:
- `SupervisorDirective` is removed from the serialized job payload and injected as a dedicated prompt section ahead of job state. This keeps the directive high-priority and prevents it from being duplicated inside summaries.

## Supervisor Steer

`Service.Steer()` injects a supervisor directive into an active job:

- Allowed only when job status is `running`, `waiting_leader`, or `waiting_worker`
- Stored as `job.SupervisorDirective` with a `[SUPERVISOR] ` prefix
- Emits a `supervisor_steer` event
- Exposed via MCP as `gorchera_steer`

Leader prompt behavior:
- The directive is inserted before current job state with explicit highest-priority instructions
- After a successful leader provider call, `runLoop()` clears `job.SupervisorDirective`
- The directive does not bypass evaluator gates, approval checks, harness ownership rules, or chain controls
- The leader prompt now includes a conditional high-risk review trigger: lifecycle/restart/retry/recovery/concurrency/deduplication/external-pricing/auth/UI-event-boundary changes should dispatch an explicit review or audit step before `complete`

## Role Profiles And Model Selection

Model/provider selection is role-based, not job-global.

Defaults from `DefaultRoleProfiles()`:
- target pipeline: director, evaluator -> `opus`; executor, reviewer -> `sonnet`
- migration compatibility: legacy planner/leader/tester override keys may still appear in persisted inputs while the director transition is being rolled out

Resolution path in `SessionManager`:
1. Read the role-specific execution profile
2. If the role profile omits `provider`, fall back to `job.Provider`
3. If still empty, fall back to `mock`
4. If the selected provider is unavailable and `fallback_provider` is set, use the fallback provider
5. If the selected adapter returns a provider command error before any structured payload is produced, and `fallback_model` is non-empty and differs from the primary model, retry exactly once on the same adapter with `fallback_model`

Adapter-specific model behavior:
- Claude passes the selected `profile.Model` through `--model`
- Codex passes `--model` only when the model name looks like a GPT-family Codex model; Claude shorthand values such as `opus` and `sonnet` are intentionally suppressed
- Codex adapter always passes `--fresh` to prevent session reuse and reduce hang probability
- The `fallback_model` retry is runtime-only; it does not change provider lookup and does not fan out into multiple fallback attempts

Role overrides on chains:
- Each `ChainGoal` carries `RoleOverrides map[string]RoleOverride` alongside its other per-goal fields.
- MCP `gorchera_start_chain` accepts a `role_overrides` object per goal entry, with each entry shaped as `{provider, model}`.
- MCP `gorchera_start_job` accepts the same `role_overrides` shape for single-job starts.
- `startChainGoal()` copies `goal.RoleOverrides` into `CreateJobInput.RoleOverrides` when creating the job for that step.
- Resolution priority inside the job: `RoleOverrides[role]` > `RoleProfiles[role]` > job provider > mock fallback.

Stored but not fully enforced yet:
- `effort`
- `tool_policy`
- `max_budget_usd`

Current fallback-model limits:
- Only one same-provider retry is allowed
- Blank or model-equal `fallback_model` values are treated as disabled
- Invalid structured output, schema failures, and provider lookup failures do not trigger the model fallback path

## Structured Errors

Provider-side structured errors live in `internal/provider/errors.go`.

Current error kinds:
- `missing_executable`
- `probe_failed`
- `command_failed`
- `invalid_response`
- `unsupported_phase`
- `auth_failure`
- `quota_exceeded`
- `rate_limited`
- `billing_required`
- `session_expired`
- `network_error`
- `transport_error`

Recommended actions:
- retry: `rate_limited`, `network_error`
- block: `auth_failure`, `billing_required`, `session_expired`
- fail: everything else, including `quota_exceeded` and `transport_error`

Worker-side structured errors:
- Failed or blocked worker outcomes can populate `Step.StructuredReason`
- Current categories include `timeout`, `schema_violation`, `file_access`, `test_failure`, and `build_failure`
- Worker failure events serialize both the human-readable reason and the structured reason JSON

## Workspace Validation And Scope Enforcement

`ValidateWorkspaceDir()` is called from:
- `Service.Start`
- `Service.StartAsync`
- `Service.StartChain`
- MCP `gorchera_start_job`
- MCP `gorchera_start_chain`

Validation rules:
- path must be absolute
- path must exist
- path must resolve to a directory
- directory symlinks are accepted
- permission-denied symlink resolution falls back to `Lstat`/`Clean` when possible

System command scope:
- `resolveSystemWorkdir()` makes relative `system_action.workdir` values workspace-relative
- `classifyScope()` marks targets as `workspace_local`, `workspace_outside`, or `unknown`
- Approval policy blocks workspace-external writes/commands, network access, deploy, git push, credential access, and mass delete

## Worker And System Execution

Single worker execution:
- `runWorkerStep()` creates one active step, calls the role-selected worker adapter, validates JSON/schema, materializes artifacts, and updates step/job status
- On successful single-worker completion, `collectWorkspaceDiffSummary()` runs `git -C <workspace> diff --stat` and stores the result in `Step.DiffSummary`
- If `git diff --stat` fails or the workspace is not a git repo, `DiffSummary` remains empty

Parallel worker execution:
- `parallel.go` enforces `maxParallelWorkers = 2`
- Targets and write scopes must be disjoint
- Parallel tasks can be expressed either as `run_workers` or embedded `parallel:` artifact specs
- Parallel worker steps do not currently populate `DiffSummary`

System execution:
- `run_system` currently supports `build`, `test`, `lint`, `search`, and `command`
- `mapSystemTask()` maps those types to runtime and approval categories
- Runtime allowlists live in `internal/runtime/policy.go`

## Artifact Flow

Artifacts are stored under `.gorchera/artifacts/<jobID>/`.

Planning artifacts:
- `product_spec.md`
- `execution_plan.json`
- `sprint_contract.json`
- `verification_contract.json`

Worker artifacts:
- `MaterializeWorkerArtifacts()` writes real file content from `WorkerOutput.FileContents` when provided
- Otherwise it writes a summary JSON payload

System artifacts:
- `MaterializeSystemResult()` stores the full runtime result JSON

## Control Surfaces

CLI:
- Job lifecycle and inspection commands exist for jobs and harness processes
- No chain-specific CLI commands yet

HTTP API:
- `/healthz`
- `/jobs`, `/jobs/{id}`
- `/jobs/{id}/events`, `/jobs/{id}/events/stream`
- `/jobs/{id}/artifacts`
- `/jobs/{id}/verification`
- `/jobs/{id}/planning`
- `/jobs/{id}/evaluator`
- `/jobs/{id}/profile`
- `/jobs/{id}/resume`, `/approve`, `/reject`, `/retry`, `/cancel`
- `/harness/*` and `/jobs/{id}/harness/*`

MCP (17 tools + notifications):
- job tools: `gorchera_start_job`, `gorchera_list_jobs`, `gorchera_status`, `gorchera_events`, `gorchera_artifacts`, `gorchera_approve`, `gorchera_reject`, `gorchera_retry`, `gorchera_cancel`, `gorchera_resume`
- chain tools: `gorchera_start_chain`, `gorchera_chain_status`, `gorchera_pause_chain`, `gorchera_resume_chain`, `gorchera_cancel_chain`, `gorchera_skip_chain_goal`
- steer tool: `gorchera_steer`
- `gorchera_start_job` key parameters: `goal`, `provider`, `workspace_dir`, `workspace_mode`, `max_steps`, `pipeline_mode`, `strictness_level`, `context_mode` (supports `auto`), `ambition_level`, `role_overrides`
- `gorchera_start_chain` key parameters: `workspace_dir`, `goals[]` with per-goal `goal`, `provider`, `strictness_level`, `ambition_level`, `context_mode`, `max_steps`, `role_overrides`
- `gorchera_resume` accepts optional bounded `extra_steps` (1-20)
- `wait=true` is supported on `gorchera_status` and `gorchera_chain_status` with 2-second polling
- Omitted `wait_timeout` defaults to 30 seconds; `wait_timeout=0` preserves the 5-minute maximum
- Positive `wait_timeout` values are interpreted as seconds
- MCP notifications:
  - `notifications/message` for event streaming
  - `notifications/job_terminal` for persisted final states (`done`, `failed`, `blocked`)

## Evaluator Rubric Scoring

Rubric axes allow the planner to define multi-dimensional evaluation criteria in the `VerificationContract`.

Schema (domain/types.go):
- `RubricAxis`: `{name string, weight float64, min_threshold float64}`
- `RubricScore`: `{axis string, score float64, passed bool}`
- `VerificationContract.RubricAxes []RubricAxis` -- axes defined by the planner
- `EvaluatorReport.RubricScores []RubricScore` -- per-axis scores returned by the provider

Enforcement in `mergeEvaluatorReport()` (evaluator.go):
- Applied only when both `verification.RubricAxes` and `providerReport.RubricScores` are non-empty.
- Additive enforcement: existing pass/fail logic (step coverage, strictness-level rules) runs first; rubric can only demote a passing report, never promote a failing one.
- Each reported score is checked against its `min_threshold`; axes below threshold are collected in `failedAxes`.
- If any axis fails: `report.Passed = false`, `report.Status = "failed"`, reason lists each failed axis with its score and threshold.

Evaluator prompt:
- When rubric axes are present in the verification contract, the evaluator prompt includes a `RUBRIC SCORING` section.
- The evaluator prompt is gate-oriented: it must assess acceptance criteria, verification evidence, and unresolved contradictions in job steps rather than passing solely because one implementation step succeeded.
- The evaluator prompt is ambition-aware: low ambition stays scoped to the explicit request, medium allows directly related improvements, and high accepts justified scope expansion while preserving the evaluator gate.
- The evaluator must score each axis on a 0.0-1.0 scale with one-sentence reasoning per axis.

Worker prompt roles:
- Executor prompts remain implementation-focused and add ambition-specific autonomy guidance.
- Reviewer prompts are adversarial: they search for counterexamples, contract violations, regressions, lifecycle/retry/recovery/idempotency issues, and state-transition problems.
- `task_type="audit"` routes to the reviewer role and uses the same adversarial prompt family, but instructs the worker to stay focused on risk discovery and contract validation rather than unrelated implementation.

## Adaptive Decomposition (strictness=auto)

When `strictness_level` is set to `"auto"`, the planner chooses the evaluation level dynamically.

Resolution path in `ensurePlanning()` (planning.go):
1. Job is created with `StrictnessLevel = "auto"` (normalizeStrictnessLevel passes it through).
2. After the planner phase runs, the planner output fields `RecommendedStrictness` and `RecommendedMaxSteps` are read.
3. If `RecommendedStrictness` is one of `strict | normal | lenient`, it is applied to `job.StrictnessLevel`.
4. If the recommendation is empty or unrecognised, `job.StrictnessLevel` falls back to `"normal"`.
5. If `RecommendedMaxSteps > 0`, `job.MaxSteps` is updated.
6. The resolved level is used for the rest of the job lifecycle: sprint contract, evaluator gate, step-type thresholds.

Planner guidance (protocol.go):
- The planner prompt instructs the planner to recommend strictness based on goal complexity and model capabilities.
- Stronger models (opus) can handle stricter evaluation with fewer steps.
- Weaker models (sonnet, haiku) benefit from normal strictness and more steps.

Fallback:
- If the planner phase is skipped (unsupported phase), `"auto"` reaching `buildSprintContract()` is treated as `"normal"`.

## Planner Prompt Enhancement

`buildPlannerPrompt()` in protocol.go includes several sections beyond the raw job JSON.

Role profiles section:
- A formatted list of all role profiles (planner, leader, executor, reviewer, tester, evaluator) is appended.
- Each entry shows `role: provider/model`, e.g. `executor: claude/sonnet`.
- This informs the planner's `recommended_strictness` and `recommended_max_steps` so it can calibrate for actual model capability.

Chain context section:
- When `job.ChainContext` is non-nil, a "Previous chain step results" section is injected with the prior step's summary and evaluator report reference.
- Allows the planner to scope the current goal relative to what the previous chain step accomplished.

Codebase analysis instruction:
- The planner is instructed to read relevant source files before writing the spec to ground the plan in current reality rather than assumptions.

Measurable acceptance criteria:
- The planner prompt requires acceptance criteria to be verifiable (e.g. `go test ./... exits 0`), not vague (e.g. "code is clean").

Worker prompt behavior:
- Executor prompts stay implementation-focused.
- Reviewer prompts are adversarial: they search for counterexamples, contract violations, regressions, lifecycle/retry/recovery/idempotency issues, and state-transition problems.
- Tester prompts are verification-focused: they prefer executable evidence and treat missing or contradictory evidence as failure unless the block is genuinely external.
