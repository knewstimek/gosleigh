# API Reference

Gorchera exposes three interfaces: MCP tools (primary), HTTP REST API, and CLI commands.

---

## 1. MCP Tools

Transport: JSON-RPC 2.0 over stdio. Protocol version: `2024-11-05`.

Notifications emitted by the server:
- `notifications/message` -- job state change events (level=info)
- `notifications/job_terminal` -- fired when a job reaches a terminal state

### notifications/job_terminal payload

```json
{
  "job_id": "abc123",
  "status": "done",
  "summary": "...",
  "workspace_mode": "isolated",
  "workspace_dir": "/path/to/worktree",
  "requested_workspace_dir": "/path/to/requested",
  "diff_stat": "3 files changed, 42 insertions(+)"
}
```

`workspace_mode`, `workspace_dir`, `requested_workspace_dir`, `diff_stat` are present only for `workspace_mode=isolated` jobs.

---

### gorchera_start_job

Start a new job. Returns `Job` object immediately; pipeline runs in background.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| goal | string | yes | - | Natural-language goal |
| provider | string | no | claude | `mock` \| `codex` \| `claude` |
| workspace_dir | string | no | - | Absolute path of workspace |
| workspace_mode | string | no | shared | `shared` \| `isolated` |
| max_steps | integer | no | 8 | Maximum director steps |
| pipeline_mode | string | no | light | `light` \| `balanced` \| `full` |
| strictness_level | string | no | normal | `strict` \| `normal` \| `lenient` |
| ambition_level | string | no | medium | `low` \| `medium` \| `high` |
| context_mode | string | no | full | `full` \| `summary` \| `minimal` \| `auto` |
| role_overrides | object | no | - | Per-role provider/model overrides (see below) |

`pipeline_mode`:
- `light` -- director -> executor -> evaluator (skip reviewer)
- `balanced` -- adds reviewer pass
- `full` -- adds fix loops and parallel workers

`role_overrides` shape:
```json
{
  "director":  { "provider": "codex", "model": "o3" },
  "executor":  { "provider": "claude", "model": "sonnet" },
  "evaluator": { "provider": "claude", "model": "opus" }
}
```
Supported role keys: `director`, `planner`, `leader`, `executor`, `reviewer`, `tester`, `evaluator`.

Example:
```json
{
  "name": "gorchera_start_job",
  "arguments": {
    "goal": "Add pagination to GET /users endpoint",
    "provider": "codex",
    "workspace_dir": "/srv/myapp",
    "pipeline_mode": "light",
    "role_overrides": {
      "executor": { "provider": "claude", "model": "sonnet" }
    }
  }
}
```

Returns: `Job` object (see Job schema below).

---

### gorchera_start_chain

Start a sequential chain of jobs. Each goal starts only after the previous one completes successfully.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| workspace_dir | string | yes | Absolute path of workspace |
| goals | array | yes | Ordered list of goal objects |

Each goal object:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| goal | string | yes | - | Natural-language goal |
| provider | string | no | - | Provider override for this step |
| strictness_level | string | no | normal | `strict` \| `normal` \| `lenient` |
| ambition_level | string | no | medium | `low` \| `medium` \| `high` |
| context_mode | string | no | full | `full` \| `summary` \| `minimal` \| `auto` |
| max_steps | integer | no | 8 | Max steps for this goal |
| role_overrides | object | no | - | Per-role overrides |

Example:
```json
{
  "name": "gorchera_start_chain",
  "arguments": {
    "workspace_dir": "/srv/myapp",
    "goals": [
      { "goal": "Write unit tests for auth module" },
      { "goal": "Refactor auth module to pass the tests" }
    ]
  }
}
```

Returns: `{ "chain_id": "<id>" }`

---

### gorchera_list_jobs

List all jobs. No parameters.

Returns: array of `Job` objects.

---

### gorchera_status

Get job status. Optionally block until terminal state.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| job_id | string | yes | - | Job ID |
| wait | boolean | no | false | Block until terminal state |
| wait_timeout | integer | no | 30 | Timeout in seconds when `wait=true`. Set to 0 for 5-minute timeout. |

Terminal states: `done`, `failed`, `blocked`, `cancelled`.

Returns: `Job` object.

---

### gorchera_chain_status

Get chain status. Optionally block until terminal state.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| chain_id | string | yes | - | Chain ID |
| wait | boolean | no | false | Block until terminal state |
| wait_timeout | integer | no | 30 | Timeout in seconds when `wait=true`. Set to 0 for 5-minute timeout. |

Terminal states: `done`, `failed`, `cancelled`.

Returns: `JobChain` object.

---

### gorchera_pause_chain

Pause a chain after the current goal finishes.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| chain_id | string | yes | Chain ID |

Returns: `JobChain` object.

---

### gorchera_resume_chain

Resume a paused chain.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| chain_id | string | yes | Chain ID |

Returns: `JobChain` object.

---

### gorchera_cancel_chain

Cancel a chain.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| chain_id | string | yes | Chain ID |
| reason | string | no | Cancellation reason |

Returns: `JobChain` object.

---

### gorchera_skip_chain_goal

Skip the current goal and advance to the next.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| chain_id | string | yes | Chain ID |

Returns: `JobChain` object.

---

### gorchera_events

Get recent events for a job.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| job_id | string | yes | - | Job ID |
| last_n | integer | no | 10 | Number of most recent events to return |

Returns: array of `Event` objects (`{ time, kind, message }`).

---

### gorchera_artifacts

Get artifact paths produced by a job (planning artifacts + step artifacts).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| job_id | string | yes | Job ID |

Returns: array of strings (file paths).

---

### gorchera_approve

Approve a pending approval. Approval is submitted asynchronously; returns pre-approval snapshot immediately.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| job_id | string | yes | Job ID |

Returns: `{ "job_id", "status", "message" }`

---

### gorchera_reject

Reject a pending approval.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| job_id | string | yes | Job ID |
| reason | string | no | Rejection reason |

Returns: `Job` object.

---

### gorchera_retry

Retry a blocked or failed job. Runs in background; returns pre-retry snapshot.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| job_id | string | yes | Job ID |

Returns: `{ "job_id", "status", "message" }`

---

### gorchera_cancel

Cancel a job.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| job_id | string | yes | Job ID |
| reason | string | no | Cancellation reason |

Returns: `Job` object.

---

### gorchera_resume

Resume a blocked or interrupted job (not for failed -- use `gorchera_retry` instead).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| job_id | string | yes | Job ID |
| extra_steps | integer | no | Additional max_steps to grant (1-20); for `max_steps_exceeded` resumes |

Returns: `Job` object.

---

### gorchera_steer

Inject a supervisor directive into a running job. The director will see it on the next call with highest priority.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| job_id | string | yes | Job ID |
| message | string | yes | Directive text |

Returns: `Job` object.

---

### gorchera_diff

Show current `git diff HEAD` for a job's workspace.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| job_id | string | yes | Job ID |
| pathspec | string | no | Restrict diff to a path (no `..` or `:` magic prefix allowed) |

Returns: diff text, or `"no changes"` if clean.

---

### Job schema (key fields)

```json
{
  "id": "string",
  "goal": "string",
  "status": "queued|starting|planning|running|waiting_leader|waiting_worker|blocked|failed|done",
  "provider": "mock|codex|claude",
  "workspace_dir": "string",
  "workspace_mode": "shared|isolated",
  "pipeline_mode": "light|balanced|full",
  "strictness_level": "strict|normal|lenient",
  "ambition_level": "low|medium|high",
  "context_mode": "full|summary|minimal|auto",
  "max_steps": 8,
  "current_step": 3,
  "retry_count": 0,
  "blocked_reason": "string",
  "failure_reason": "string",
  "summary": "string",
  "pending_approval": {
    "step_index": 2,
    "reason": "string",
    "requested_at": "RFC3339",
    "target": "string",
    "task_type": "string",
    "task_text": "string",
    "system_action": { "type": "build|test|lint|command|search", "command": "string" }
  },
  "token_usage": {
    "input_tokens": 0,
    "output_tokens": 0,
    "total_tokens": 0,
    "estimated_cost_usd": 0.0
  },
  "steps": [...],
  "events": [...],
  "created_at": "RFC3339",
  "updated_at": "RFC3339"
}
```

### JobChain schema

```json
{
  "id": "string",
  "status": "running|paused|done|failed|cancelled",
  "current_index": 0,
  "goals": [
    {
      "goal": "string",
      "provider": "string",
      "status": "pending|running|done|failed|skipped",
      "job_id": "string",
      "max_steps": 8
    }
  ],
  "created_at": "RFC3339",
  "updated_at": "RFC3339"
}
```

---

## 2. HTTP API

Start server: `gorchera serve [-addr 127.0.0.1:8080]`

Auth: if `GORCHERA_AUTH_TOKEN` env var is set, all requests require `Authorization: Bearer <token>`. If unset, no auth (dev mode).

All responses are `application/json`.

### Endpoints

#### Health

| Method | Path | Description |
|--------|------|-------------|
| GET | /healthz | Health check |

Response: `{ "status": "ok" }`

---

#### Jobs

| Method | Path | Description |
|--------|------|-------------|
| GET | /jobs | List all jobs |
| POST | /jobs | Start a new job (blocking) |
| GET | /jobs/{id} | Get job by ID |
| POST | /jobs/{id}/resume | Resume a blocked/interrupted job |
| POST | /jobs/{id}/approve | Approve pending approval |
| POST | /jobs/{id}/retry | Retry blocked/failed job |
| POST | /jobs/{id}/reject | Reject pending approval |
| POST | /jobs/{id}/cancel | Cancel job |
| POST | /jobs/{id}/steer | Inject supervisor directive |
| GET | /jobs/{id}/events | Get job events |
| GET | /jobs/{id}/events/stream | SSE stream of job events |
| GET | /jobs/{id}/artifacts | Get artifact paths |
| GET | /jobs/{id}/verification | Get verification view |
| GET | /jobs/{id}/planning | Get planning view |
| GET | /jobs/{id}/evaluator | Get evaluator view |
| GET | /jobs/{id}/profile | Get role profile view |

`POST /jobs` request body:
```json
{
  "goal": "string",
  "provider": "mock|codex|claude",
  "workspace_dir": "string",
  "workspace_mode": "shared|isolated",
  "tech_stack": "string",
  "constraints": ["string"],
  "done_criteria": ["string"],
  "max_steps": 8,
  "role_profiles": { ... }
}
```

`POST /jobs/{id}/reject` and `POST /jobs/{id}/cancel` accept optional body:
```json
{ "reason": "string" }
```

`POST /jobs/{id}/steer` request body:
```json
{ "message": "string" }
```

`GET /jobs/{id}/events/stream` -- Server-Sent Events. Each event:
```
id: <index>
event: job_event
data: {"time":"...","kind":"...","message":"..."}
```
Stream closes when job reaches `done`, `failed`, or `blocked`.

---

#### Chains

| Method | Path | Description |
|--------|------|-------------|
| GET | /chains | List all chains |
| GET | /chains/{id} | Get chain by ID |

---

#### Harness (runtime process management)

| Method | Path | Description |
|--------|------|-------------|
| GET | /harness/processes | List global harness processes |
| POST | /harness/processes | Start a global harness process |
| GET | /harness/processes/{pid} | Get process by PID |
| POST | /harness/processes/{pid}/stop | Stop process by PID |
| GET | /jobs/{id}/harness | Job harness view (job + processes) |
| GET | /jobs/{id}/harness/processes | List job-scoped processes |
| POST | /jobs/{id}/harness/processes | Start job-scoped process |
| GET | /jobs/{id}/harness/processes/{pid} | Get job-scoped process by PID |
| POST | /jobs/{id}/harness/processes/{pid}/stop | Stop job-scoped process |

`POST /harness/processes` and `POST /jobs/{id}/harness/processes` request body:
```json
{
  "command": "string",
  "name": "string",
  "category": "command|build|test|lint|search",
  "args": ["string"],
  "dir": "string",
  "env": ["KEY=VALUE"],
  "timeout_seconds": 0,
  "max_output_bytes": 0,
  "log_dir": "string",
  "port": 0
}
```

---

#### Dashboard

`GET /dashboard/*` -- serves static files from `web/` directory.

---

## 3. CLI Commands

Usage: `gorchera <command> [flags]`

### run

Start a job synchronously (blocks until completion).

```
gorchera run -goal <text> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| -goal | (required) | Job goal |
| -provider | mock | Provider: `mock` \| `codex` \| `claude` |
| -workspace-mode | shared | `shared` \| `isolated` |
| -max-steps | 8 | Maximum worker steps |
| -strictness | normal | `strict` \| `normal` \| `lenient` |
| -tech-stack | go | Tech stack label |
| -constraints | - | Comma-separated constraints |
| -done | - | Comma-separated done criteria |
| -profiles-file | - | Path to role profile JSON file |

---

### status

```
gorchera status -job <id>
gorchera status -all
```

| Flag | Description |
|------|-------------|
| -job | Job ID |
| -all | List all jobs |

---

### events

```
gorchera events -job <id>
```

---

### artifacts

```
gorchera artifacts -job <id>
```

---

### verification / planning / evaluator / profile

Structured views of a job's pipeline state.

```
gorchera verification -job <id>
gorchera planning     -job <id>
gorchera evaluator    -job <id>
gorchera profile      -job <id>
```

---

### resume / approve / retry

```
gorchera resume  -job <id>
gorchera approve -job <id>
gorchera retry   -job <id>
```

---

### cancel

```
gorchera cancel -job <id> [-reason <text>]
```

---

### reject

```
gorchera reject -job <id> [-reason <text>]
```

---

### serve

Start the HTTP API server.

```
gorchera serve [-addr 127.0.0.1:8080] [-recover] [-recover-jobs job1,job2]
```

| Flag | Default | Description |
|------|---------|-------------|
| -addr | 127.0.0.1:8080 | Listen address |
| -recover | false | Recover all interrupted jobs on startup |
| -recover-jobs | - | Comma-separated job IDs to recover |

---

### mcp

Start the MCP stdio server.

```
gorchera mcp [-recover] [-recover-jobs job1,job2]
```

| Flag | Default | Description |
|------|---------|-------------|
| -recover | false | Recover all interrupted jobs on startup |
| -recover-jobs | - | Comma-separated job IDs to recover |

---

### stream

Stream SSE job events from the HTTP server to stdout.

```
gorchera stream -job <id> [-server http://127.0.0.1:8080]
```

---

### harness-start

Start a runtime process.

```
gorchera harness-start -command <cmd> [-job <id>] [-name <name>] [-category command|build|test|lint] [-args a,b] [-dir <dir>] [-env KEY=VAL,KEY2=VAL2] [-timeout-seconds 0] [-max-output-bytes 0] [-log-dir <dir>] [-port 0]
```

---

### harness-view

```
gorchera harness-view -job <id>
```

---

### harness-list

```
gorchera harness-list [-job <id>]
```

---

### harness-status

```
gorchera harness-status -pid <pid> [-job <id>]
```

---

### harness-stop

```
gorchera harness-stop -pid <pid> [-job <id>]
```
