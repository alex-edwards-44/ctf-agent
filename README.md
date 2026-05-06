# vuln-triage

Semgrep-driven vulnerability triage with a multi-model solver swarm.

![Python 3.14+](https://img.shields.io/badge/python-3.14%2B-blue)
![License MIT](https://img.shields.io/badge/license-MIT-green)

## What it does

vuln-triage runs Semgrep against a GitHub repository or local directory, then dispatches each finding to a swarm of LLM solvers that investigate whether the flagged code is actually exploitable. Each solver has access to a network-isolated Docker sandbox containing a read-only copy of the target and a JSON description of the finding. Results are consolidated by a coordinator model and written to a structured markdown report with verdicts, confidence scores, proof-of-concept notes, and remediation suggestions. The whole pipeline is cost-bounded: you set a USD ceiling and the coordinator stops spawning new solvers once it is reached.

## Why this exists

Static analyzers produce a lot of noise. A tool like Semgrep can fire dozens of rules against a medium-sized codebase; most findings require non-trivial manual investigation to determine whether they represent real risk. That triage step is repetitive but context-sensitive — it requires reading control flow, checking whether untrusted input actually reaches a sink, looking for mitigations nearby — which makes it a reasonable fit for LLM agents equipped with file-reading and code-execution tools. vuln-triage automates the first pass so a human reviewer can focus on the findings the models consider confirmed or likely, with the models' reasoning available inline.

## How it works

```
target (GitHub URL or local path)
        │
        ▼
  ┌─────────────┐
  │   Semgrep   │  --config auto (fallback: p/security-audit)
  └──────┬──────┘
         │  list[SemgrepFinding]  (sorted ERROR → WARNING → INFO)
         ▼
  ┌──────────────────┐
  │   Coordinator    │  Claude Opus 4 — orchestrates the swarm
  │  (claude_sdk)    │  MCP tools: spawn_swarm, kill_swarm,
  └──────┬───────────┘  bump_solver, get_triage_status, broadcast
         │
         │  (up to --max-concurrent swarms in parallel)
         ▼
  ┌────────────────────────────────────────────────────────────────┐
  │                        FindingSwarm                            │
  │                                                                │
  │  ClaudeSolver A    ClaudeSolver B    GeminiSolver  OpenAISolver│
  │  (opus/medium)     (opus/max)        (gemini-2.5)  (gpt-5.4)  │
  │       │                 │                │              │      │
  │       └─────────────────┴────────────────┴──────────────┘      │
  │                                ▼                               │
  │                   Docker sandbox (per solver)                  │
  │                   /target  (read-only)                         │
  │                   /finding.json (read-only)                    │
  │                   /workspace (read-write)                      │
  │                   network: none                                │
  └──────────────────────────┬─────────────────────────────────────┘
                     │  TriageVerdict
                     ▼
             ┌───────────────┐
             │  report.md    │
             └───────────────┘
```

The coordinator runs in a Claude agent SDK loop. It receives findings sorted by priority and calls `spawn_swarm` for each one up to the concurrency limit. A swarm runs four solvers in parallel — two Claude instances (via the Claude Agent SDK), one Gemini, one OpenAI — each investigating the finding independently using Bash tools inside the sandbox. Solvers submit a triage verdict via `submit_triage '{...}'`; the first verdict in wins and cancels the rest. The coordinator polls swarm status, bumps solvers that stall, and collects verdicts. Once all findings are triaged or the budget is exhausted, control returns to the CLI, which generates the markdown report.

Insights found by one solver (e.g., "the function is only reachable from admin routes") are broadcast to peers via `FindingMessageBus`, reducing redundant exploration.

## Requirements

- Python 3.14+
- [uv](https://docs.astral.sh/uv/) package manager
- Docker (for the solver sandbox)
- Semgrep (`brew install semgrep` or `pip install semgrep`)
- API keys: Anthropic (required), Google and OpenAI (required for full 4-model swarm; each is optional if you trim `DEFAULT_MODELS`)

## Installation

Clone the repository and build the sandbox image:

```bash
git clone https://github.com/your-org/vuln-triage
cd vuln-triage
```

Build the Docker sandbox image (extends `ctf-sandbox`; adds ripgrep, semgrep, ast-grep-py):

```bash
docker build -f sandbox/Dockerfile.vuln-sandbox -t vuln-sandbox .
```

Install Python dependencies:

```bash
uv sync
```

Copy and populate the environment file:

```bash
cp .env.example .env
# edit .env — fill in ANTHROPIC_API_KEY at minimum
```

Verify the install:

```bash
uv run vuln-triage --help
```

## Usage

Basic usage against a GitHub repository:

```bash
uv run vuln-triage https://github.com/owner/repo
```

Limit concurrency and set a cost ceiling:

```bash
uv run vuln-triage https://github.com/owner/repo \
  --max-concurrent 2 \
  --budget-usd 5.00 \
  --severity warning \
  --output results/triage.md
```

Use a custom Semgrep rules file instead of the auto config:

```bash
uv run vuln-triage https://github.com/owner/repo \
  --semgrep-config rules/my-rules.yaml \
  --max-solver-steps 60 \
  -v
```

Run against a local directory:

```bash
uv run vuln-triage /path/to/local/project --no-cleanup
```

Send a message to the coordinator while it is running (in a separate terminal):

```bash
uv run vuln-triage-msg "focus on the SQL injection findings first" --port 9400
```

### CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `<target>` | — | GitHub URL or local path |
| `--max-concurrent` | 4 | Swarms running in parallel |
| `--max-solver-steps` | 30 | Tool-call cap per solver (0 = unlimited) |
| `--budget-usd` | 10.00 | Total API cost ceiling in USD (0 = unlimited) |
| `--severity` | warning | Minimum Semgrep severity: error, warning, info, all |
| `--output` | report.md | Output path for the markdown report |
| `--image` | vuln-sandbox | Docker image name for the solver sandbox |
| `--models` | see below | Model specs (repeatable) |
| `--coordinator-model` | claude-opus-4-6 | Model for the coordinator agent |
| `--semgrep-config` | auto | Custom Semgrep rules file or registry config |
| `--no-cleanup` | false | Keep the cloned repo after the run |
| `--msg-port` | 0 (auto) | Port for operator messages to the coordinator |
| `-v / --verbose` | false | Debug-level logging |

### Sample report excerpt

```markdown
## Confirmed Vulnerabilities (2)

### 🔴 `generate_exam_links.py:41` · CWE-345: Insufficient Verification of Data Authenticity

**Rule**: `unsigned-base64-pii-in-url`
**Severity**: ERROR
**Exploitability**: 🔥 trivial
**Confidence**: 95%

**Verdict**: Student PII is base64-encoded without HMAC/signature and placed in URL
query parameters, enabling trivial data exposure and identity forgery.

**Proof of concept**:
python3 -c "import base64,json;print(base64.b64encode(json.dumps({\"student_id\":
\"FORGED_ID\",\"student_name\":\"Attacker\"}).encode()).decode())"

**Remediation**: Sign the vars payload with HMAC and verify the signature before trusting.
```

## Configuration

### .env

```
ANTHROPIC_API_KEY=sk-ant-...   # required
GEMINI_API_KEY=...             # required for google/* specs
OPENAI_API_KEY=sk-...          # required for openai/* specs
```

Keys are read from `.env` via pydantic-settings. If a key is missing and its provider is in the active model list, solver creation raises a `ValueError` at swarm spawn time and the run fails loudly (no silent skip). To run with fewer providers, pass `--models` explicitly to override `DEFAULT_MODELS`.

### Model lineup

The default model specs passed to `--models` are:

```
claude-sdk/claude-opus-4-6/medium   # ClaudeSolver via Claude Agent SDK
claude-sdk/claude-opus-4-6/max      # ClaudeSolver via Claude Agent SDK
google/gemini-2.5-pro               # GeminiSolver via google-genai
openai/gpt-5.4                      # OpenAISolver via openai SDK
```

Each spec has the form `provider/model-id` (with an optional `/service-tier` suffix for `claude-sdk`). The coordinator always runs on `claude-opus-4-6` unless `--coordinator-model` overrides it.

All three providers are genuinely implemented. Each finding gets all four solvers racing in parallel inside separate Docker containers; the first to submit a verdict wins. To use fewer providers, override via `--models`:

```bash
# Claude only (two tiers)
uv run vuln-triage https://github.com/owner/repo \
  --models claude-sdk/claude-opus-4-6/medium \
  --models claude-sdk/claude-opus-4-6/max

# Single Gemini solver
uv run vuln-triage https://github.com/owner/repo \
  --models google/gemini-2.5-flash
```

## Sandbox model

Each solver runs inside a Docker container created from the `vuln-sandbox` image. The container has:

- `/target` — read-only bind-mount of the cloned repository
- `/finding.json` — read-only JSON describing the current finding (path, line, rule, message, code snippet, CWE)
- `/workspace` — read-write tmpfs for scratch work
- `NetworkMode: none` — no outbound or inbound network access
- All Linux capabilities dropped; `no-new-privileges` set

The solver's Bash tool is constrained to this container. It cannot make HTTP requests, cannot write to the target, and cannot persist state between runs. Container cleanup is guaranteed by a finally block in the swarm; orphaned containers (from a crashed run) are removed on the next startup via `cleanup_orphan_containers()`.

The coordinator runs outside the sandbox with network access, since it needs to call the model APIs. It does not execute attacker-controlled code.

## Limitations

- **Semgrep auto config requires a network connection and accepts Semgrep's telemetry.** If your policy prohibits this, supply your own rules with `--semgrep-config`.
- **Custom rules are necessary for logic-level vulnerabilities.** Standard Semgrep rulesets target syntax patterns (SQL concatenation, command injection, hardcoded secrets). Vulnerabilities that require understanding data flow across multiple files — broken access control, insecure design, business logic flaws — will not be found without purpose-written rules.
- **Claude has the most mature integration.** ClaudeSolver uses the Claude Agent SDK, which provides a persistent session, structured output schema, and PreToolUse/PostToolUse hook interception. GeminiSolver and OpenAISolver implement a manual function-calling loop that replays the full conversation history on every API call (no persistent session). This means Gemini and OpenAI pay the full context cost on each turn, while Claude's SDK can cache previous turns.
- **Gemini free-tier rate limits.** The free tier is rate-limited to a small number of requests per minute. On a run with multiple concurrent findings, you will likely hit 429 errors from Gemini. The solver catches these as `QUOTA_ERROR` and stops cleanly, but the finding may end up triaged by Claude only. Use a paid key for reliable multi-provider operation.
- **Parallel tool calls.** OpenAI may return multiple tool calls in one response (parallel function calling). GeminiSolver and OpenAISolver both handle this correctly, but step counting may differ slightly from ClaudeSolver since parallel calls count as one step in some providers.
- **Prompt injection in target code.** If the repository under analysis contains text specifically crafted to manipulate LLM behavior, a solver may be influenced. The finding JSON and target are treated as untrusted data by the prompts, but this is best-effort, not a guarantee.
- **Cost unpredictability.** The `--budget-usd` ceiling is checked before spawning new swarms; it does not interrupt a running swarm. A single swarm with four solvers can cost more than expected if all explore aggressively before hitting their step cap.
- **No support for private repositories.** `RepoLoader` clones with `git clone --depth=1` and no authentication. For private repos, clone manually and pass the local path.
- **Code snippets in reports show "requires login"** when using the Semgrep registry without an account. This is a Semgrep API limitation; it does not affect solver quality since solvers read `/target` directly.

## Roadmap

- Support SARIF output in addition to markdown
- Add a `--recheck` flag that feeds a prior report back as context for a second-pass run
- Explore structured output mode as the primary verdict channel (currently secondary to `submit_triage` interception)
- Improve budget tracking granularity: per-swarm cost caps in addition to the global ceiling
- Add a web UI for browsing reports and replaying solver traces

## Credits

vuln-triage is derived from [ctf-agent](https://github.com/verialabs/ctf-agent) by Veria Labs, which pioneered the multi-model solver swarm architecture for automated CTF challenge solving. The coordinator/swarm/solver structure, Docker sandbox isolation approach, Claude agent SDK integration, and PreToolUse hook interception pattern all originate from that codebase. This fork replaces the CTFd integration and challenge-solving domain with Semgrep-driven vulnerability triage.

The original ctf-agent was itself inspired by [Eruditus](https://github.com/es3n1n/Eruditus) by es3n1n.

## License

MIT — see [LICENSE](LICENSE).
