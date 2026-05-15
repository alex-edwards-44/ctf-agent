# vuln-triage

Semgrep-driven vulnerability triage with a multi-model solver swarm and verified exploitation.

![Python 3.14+](https://img.shields.io/badge/python-3.14%2B-blue)
![License MIT](https://img.shields.io/badge/license-MIT-green)

## What it does

vuln-triage runs Semgrep against a GitHub repository or local directory, then dispatches each finding to a swarm of LLM solvers that investigate whether the flagged code is actually exploitable. Each solver has access to a network-isolated Docker sandbox containing a read-only copy of the target and a JSON description of the finding. Results are consolidated by a coordinator model and written to a structured markdown report with verdicts, confidence scores, proof-of-concept notes, and remediation suggestions.

Optionally, confirmed findings can be escalated to an **exploit phase**: a separate agent deploys the target application inside a dedicated sandbox and attempts to verify the vulnerability by actually running a proof-of-concept exploit against it.

The whole pipeline is cost-bounded: you set separate USD ceilings for the triage and exploit phases, and the coordinator stops spawning new work once either limit is reached.

## Why this exists

Static analyzers produce a lot of noise. A tool like Semgrep can fire dozens of rules against a medium-sized codebase; most findings require non-trivial manual investigation to determine whether they represent real risk. That triage step is repetitive but context-sensitive — it requires reading control flow, checking whether untrusted input actually reaches a sink, looking for mitigations nearby — which makes it a reasonable fit for LLM agents equipped with file-reading and code-execution tools. vuln-triage automates the first pass so a human reviewer can focus on the findings the models consider confirmed or likely, with the models' reasoning available inline.

## How it works

```
target (GitHub URL or local path)
        │
        ▼
  ┌─────────────────────────────┐
  │   Semgrep (multi-pack)      │  p/security-audit, p/owasp-top-ten,
  │                             │  p/cwe-top-25, p/secrets
  └──────────────┬──────────────┘  (deduplicated by path+line+rule_id)
                 │  list[SemgrepFinding]  (sorted ERROR → WARNING → INFO)
                 │
                 ▼  [optional: --triage-top-percent / --triage-threshold]
          size-aware filter
          (ERROR > WARNING > INFO, then OWASP CWEs, then file size)
                 │
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
         ┌────────────────────────┐
         │   [optional]           │  --exploit-mode verify
         │   ExploitSolver        │  deploys app in exploit-sandbox,
         │   (top N confirmed)    │  runs PoC, returns ExploitResult
         └────────────┬───────────┘
                      │
                      ▼
              ┌───────────────┐
              │  report.md    │
              └───────────────┘
```

**Triage phase**: the coordinator runs in a Claude agent SDK loop. It receives findings sorted by priority and calls `spawn_swarm` for each one up to the concurrency limit. A swarm runs four solvers in parallel — two Claude instances (via the Claude Agent SDK), one Gemini, one OpenAI — each investigating the finding independently using Bash tools inside the sandbox. Solvers submit a triage verdict via `submit_triage '{...}'`; the first verdict in wins and cancels the rest. Insights found by one solver are broadcast to peers via `FindingMessageBus`, reducing redundant exploration.

**Exploit phase** (optional, `--exploit-mode verify`): after triage completes, the top N confirmed findings are sent to `ExploitSolver` sequentially. Each solver deploys the target app inside a dedicated `exploit-sandbox` container (which includes Python, Node, Java, pip, npm, Maven, curl, chromium, and a framework-aware startup supervisor), constructs a minimal proof-of-concept exploit, runs it against `localhost`, and returns a structured `ExploitResult` with the exploit script, raw output, and a one-sentence evidence summary. Results appear as a "Verified Exploits" section at the top of the report.

## Requirements

- Python 3.14+
- [uv](https://docs.astral.sh/uv/) package manager
- Docker (for the solver and exploit sandboxes)
- Semgrep (`brew install semgrep` or `pip install semgrep`)
- API keys: Anthropic (required), Google and OpenAI (required for full 4-model swarm; optional if you trim `DEFAULT_MODELS`)

## Installation

Clone the repository:

```bash
git clone https://github.com/your-org/vuln-triage
cd vuln-triage
```

Build the triage sandbox image:

```bash
docker build -f sandbox/Dockerfile.vuln-sandbox -t vuln-sandbox .
```

Build the exploit sandbox image (needed for `--exploit-mode verify` or `suggest`):

```bash
docker build -f sandbox/Dockerfile.exploit -t exploit-sandbox .
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

Use specific Semgrep rule packs instead of the default four:

```bash
uv run vuln-triage https://github.com/owner/repo \
  --semgrep-rules p/security-audit,p/secrets
```

Use a custom Semgrep rules file:

```bash
uv run vuln-triage https://github.com/owner/repo \
  --semgrep-config rules/my-rules.yaml
```

Only triage the highest-priority findings when the scan is large:

```bash
uv run vuln-triage https://github.com/owner/repo \
  --triage-threshold 50 \
  --triage-top-percent 40
# If >50 findings: triage the top 40%, skip the rest (they appear in the report)
```

Verify the top confirmed findings by actually running exploits:

```bash
uv run vuln-triage https://github.com/owner/repo \
  --exploit-mode verify \
  --exploit-top-n 5 \
  --exploit-budget-usd 10.00
```

Get suggested PoC scripts without executing them:

```bash
uv run vuln-triage https://github.com/owner/repo \
  --exploit-mode suggest
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
| `--budget-usd` | 10.00 | Triage phase cost ceiling in USD (0 = unlimited) |
| `--severity` | warning | Minimum Semgrep severity: `error`, `warning`, `info`, `all` |
| `--output` | report.md | Output path for the markdown report |
| `--image` | vuln-sandbox | Docker image name for the triage sandbox |
| `--models` | see below | Model specs (repeatable) |
| `--coordinator-model` | claude-opus-4-6 | Model for the coordinator agent |
| `--semgrep-config` | — | Custom Semgrep rules file/registry config (overrides default multi-pack scan) |
| `--semgrep-rules` | — | Comma-separated pack names, e.g. `p/security-audit,p/secrets` (overrides defaults, ignored if `--semgrep-config` is set) |
| `--triage-threshold` | 100 | Finding count above which `--triage-top-percent` activates |
| `--triage-top-percent` | 100 | Triage only the top N% of findings when count exceeds `--triage-threshold` |
| `--exploit-mode` | none | `none` \| `suggest` \| `verify` |
| `--exploit-top-n` | 0 (auto) | Confirmed findings to exploit (0 = 10% of confirmed, min 3, max 10) |
| `--exploit-timeout-seconds` | 300 | Seconds per exploit attempt |
| `--exploit-budget-usd` | 5.00 | Exploit phase cost ceiling in USD |
| `--no-cleanup` | false | Keep the cloned repo after the run |
| `--msg-port` | 0 (auto) | Port for operator messages to the coordinator |
| `-v / --verbose` | false | Debug-level logging |

### Sample report excerpt

```markdown
## Verified Exploits (1)

The following vulnerabilities were confirmed exploitable by the exploit solver.

### 💥 `main.py:484` — `sqli`

**Evidence**: UNION-based SQL injection on /listservices?category= successfully
extracted all rows from the secret_stuff table.

**Exploit script**:
curl -s "http://127.0.0.1:4000/listservices?category=%27%20UNION%20SELECT%201%2Cname%2C%27secret%27%2Cdescription%20FROM%20secret_stuff--"

**Output**:
<td>My first secret</td><td>Second secret</td>...

---

## Confirmed Vulnerabilities (4)

### 🔴 `main.py:329` · CWE-502: Deserialization of Untrusted Data

**Rule**: `python.flask.security.insecure-deserialization.insecure-deserialization`
**Severity**: ERROR
**Exploitability**: 🔥 trivial
**Confidence**: 99%

**Verdict**: The /cookie Flask route directly deserializes attacker-controlled
data with pickle.loads(b64decode(request.cookies["value"])). No integrity check
is performed before unpickling, so any remote user can trigger RCE.

**Proof of concept**:
python3 -c "import pickle,base64,os;
class RCE:
    def __reduce__(self): return (os.system,('id',))
print(base64.b64encode(pickle.dumps(RCE())).decode())"
# send result as Cookie: value=<payload>

**Remediation**: Replace pickle with JSON + HMAC-signed Flask sessions.
```

## Configuration

### .env

```
ANTHROPIC_API_KEY=sk-ant-...   # required
GEMINI_API_KEY=...             # required for google/* specs
OPENAI_API_KEY=sk-...          # required for openai/* specs
```

Keys are read from `.env` via pydantic-settings. If a key is missing and its provider is in the active model list, solver creation raises a `ValueError` at swarm spawn time (no silent skip). To run with fewer providers, pass `--models` explicitly.

### Model lineup

```
claude-sdk/claude-opus-4-6/medium   # ClaudeSolver via Claude Agent SDK
claude-sdk/claude-opus-4-6/max      # ClaudeSolver via Claude Agent SDK
google/gemini-2.5-pro               # GeminiSolver via google-genai
openai/gpt-5.4                      # OpenAISolver via openai SDK
```

Each spec has the form `provider/model-id` (with an optional `/service-tier` suffix for `claude-sdk`). To use fewer providers:

```bash
# Claude only
uv run vuln-triage https://github.com/owner/repo \
  --models claude-sdk/claude-opus-4-6/medium \
  --models claude-sdk/claude-opus-4-6/max

# Single Gemini solver
uv run vuln-triage https://github.com/owner/repo \
  --models google/gemini-2.5-flash
```

## Sandbox model

### Triage sandbox (`vuln-sandbox`)

Each triage solver runs inside a Docker container with:

- `/target` — read-only bind-mount of the cloned repository
- `/finding.json` — read-only JSON describing the current finding
- `/workspace` — read-write scratch space
- `NetworkMode: none` — no outbound or inbound network access
- All Linux capabilities dropped; `no-new-privileges` set

### Exploit sandbox (`exploit-sandbox`)

Each exploit attempt runs inside a separate container with:

- `/target` — read-only bind-mount of the cloned repository
- `/workspace` — read-write scratch space
- `NetworkMode: none` — loopback (`127.0.0.1`) works for the app under test; no external access
- Runtimes: Python 3, Node 20, Java 17 JRE, pip, npm, Maven
- Tools: curl, jq, ripgrep, chromium (headless)
- `run_target [framework|auto]` — framework-aware supervisor: detects Flask/FastAPI/Django/Express/Spring from package files, installs dependencies, binds to a free port, waits for the port to respond, and prints `APP_PORT=<port>`
- `stop_target` — stops the previously started target process

## Semgrep rule coverage

By default, vuln-triage runs four Semgrep rule packs and merges results:

| Pack | Focus |
|------|-------|
| `p/security-audit` | General security anti-patterns |
| `p/owasp-top-ten` | OWASP Top 10 2021 |
| `p/cwe-top-25` | CWE Top 25 Most Dangerous |
| `p/secrets` | Hardcoded credentials and tokens |

Findings are deduplicated by `(path, line, rule_id)`. Use `--semgrep-rules` to override the pack list or `--semgrep-config` to supply a local rules file.

## Triage filtering

When scans produce many findings, `--triage-threshold` and `--triage-top-percent` let you focus triage on the highest-priority subset:

```
--triage-threshold 100    # activate filtering when total > 100
--triage-top-percent 40   # triage the top 40%, skip the rest
```

Priority ordering within the filter: severity (ERROR > WARNING > INFO) → OWASP Top 10 CWE presence → file size (smaller files first). Skipped findings are listed in the report under "Filtered Out" and are not lost — just not investigated by the LLM.

## Limitations

- **Custom rules needed for logic-level vulnerabilities.** Standard Semgrep packs target syntax patterns. Broken access control, insecure design, and business logic flaws require purpose-written rules.
- **Claude has the most mature integration.** GeminiSolver and OpenAISolver use a manual function-calling loop that replays full conversation history on every API call. ClaudeSolver uses the Claude Agent SDK with persistent sessions and turn-level caching.
- **Gemini free-tier rate limits.** On runs with multiple concurrent findings you will likely see 429 errors from Gemini. The solver stops cleanly on quota errors; findings may be triaged by Claude only. Use a paid key for reliable multi-provider operation.
- **`--budget-usd` does not interrupt a running swarm.** Budget is checked before spawning; a running four-solver swarm can overshoot the ceiling before it finishes.
- **Exploit verification is Claude Opus only.** `ExploitSolver` uses `claude-opus-4-6` directly and is not part of the multi-model swarm.
- **No live-target exploitation.** The exploit sandbox only ever targets the cloned repository running inside itself on `localhost`. URL-based exploitation of running services is not supported.
- **Non-runtime findings return `verified=false`.** Hardcoded secrets in config files, weak crypto choices, and similar static findings have no runtime trigger; `ExploitSolver` reports a clear `failure_reason` rather than fabricating a result.
- **No support for private repositories.** `RepoLoader` clones with `git clone --depth=1` and no authentication. For private repos, clone manually and pass the local path.
- **Code snippets in reports may show "requires login"** when using the Semgrep registry without an account. This is a Semgrep API limitation and does not affect solver quality since solvers read `/target` directly.
- **Prompt injection in target code.** If the repository contains text crafted to manipulate LLM behavior, a solver may be influenced. This is best-effort mitigation, not a guarantee.

## Roadmap

- Support SARIF output in addition to markdown
- Add a `--recheck` flag that feeds a prior report back as context for a second-pass run
- Per-swarm cost caps in addition to the global ceiling
- Add a web UI for browsing reports and replaying solver traces
- Parallel exploit attempts (currently sequential to keep logs clean)

## Credits

vuln-triage is derived from [ctf-agent](https://github.com/verialabs/ctf-agent) by Veria Labs, which pioneered the multi-model solver swarm architecture for automated CTF challenge solving. The coordinator/swarm/solver structure, Docker sandbox isolation approach, Claude agent SDK integration, and PreToolUse hook interception pattern all originate from that codebase. This fork replaces the CTFd integration and challenge-solving domain with Semgrep-driven vulnerability triage.

The original ctf-agent was itself inspired by [Eruditus](https://github.com/es3n1n/Eruditus) by es3n1n.

## License

MIT — see [LICENSE](LICENSE).
