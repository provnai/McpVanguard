# Benchmark Interpretation

McpVanguard includes benchmark corpora so security behavior can be measured and regression-tested. These benchmarks are useful release gates, but they are not universal proof that every possible MCP attack is blocked.

## What The Public Benchmarks Cover

The current public benchmark set covers:

- deterministic rule blocking
- strict-profile overlay rules
- benign false-positive checks
- metadata poisoning checks
- management/auth policy checks
- behavioral request sequences
- semantic threshold accounting
- MCP-38 taxonomy-oriented cases
- packaged-corpus availability outside the repository checkout

Public benign/false-positive pressure cases include:

- admin and developer workflows such as `git status`, dependency installation, Docker image builds, and test execution
- incident-response and log-analysis workflows that contain suspicious strings as evidence rather than instructions
- security research and training documentation that mentions prompt injection, SSRF, traversal, or destructive command examples
- local/offline semantic configuration guidance that includes Vanguard environment variables

These examples are intentionally sanitized. They are designed to test tuning behavior without publishing private customer payloads, exploit-heavy raw artifacts, or provider transcripts.

The benchmark harness is available through the CLI:

```bash
vanguard benchmark-run --profile strict
vanguard benchmark-profiles
vanguard benchmark-baselines
vanguard gpu-harden
vanguard gpu-thresholds
```

## How To Read The Numbers

A benchmark pass rate means the current code matches the expected behavior for the curated cases in that corpus. It does not mean:

- zero false positives in all deployments
- complete coverage of every MCP threat
- full sandboxing
- hardware-rooted provenance
- GPU-accelerated enforcement
- semantic scoring as the primary security boundary

Layered enforcement is strongest when deterministic layers carry the main blocking decision and semantic scoring adds context for ambiguous cases.

Benchmark JSON reports also include breakdowns for:

- deterministic public-safe case IDs (`public_case_id`)
- source corpus labels (`source_corpus`)
- benign blocks by layer
- benign blocks by rule family
- malicious blocks by layer
- malicious blocks by rule family
- false negatives by expected rule
- expected-vs-actual action confusion matrix
- per-action precision/recall-style counts scoped to the evaluated corpus
- harness latency summary (`mean_ms`, `p50_ms`, `p95_ms`, `max_ms`, `total_ms`)

Use these breakdowns to decide whether a false-positive issue is caused by safe-zone tuning, deterministic rules, semantic thresholds, behavioral state, or auth policy. For operational interpretation, see [BLOCK_DECISIONS.md](BLOCK_DECISIONS.md).

`public_case_id` values are generated from the corpus name and local case ID, for example `mcpv:mcp38_cases:bench-mcp08-etc-passwd`. They are intended for public reports, regression references, and issue discussions without exposing private evidence-package paths.

The confusion matrix is especially useful when comparing `monitor`, `balanced`, and `strict` runs. Rows are expected corpus actions; columns are actions returned by the current profile. Treat the matrix as profile- and corpus-scoped evidence, not a universal detection rate.

For a one-command comparison across supported profiles, run:

```bash
vanguard benchmark-profiles
vanguard benchmark-profiles --json-output
```

This evaluates the same corpus under `monitor`, `balanced`, and `strict`, then reports per-profile summaries, expected-vs-actual matrices, and case-level action deltas.

Latency values in these reports measure benchmark harness execution time for the selected corpus/profile. They are useful for comparing relative local overhead between profiles and corpora, but they are not a production latency SLA. Real deployments also depend on payload size, upstream server behavior, Redis/network latency, semantic backend choice, concurrency, and host resources.

Recommended latency views before a larger deployment:

- `vanguard benchmark-baselines --json-output`: captures no-gateway, L1-only, synthetic L2-threshold, and configured-harness timing for public corpora.
- `VANGUARD_SEMANTIC_ENABLED=false vanguard benchmark-run --profile strict --json-output`: captures the layered harness with semantic disabled, useful when validating deterministic/L3 overhead.
- `python scripts/phase7_local_l2_probe.py --output-json <path> --output-md <path>`: exercises the semantic code path with a mock OpenAI-compatible backend and records mean/p95 latency.
- `python scripts/phase7_live_evidence_probe.py --output-json <path> --output-md <path>`: records live semantic and Redis probe status when a backend is actually configured.

Keep mock and live semantic latency separate in reports. The mock probe proves code-path overhead; the live probe measures one configured backend in one environment.

For baseline comparisons, run:

```bash
vanguard benchmark-baselines
vanguard benchmark-baselines --json-output
```

The baseline report includes:

- `no_gateway`: synthetic baseline where every request is allowed
- `l1_only`: deterministic rules engine only
- `l2_threshold_only`: synthetic semantic-threshold cases only; non-semantic cases allow
- `configured_harness`: the current benchmark harness behavior for the corpus

Use this to compare the value of deterministic rules, semantic-threshold cases, and the configured layered harness on public corpora. Do not describe `l2_threshold_only` as a live model-provider benchmark.

## Safe Zones Affect Results

Safe Zones are intentionally strict. If they are enabled, filesystem benchmark behavior can be dominated by perimeter decisions such as `VANGUARD-SAFEZONE-001`.

That is expected in real deployments, but it changes how benchmark results should be interpreted:

- With safe zones enabled, many path-bearing requests block because they are outside the configured workspace.
- With safe zones disabled, results show more of the rule/camouflage/behavioral layer behavior.
- Both views are useful, but they answer different questions.

Use [SAFE_ZONES.md](SAFE_ZONES.md) before interpreting path-heavy benchmark results.

## What The Public Corpus Does Not Cover

The public corpus is a regression and tuning suite, not a complete threat model. It does not currently prove:

- coverage for every MCP server implementation or custom tool schema
- zero false positives across all production workflows
- operating-system, container, browser, or cloud sandbox isolation
- hardware-rooted provenance, GPU acceleration, or confidential-compute attestation
- live model-provider behavior under every prompt/model/backend combination
- private design-partner corpora or exploit-heavy artifacts retained outside the repository

If a claim depends on private evidence, describe it as internal research until a sanitized public case is added with a stable `public_case_id`.

## Adding An Internal Corpus

Teams can add private benchmark corpora without committing sensitive examples to the public repository.

Recommended workflow:

1. Copy the YAML shape from `tests/benchmarks/layered_balanced_benign_cases.yaml` or `tests/benchmarks/mcp38_cases.yaml`.
2. Store private corpora outside git, for example under `.private-docs/` or your internal CI secret workspace.
3. Give each case a stable `case_id`, short `title`, `harness`, `expected_action`, and sanitized `input`.
4. Run the private corpus with:

```bash
vanguard benchmark-run --benchmark-file path/to/private_corpus.yaml --profile balanced
vanguard benchmark-run --benchmark-file path/to/private_corpus.yaml --profile strict --json-output
```

5. Use `public_case_id` in issue trackers and reports when a case can be safely discussed.
6. If a private case should become public, remove secrets, internal hostnames, access tokens, customer identifiers, raw exploit chains, and provider transcripts before opening a pull request.

For profile comparison, use:

```bash
vanguard benchmark-profiles --benchmark-file path/to/private_corpus.yaml --json-output
```

The profile comparison report helps answer whether a case is only strict-sensitive, broadly blocked, or profile-invariant.

## Recommended Release Gate

Before release or deployment promotion, run:

```bash
python -m pytest
vanguard benchmark-run --profile strict
vanguard benchmark-profiles
vanguard benchmark-baselines
vanguard gpu-harden
python -m build
twine check dist/*
```

For hosted deployments, also verify:

- GitHub Actions tests
- CodeQL
- dependency audit
- SBOM generation
- Railway `/health`
- one balanced-profile smoke request
- clean install from the published PyPI artifact

## How To Describe The Results

The clearest public framing is:

> The public regression suite passes for the shipped benchmark corpora, and each metric is scoped to its corpus and active profile.

These results support McpVanguard's layered enforcement model at the MCP execution boundary. They should not be presented as proof of:

- blocking every possible MCP attack
- zero false positives in all deployments
- full sandboxing of the underlying execution environment
- hardware-rooted provenance or GPU-accelerated enforcement
- semantic scoring as the primary security boundary

The accurate framing is: McpVanguard provides layered, configurable enforcement at the MCP execution boundary, with deterministic rules and safe zones carrying the primary blocking path.
