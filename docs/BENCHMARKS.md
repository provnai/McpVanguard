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

The benchmark harness is available through the CLI:

```bash
vanguard benchmark-run --profile strict
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

## Safe Zones Affect Results

Safe Zones are intentionally strict. If they are enabled, filesystem benchmark behavior can be dominated by perimeter decisions such as `VANGUARD-SAFEZONE-001`.

That is expected in real deployments, but it changes how benchmark results should be interpreted:

- With safe zones enabled, many path-bearing requests block because they are outside the configured workspace.
- With safe zones disabled, results show more of the rule/camouflage/behavioral layer behavior.
- Both views are useful, but they answer different questions.

Use [SAFE_ZONES.md](SAFE_ZONES.md) before interpreting path-heavy benchmark results.

## Recommended Release Gate

Before release or deployment promotion, run:

```bash
python -m pytest
vanguard benchmark-run --profile strict
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

## Public Claim Guidance

Good public wording:

> The public regression suite passes for the shipped benchmark corpora, and each metric is scoped to its corpus and active profile.

Avoid:

> McpVanguard blocks all MCP attacks.

Avoid:

> Zero false positives.

Avoid:

> Fully sandboxed.

Avoid:

> Semantic scoring is the security boundary.

The accurate framing is: McpVanguard provides layered, configurable enforcement at the MCP execution boundary, with deterministic rules and safe zones carrying the primary blocking path.
