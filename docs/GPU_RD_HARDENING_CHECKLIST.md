# GPU R&D Hardening Checklist for McpVanguard

This document converts the useful lessons from the `C:\Users\quint\Desktop\gpu` weekend R&D lab into a concrete near-term hardening plan for the current McpVanguard release line.

The goal is not to productize every experiment. The goal is to strengthen the current McpVanguard gateway in the areas where the R&D produced the most credible signal:

- offline/local semantic scoring
- adversarial regression coverage
- false-positive reduction
- benchmark discipline
- operator-facing semantic configuration clarity

## Source Handling Rule

The GPU lab at `C:\Users\quint\Desktop\gpu` is a read-only reference source for this hardening effort.

- Read from it
- analyze it
- extract lessons from it
- identify artifacts worth reproducing or porting

Do not edit, rewrite, clean up, or restructure files inside `C:\Users\quint\Desktop\gpu` as part of this checklist.

Any implementation work should happen in the real McpVanguard product workspace, with the GPU lab treated as research input rather than an active codebase.

## Scope

This checklist is intentionally focused on near-term hardening of the current release line.

It excludes, for now:

- GPU-rooted provenance as a shipped feature
- CUDA rewrites of the behavioral layer
- separate daemon/fork architectures
- broad ProvnCloud control-plane work

Those remain research tracks until the current gateway benefits have been fully extracted and stabilized.

## Hardening Outcome

McpVanguard should emerge from this work with:

- the current 2.0.x release line fixed for the highest-confidence correctness bugs
- a documented and testable offline/local L2 path
- a reusable adversarial regression corpus
- a false-positive evaluation corpus
- a repeatable benchmark/hardening workflow
- clearer operator guidance for semantic backend selection and tuning

## Release-First Triage Rule

The most productive way to use the GPU R&D lessons is not to widen scope immediately.

Before deeper semantic hardening, treat the current release line as the baseline that must first be made more correct and more measurable.

Use this priority order:

1. fix confirmed current-release correctness bugs
2. add tests that lock those fixes in
3. then extract GPU-lab learnings into L2 hardening, adversarial regression, and benchmark discipline

Do not let attractive R&D work delay fixes for defects already confirmed in the shipping release.

## Phase 0: Current Release Triage and Patch Queue

This phase exists to make sure the team hardens the current McpVanguard baseline before layering on broader semantic or GPU-derived work.

### 0.1 Confirm and patch the highest-confidence release bugs

- [ ] Fix SSE rate-limit fallthrough in `core/sse_server.py`
- [ ] Add an immediate `return` after sending the `429` response in `handle_sse()`
- [ ] Add an integration test proving a rate-limited client does not establish a session

- [ ] Fix shared `ProxyConfig` mutation in DEGRADE mode in `core/proxy.py`
- [ ] Replace `self.config.semantic_enabled = True` with a per-session or per-instance semantic override
- [ ] Add a regression test proving one degraded session does not permanently enable semantic scanning for unrelated sessions

- [ ] Fix unreachable `ENTROPY_CRITICAL` risk recording in `core/behavioral.py`
- [ ] Record `ENTROPY_CRITICAL` before returning the block result
- [ ] Add a regression test verifying a blocked high-entropy response decreases the risk score

- [ ] Fix orphaned semantic task behavior when L3 blocks in `core/proxy.py`
- [ ] Cancel `sem_task` before returning an L3 block result
- [ ] Add a test that proves no semantic task is left running after an L3 block path

### 0.2 Patch the most valuable medium-severity correctness issues

- [ ] Correct risk event typing for semantic blocks in `core/proxy.py`
- [ ] Introduce a distinct semantic event type or equivalent explicit mapping for Layer 2 results
- [ ] Add a test proving Layer 2 blocks are not recorded as behavioral blocks

- [ ] Revisit default tool hinting in `_enrich_tool_list()`
- [ ] Stop defaulting ambiguous tools to `readOnlyHint = True`
- [ ] Choose a safer fallback for unknown tools:
  - [ ] no hint
  - [ ] explicit destructive hint only when confidently inferred
  - [ ] optional configurable conservative mode

- [ ] Expand or redesign safe-zone path-key coverage in `core/rules_engine.py`
- [ ] Decide whether to:
  - [ ] broaden the static key list
  - [ ] derive path-like keys from tool schema metadata
  - [ ] introduce explicit per-tool jail mapping
- [ ] Add tests covering non-standard path argument names

- [ ] Tighten management-tool safety posture
- [ ] Confirm expected behavior when `management_tools_enabled=true` and auth is disabled
- [ ] Decide whether management tools should:
  - [ ] be forbidden entirely when auth is disabled
  - [ ] require explicit opt-in plus local-only trust assumptions
  - [ ] require additional guardrails such as size caps and rate limits
- [ ] Add size limits and basic rate limiting for `vanguard_apply_rule`

### 0.3 Track real issues separately from overstated audit items

- [ ] Create an internal triage note classifying audit findings as:
  - [ ] confirmed bug
  - [ ] design debt
  - [ ] lower-severity maintenance issue
  - [ ] rejected / overstated finding
- [ ] Keep the following out of the immediate hardening critical path unless revalidated:
  - [ ] `_CACHE_LOCKS` "race condition" concerns in `core/auth.py`
  - [ ] duplicate audit-handler claims in `core/proxy.py`
  - [ ] high-severity framing around primitive normalization fallthrough
  - [ ] digest pre-check complaints that do not bypass actual signature verification

### 0.4 Lock release fixes into regression coverage

- [ ] Add tests for each confirmed bug fixed in Phase 0
- [ ] Prefer integration-style tests for:
  - [ ] SSE rate-limit behavior
  - [ ] cross-session DEGRADE isolation
  - [ ] management-tool auth behavior
- [ ] Prefer focused unit tests for:
  - [ ] entropy risk recording
  - [ ] event-type mapping
  - [ ] tool-hint enrichment

### 0.5 Only then move into GPU-derived hardening work

- [ ] Treat Phase 0 completion as the baseline gate before larger L2 tuning work
- [ ] Do not start broad prompt/threshold tuning until known release correctness bugs are closed or explicitly deferred

## Phase 1: R&D Triage and Extraction

### 1. Inventory useful Track 1 assets

- [ ] Review `C:\Users\quint\Desktop\gpu\track_1_airgap_mode`
- [ ] Identify which files are:
  - [ ] reproducible setup artifacts
  - [ ] benchmark artifacts
  - [ ] attack corpus candidates
  - [ ] one-off exploratory scripts
  - [ ] research-writing only
- [ ] Create a keep/archive decision list for all major subfolders under:
  - [ ] `configs`
  - [ ] `docker`
  - [ ] `wsl/src/core`
  - [ ] `wsl/src/phase2`
  - [ ] `wsl/src/paper_tests`
  - [ ] `wsl/reports`

### 2. Extract only reusable implementation-relevant artifacts

- [ ] Keep a minimal set of artifacts that can inform product hardening:
  - [ ] local L2 configuration examples
  - [ ] local inference benchmark outputs
  - [ ] attack/bypass examples with clear reproduction value
  - [ ] false-positive examples involving benign-but-scary strings
- [ ] Archive or isolate the following from product-facing work:
  - [ ] speculative daemon implementations
  - [ ] paper-only helper scripts
  - [ ] duplicate report variants
  - [ ] scripts whose behavior no longer matches McpVanguard 2.0.x

### 3. Produce a canonical extraction map

- [ ] Write one internal note listing:
  - [ ] what from the GPU lab will be adopted into McpVanguard hardening
  - [ ] what remains research-only
  - [ ] what should be ignored
- [ ] Ensure no one treats the weekend lab as a production implementation branch

## Phase 2: Offline / Local L2 Hardening

### 4. Define the supported local semantic mode

- [ ] Decide the supported local L2 story for near term:
  - [ ] LM Studio via OpenAI-compatible endpoint
  - [ ] llama.cpp server via OpenAI-compatible endpoint
  - [ ] Ollama local mode
- [ ] Choose whether all three are documented equally or one becomes the recommended path
- [ ] Define the canonical terminology:
  - [ ] `offline semantic mode`
  - [ ] `local semantic mode`
  - [ ] `air-gapped semantic mode`
- [ ] Use one term consistently in docs

### 5. Map local L2 to the real McpVanguard config surface

- [ ] Document the real current configuration path in McpVanguard:
  - [ ] `VANGUARD_SEMANTIC_CUSTOM_URL`
  - [ ] `VANGUARD_SEMANTIC_CUSTOM_MODEL`
  - [ ] `VANGUARD_SEMANTIC_CUSTOM_KEY`
  - [ ] `VANGUARD_SEMANTIC_TIMEOUT_SECS`
  - [ ] `VANGUARD_SEMANTIC_THRESHOLD_BLOCK`
  - [ ] `VANGUARD_SEMANTIC_THRESHOLD_WARN`
  - [ ] `VANGUARD_SEMANTIC_FAIL_CLOSED`
- [ ] Remove or quarantine any GPU-lab config files that imply a product config interface McpVanguard does not actually expose
- [ ] Ensure all local/offline examples use the real current env-var interface

### 6. Create a first-class documented local setup path

- [ ] Add a dedicated docs section or document for local semantic mode
- [ ] Include:
  - [ ] supported local providers
  - [ ] required environment variables
  - [ ] example startup commands
  - [ ] expected latency tradeoffs
  - [ ] fail-closed behavior
  - [ ] troubleshooting steps
- [ ] Add at least one example for:
  - [ ] local developer laptop
  - [ ] isolated/offline deployment

### 7. Define local L2 operating profiles

- [ ] Introduce documented profile guidance for:
  - [ ] strict/high-assurance blocking
  - [ ] balanced default
  - [ ] cost/latency-sensitive mode
  - [ ] offline local mode
- [ ] For each profile, document:
  - [ ] backend recommendation
  - [ ] timeout
  - [ ] warn threshold
  - [ ] block threshold
  - [ ] fail-closed recommendation

### 8. Validate local mode against current code

- [ ] Verify local OpenAI-compatible endpoints work through the actual `core/semantic.py` flow
- [ ] Confirm payload formatting compatibility with:
  - [ ] LM Studio
  - [ ] llama.cpp server
  - [ ] OpenAI-compatible local wrappers
- [ ] Check for local-provider-specific issues:
  - [ ] model naming assumptions
  - [ ] `response_format` behavior
  - [ ] timeout behavior
  - [ ] retry behavior

## Phase 3: Adversarial Regression Corpus

### 9. Create a curated adversarial corpus

- [ ] Extract useful attacks from GPU-lab scripts and reports
- [ ] Group them into categories:
  - [ ] prompt injection
  - [ ] trust poisoning
  - [ ] social/authority framing
  - [ ] obfuscation and encoding
  - [ ] shell indirection
  - [ ] path traversal bypass attempts
  - [ ] SSRF evasions
  - [ ] multi-turn or sequence-based attacks
- [ ] Remove duplicates and near-duplicates
- [ ] Keep only cases that are:
  - [ ] reproducible
  - [ ] understandable
  - [ ] relevant to current McpVanguard architecture

### 10. Convert adversarial cases into structured product artifacts

- [ ] Create a benchmark/corpus format that is easy to run in CI or manually
- [ ] For each case, capture:
  - [ ] payload
  - [ ] intended risk category
  - [ ] expected L1 outcome
  - [ ] expected L2 outcome
  - [ ] expected overall outcome
  - [ ] whether it is request-side or response-side
- [ ] Mark cases as:
  - [ ] regression test
  - [ ] benchmark-only
  - [ ] research-only

### 11. Turn real bypasses into regression protections

- [ ] For each credible bypass discovered in the R&D lab:
  - [ ] determine whether L1 should catch it
  - [ ] determine whether L2 should catch it
  - [ ] determine whether it should be addressed by metadata inspection
  - [ ] determine whether it is a sequence/behavioral case
- [ ] Add the right protection path:
  - [ ] new L1 rule
  - [ ] prompt or threshold change in L2
  - [ ] behavioral detector enhancement
  - [ ] documentation note if it remains an acknowledged limitation

### 12. Build a false-positive corpus in parallel

- [ ] Collect benign-but-scary examples from the lab:
  - [ ] docs quoting malicious commands
  - [ ] log analysis containing dangerous strings
  - [ ] incident response notes
  - [ ] educational or testing content
  - [ ] code snippets containing attack examples
- [ ] For each case, capture:
  - [ ] benign intent
  - [ ] why it looks risky
  - [ ] expected product behavior
- [ ] Use this corpus to prevent hardening from making McpVanguard unusable

## Phase 4: L2 Prompt and Threshold Hardening

### 13. Audit the current semantic prompt

- [ ] Review the current `_SYSTEM_PROMPT` in `core/semantic.py`
- [ ] Compare it to the strongest ideas from the GPU-lab prompt experiments
- [ ] Identify concrete improvements around:
  - [ ] authority-spoofing detection
  - [ ] trust-poisoning language
  - [ ] prompt-injection language in tool arguments
  - [ ] benign quoted-string contexts
  - [ ] shell indirection and euphemistic phrasing

### 14. Improve prompt discipline without overfitting

- [ ] Add prompt guidance that improves adversarial recall
- [ ] Avoid overfitting to weekend-lab artifacts only
- [ ] Ensure prompt changes do not:
  - [ ] sharply increase false positives
  - [ ] lock the scorer to one provider's quirks
  - [ ] assume a single model family

### 15. Tune thresholds using real corpora

- [ ] Run:
  - [ ] adversarial corpus
  - [ ] benign false-positive corpus
  - [ ] current benchmark corpus
- [ ] Measure:
  - [ ] precision
  - [ ] recall
  - [ ] false-positive rate
  - [ ] threshold sensitivity
- [ ] Choose threshold defaults that optimize for the actual product mode:
  - [ ] local developer mode
  - [ ] hosted gateway mode
  - [ ] high-assurance mode

### 16. Decide where L2 should stop and L1 should start

- [ ] Identify weekend-lab cases that should never have been L2-only
- [ ] Strengthen L1 for obvious deterministic patterns discovered in the lab
- [ ] Keep L2 focused on:
  - [ ] creative phrasing
  - [ ] intent inference
  - [ ] heuristic evasion
- [ ] Avoid using L2 to compensate for missing obvious static rules

## Phase 5: Benchmark and Hardening Workflow

### 17. Create a repeatable hardening pipeline

- [ ] Define one repeatable benchmark workflow that runs:
  - [ ] existing benchmark corpus
  - [ ] adversarial regression corpus
  - [ ] false-positive corpus
  - [ ] local-vs-cloud semantic comparison where relevant
- [ ] Standardize output:
  - [ ] pass/fail summary
  - [ ] precision/recall
  - [ ] notable regressions
  - [ ] latency observations

### 18. Make benchmark outputs actionable

- [ ] Ensure benchmark results answer:
  - [ ] did detection improve?
  - [ ] did false positives worsen?
  - [ ] did local mode become too slow?
  - [ ] did a rule change shift too much burden onto L2?
- [ ] Produce one summary format suitable for:
  - [ ] internal engineering use
  - [ ] release hardening decisions
  - [ ] selective external research or marketing use

### 19. Decide CI vs. offline benchmark boundaries

- [ ] Keep lightweight regression cases in normal CI
- [ ] Keep heavyweight model-backed benchmarks outside normal CI if needed
- [ ] Define a manual or scheduled benchmark process for:
  - [ ] local model scoring
  - [ ] large adversarial sweeps
  - [ ] model comparison runs

## Phase 6: Docs and Operator Experience

### 20. Improve semantic backend documentation

- [ ] Update docs to clearly explain the current backend priority and options
- [ ] Clarify support language:
  - [ ] OpenAI
  - [ ] Ollama
  - [ ] MiniMax
  - [ ] custom OpenAI-compatible backends
- [ ] Add local-mode examples that are real and tested

### 21. Add a â€œwhen to use local modeâ€ guide

- [ ] Document best-fit cases:
  - [ ] regulated data
  - [ ] low-latency local development
  - [ ] air-gapped labs
  - [ ] cost-sensitive deployments
- [ ] Document non-ideal cases:
  - [ ] small machines without GPU capacity
  - [ ] teams unwilling to manage local model infrastructure

### 22. Add a semantic hardening section to deployment docs

- [ ] Explain:
  - [ ] timeouts
  - [ ] fail-closed mode
  - [ ] warm-start considerations
  - [ ] model choice tradeoffs
  - [ ] local endpoint health checks
- [ ] Include operator warnings:
  - [ ] local model drift
  - [ ] long-tail false positives
  - [ ] throughput ceilings

## Phase 7: What To Measure Before Bigger GPU Work

### 23. Measure whether L3 is actually a bottleneck

- [ ] Profile current L3 CPU cost on real-ish workloads
- [ ] Measure:
  - [ ] entropy scan cost
  - [ ] sliding-window cost
  - [ ] session-state growth behavior
  - [ ] Redis overhead
- [ ] Do not start CUDA L3 work until product evidence shows a meaningful bottleneck

### 24. Measure local L2 throughput before deeper GPU claims

- [ ] Benchmark local models across:
  - [ ] cold start
  - [ ] warm steady-state
  - [ ] concurrent bursts
  - [ ] different model sizes
- [ ] Record:
  - [ ] mean latency
  - [ ] p95 latency
  - [ ] calls/sec
  - [ ] timeout behavior
  - [ ] memory/VRAM requirements

### 25. Keep GPU attestation in research until feasibility is proven

- [ ] Verify actual RTX 3060-compatible attestation capability against NVIDIA docs and SDK
- [ ] Separate:
  - [ ] genuine device identity proof
  - [ ] confidential-computing narratives
  - [ ] what VEX could really consume
- [ ] Do not put hardware-rooted provenance into the core McpVanguard hardening roadmap yet

## Phase 8: Cleanup and Governance

### 26. Prevent the weekend lab from becoming accidental product truth

- [ ] Add a short internal note stating:
  - [ ] GPU lab artifacts are exploratory
  - [ ] McpVanguard public release behavior is defined by the main repo
  - [ ] only curated findings should influence product claims
- [ ] Avoid copying raw R&D claims into:
  - [ ] README
  - [ ] product pages
  - [ ] release notes
  - [ ] customer-facing docs

### 27. Create a clean â€œadopt / defer / archiveâ€ ledger

- [ ] Adopt now:
  - [ ] offline/local L2 support story
  - [ ] adversarial regression corpus
  - [ ] false-positive corpus
  - [ ] benchmark workflow
- [ ] Defer:
  - [ ] GPU attestation
  - [ ] CUDA L3 rewrite
  - [ ] giant daemon or architectural fork
- [ ] Archive:
  - [ ] duplicate reports
  - [ ] dead exploratory scripts
  - [ ] non-reproducible one-offs

## Deliverables

The hardening work should produce the following concrete outputs:

- [ ] one documented offline/local L2 setup path
- [ ] one adversarial regression corpus
- [ ] one benign false-positive corpus
- [ ] one repeatable benchmark/hardening workflow
- [ ] one internal extraction memo from the GPU lab
- [ ] one updated deployment/operator doc for semantic mode selection

## Success Criteria

This hardening effort is successful when:

- [ ] McpVanguard can be run in a clearly documented local/offline semantic mode
- [ ] adversarial cases from the GPU lab are captured as regressions or acknowledged gaps
- [ ] false positives are measured, not guessed
- [ ] semantic prompt and threshold changes are benchmark-backed
- [ ] the product is stronger without inheriting the GPU labâ€™s architectural sprawl

## Not A Goal

This hardening effort is not intended to:

- [ ] replace the current McpVanguard architecture
- [ ] merge the research daemon into core product code
- [ ] claim GPU-accelerated behavioral scoring as a shipped feature
- [ ] claim GPU attestation as a product capability before real feasibility work
- [ ] convert every R&D note into roadmap scope

## Recommended Execution Order

1. Triage and extract useful Track 1 assets.
2. Define and document the supported offline/local L2 path.
3. Build the adversarial and false-positive corpora.
4. Tune semantic prompt and thresholds using those corpora.
5. Add the repeatable benchmark/hardening workflow.
6. Update docs and operator guidance.
7. Measure whether deeper GPU work is justified.

