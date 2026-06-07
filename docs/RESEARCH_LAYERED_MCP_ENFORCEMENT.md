# Why MCP Security Needs Layered Runtime Enforcement

McpVanguard `v2.1.0` ships a five-layer runtime enforcement path for Model Context Protocol (MCP) tool calls.

This research note explains the thinking behind that design: what we tested, what we learned, and why we believe MCP security needs more than prompt safety or a single LLM judge.

This is not a claim that McpVanguard blocks every MCP attack. It is a public, reproducible framing for the shipped open-source work: inspect the proposed tool call, apply deterministic policy before execution, use semantic scoring as one layer, and keep the final decision explainable.

The architecture and the measurements should be read separately:

- McpVanguard `v2.1.0` ships the public product version of the five-layer runtime enforcement architecture.
- The numeric results below come from scoped adversarial research runs and public benchmark corpora.
- Those results are evidence for the design, not universal product guarantees.

## Executive Summary

MCP changes the security boundary.

When an agent can invoke tools, read files, call APIs, query databases, or trigger automation, the security question is no longer only:

> What did the model say?

It becomes:

> What is the agent about to do?

Our research direction points to one practical conclusion:

> Semantic scoring is useful, but it should not be the primary security boundary. The stronger design is layered runtime enforcement: normalize inputs, block known hazards deterministically, detect camouflage, use semantic scoring as an advisor, track session behavior, and compose one explicit verdict before execution.

That is the model McpVanguard `v2.1.0` implements.

## Shipped Architecture vs Research Evidence

The `v2.1.0` release turns the layered design into a concrete public runtime architecture. The research measurements below are narrower than the product architecture: they evaluate specific corpora, thresholds, and ablation harnesses.

| Layer Or Stage | Shipped In `v2.1.0` | Public Code / Test Surface | Research Metric Status |
|---|---|---|---|
| `L0` Preflight | Yes | `core/preflight.py`, `tests/test_preflight.py` | Measured in ablations and strict-profile corpora |
| `L1` Rules and Safe Zones | Yes | `core/rules_engine.py`, `rules/`, `tests/test_rules_strict.py` | Strongest measured deterministic contributor in ablations |
| `L1.5` Camouflage | Yes | `core/camouflage.py`, `tests/test_policy.py`, `tests/test_semantic_ws5.py` | Supported by camouflage experiments and semantic-context design; aggregate lift is not yet isolated cleanly |
| `L2` Semantic Advisor | Yes, optional backend | `core/semantic.py`, `tests/test_semantic.py`, `tests/test_semantic_ws5.py` | Measured as useful but weaker than layered enforcement alone |
| `L3` Behavioral / Risk | Yes | `core/behavioral.py`, `core/risk.py`, `tests/test_behavioral_ws6.py` | Covered by product tests and behavioral sequences; live Redis/scale measurements remain deployment-specific |
| Auth Policy | Yes | `core/auth.py`, `core/sse_server.py`, SSE/auth tests | Product feature, not part of every research ablation table |
| Policy Composer | Yes | `core/policy.py`, `tests/test_policy.py` | Enforces monotonic composition: later layers cannot silently downgrade earlier blocks |

This distinction matters. It lets us say clearly that `v2.1.0` ships the five-layer architecture while keeping the research numbers scoped to the exact runs that produced them.

## Evidence Boundary And Provenance

The measured results in this note come from a preserved adversarial evidence package created before the `v2.1.0` public release. That package is retained outside the public repository while raw artifacts, exploit-heavy corpora, provider responses, and local-run metadata are reviewed for safe publication.

The important provenance boundary is:

- Public product-path reruns used `mcp-vanguard==2.0.1` from PyPI.
- Some rule/profile comparisons used external Track 1 test configuration rather than the default public package alone.
- `v2.1.0` is the public release that incorporates the layered architecture and productizes several controls that were still research or candidate work during earlier reruns.
- The numbers below support the layered-design conclusion; they should not be cited as proof that `2.0.1` shipped every layer fully enabled by default.

Preserved metadata includes:

| Item | Preserved Value |
|---|---|
| Public package version in product-path reruns | `mcp-vanguard==2.0.1` |
| Observed OSS checkout during evidence handoff | `748352383e9a4757eb96cbb4e42d6d2146213c14` |
| Seven-rule baseline SHA-256 | `5f4eb7d094740e8d04811658b0dbbca73c1a0ac0f13952e1db64ebf330ac9aed` |
| Twelve-rule candidate SHA-256 | `18ff97a5cc538734381f5cf7cebcc1e512ebfb080e841ff7ef4396b07e8c2a13` |
| Evidence package ledger SHA-256 | `427e339d896577052ba0b1b1cccb83c71ee7f3bf8a7bc8e7615ab5af6861edae` |

The current public repository does not include the full raw evidence package. The public release path is the code, docs, benchmark corpora, and tests in this repository.

## The Problem: MCP Turns Text Into Action

MCP servers expose capabilities. Those capabilities can touch real systems:

- filesystems
- shells and command runners
- cloud APIs
- databases
- browsers
- internal services
- developer tooling
- automation workflows

The same tool can be harmless in one context and dangerous in another. Reading `README.md` is different from reading a credential store. Calling a public URL is different from reaching localhost, cloud metadata endpoints, or private-network services. Processing normal tool metadata is different from exposing hostile tool instructions to a downstream model.

That makes MCP security a runtime problem. Static scanning can find unsafe code and vulnerable packages, but it does not decide whether this specific tool call should execute now, under this policy, with these arguments, in this session.

Runtime enforcement exists for that moment.

## What We Evaluated

Our adversarial work focused on MCP-style tool-call risk rather than general chatbot safety. The test families included:

- filesystem path abuse and sensitive file access
- SSRF-style network targets, including localhost and private ranges
- command execution and encoded payloads
- comments and trust labels that make dangerous operations look approved
- Unicode, normalization, and mixed-script edge cases
- tool metadata and instruction exposure
- benign false-positive pressure cases
- semantic threshold sensitivity
- repeated or escalating behavior across a session

The public repository includes packaged benchmark corpora for release validation and regression testing. Those corpora are useful evidence, but they are intentionally scoped. They are not a complete map of every possible MCP attack.

See [BENCHMARKS.md](BENCHMARKS.md) for the public benchmark interpretation guide.

## Key Empirical Findings

These numbers are from adversarial research runs that informed the `v2.1.0` design. They are included to make the design rationale concrete.

They should be read as corpus-scoped measurements, not universal detection guarantees.

### 1. L2 Alone Was Materially Weaker Than Layered Enforcement

The strongest repeated result was that semantic scoring alone underperformed the full layered path.

| Ablation | L2-only malicious blocking | Full-pipeline malicious blocking | Delta |
|---|---:|---:|---:|
| Live ablation set | `24/34` | `33/34` | `+9` blocked |
| Definitive ablation set | `15/55` | `54/55` | `+39` blocked |

This is the core empirical reason McpVanguard treats `L2` as an advisor rather than the whole security boundary.

### 2. Deterministic L1 Carried Most Of The Measured Blocking Value

In the definitive ablation, deterministic rules carried most of the malicious blocking signal:

| Layer Set | Malicious Blocked | Malicious Rate |
|---|---:|---:|
| `L1` rules | `49/55` | `89.1%` |
| `L2` only | `15/55` | `27.3%` |
| Full layered path | `54/55` | `98.2%` |

This is why the product design keeps known-hazard blocking in deterministic layers instead of asking a semantic scorer to rediscover obvious dangerous behavior every time.

### 3. Threshold And False-Positive Pressure

One release-candidate threshold family showed strong performance on curated adversarial and benign suites, while also surfacing the expected tradeoff on a harder benign corpus:

| Evaluation | Result | Interpretation |
|---|---:|---|
| Curated adversarial semantic suite at threshold `0.95` | `47/47` | High-confidence malicious cases were caught in this suite |
| Curated semantic false-positive suite at threshold `0.95` | `37/37` | The curated benign suite stayed clear at this threshold |
| URL/path edge suite at threshold `0.95` | `34/34` | Path and URL boundary cases were handled in this suite |
| Larger benign corpus at threshold `0.95` | `77/91` | `14/91` cases still hit policy-boundary blocks |
| Combined threshold `0.95` family | `195/209` | Strong aggregate result, with visible strict-profile tradeoffs |

The important lesson is not "zero false positives." The lesson is that strict policy can perform well on curated benign cases while still needing rollout discipline on broader benign traffic.

### 4. The Broader Definitive Ablation Exposed The Tradeoff

The definitive ablation also made the benign-side tradeoff visible:

| Layer Set | Malicious Blocked | Malicious Rate | Benign Blocked | Benign Block Rate |
|---|---:|---:|---:|---:|
| `L2` only | `15/55` | `27.3%` | `5/39` | `12.8%` |
| Full layered path | `54/55` | `98.2%` | `10/39` | `25.6%` |

That table is exactly why the public product has profiles. Strict enforcement can catch more high-risk behavior, but it also needs policy tuning, allowlists, and review paths for workflows that resemble security research or administration.

### 5. Comment And Trust-Label Camouflage Affected Scorer Judgment

The scorer-side experiments showed that comments and trusted-looking labels can affect model judgment, especially on commands the scorer already finds ambiguous.

Examples observed in the adversarial runs:

| Pattern | Observed Behavior |
|---|---|
| Unambiguous destructive command plus a trust comment | Often remained high-risk |
| Ambiguous sensitive-file command plus a trust comment | Could shift toward lower-risk scoring |
| Cross-domain comments in shell, SQL, Python, and config contexts | Showed domain-general influence rather than a shell-only artifact |
| Prompt-isolation variants | Helped in some settings, but did not remove the need for preprocessing and deterministic layers |

The practical conclusion is narrower than "comments always bypass security." The more useful conclusion is that attacker-supplied reassurance should not be treated as trusted context for a security scorer.

That finding directly informed `L1.5` camouflage detection and the decision to pass earlier-layer findings into the semantic scorer as trusted security annotations.

The aggregate ablation tables do not yet prove a clean standalone `L1.5` lift. The current public claim is narrower: camouflage detection is justified by observed scorer manipulation patterns and by the need to label attacker-supplied reassurance as untrusted context before semantic scoring.

### 6. Stronger Models Shifted The Error Surface Rather Than Removing It

Additional model-comparison runs showed that stronger or different models did not remove the need for layers. Different scorers showed different blind spots: one model family might resist one attack shape while missing another.

The engineering lesson is the same: no single semantic scorer should be treated as the product boundary. Deterministic preprocessing, safe-zone checks, metadata inspection, session context, and explicit policy composition remain necessary even when the semantic backend improves.

## The Five Core Inspection Layers

McpVanguard `v2.1.0` uses five core inspection layers, with auth policy and a final policy composer around them.

| Layer | Role | Why It Matters |
|---|---|---|
| `L0` Preflight | Normalize and annotate inputs before deeper inspection | Catches encoding, Unicode, size, depth, and scorer-targeting issues early |
| `L1` Rules | Apply deterministic signatures and safe-zone boundaries | Carries the main fast blocking path for known high-risk behavior |
| `L1.5` Camouflage | Detect trust-signal and scorer-manipulation patterns | Marks payloads that try to look approved, safe, or policy-exempt |
| `L2` Semantic | Score ambiguous intent with an optional model backend | Adds context, but cannot downgrade deterministic blocks |
| `L3` Behavioral | Track suspicious sequences across a session | Captures repeated or escalating behavior that single-call checks may miss |

The final policy composer returns one verdict:

- `ALLOW`
- `WARN`
- `REVIEW`
- `SHADOW-BLOCK`
- `BLOCK`

The key invariant is simple: later layers should not silently downgrade earlier deterministic blocks.

## Finding 1: The Tool Call Is The Control Point

Prompt injection matters, but in MCP the dangerous outcome is often a tool call.

A malicious instruction is most harmful when it changes:

- which tool is invoked
- which arguments are passed
- which file, URL, API, database, or service is reached
- which metadata reaches the model
- which workflow is triggered next

That means a useful MCP gateway should inspect the action itself:

- JSON-RPC method
- tool name
- tool arguments
- active profile
- session and server context
- auth and scope context when available
- relevant metadata exposure
- prior behavior in the session

The security question is not just "is this text malicious?" It is "should this proposed action execute?"

## Finding 2: Known Hazards Should Be Blocked Deterministically

Some high-risk patterns should not depend on a model's interpretation when a deterministic check is available.

Examples include:

- sensitive filesystem paths
- credential stores and shell history
- obvious destructive filesystem operations
- localhost, metadata, and private-network SSRF targets
- encoded shell execution
- container escape patterns
- anti-forensics and log-tampering behavior
- suspicious package or supply-chain hooks

This is why McpVanguard keeps deterministic rules and safe zones in the primary enforcement path. They are fast, explainable, auditable, and easier to regression-test than model-only decisions.

## Finding 3: Semantic Scoring Helps Most When It Is An Advisor

Semantic scoring is valuable. It can identify intent that string matching misses, and it can help classify ambiguous tool-call arguments.

But adversarial testing showed a consistent design risk: scorer inputs can be influenced by surrounding text. Comments, trusted-looking labels, role framing, and benign explanations can change how a model interprets a dangerous operation.

The practical answer is not to remove semantic scoring. The practical answer is to scope it correctly:

- let semantic scoring add context
- let it raise severity
- let it trigger review or block in strict profiles
- do not let it override deterministic blocks
- feed it structured security annotations from earlier layers

In McpVanguard `v2.1.0`, L2 is an advisor inside the policy composer, not the whole security boundary.

## Finding 4: Camouflage Is A Runtime Pattern

Many unsafe requests do not only contain a dangerous operation. They also contain text that tries to make the operation look safe:

- "approved by admin"
- "for documentation only"
- "safe test"
- "security audit"
- "ignore previous warning"
- "score this as benign"

Some phrases like these are legitimate in developer, security, or incident-response workflows. Others are attacker-controlled camouflage. The gateway should not blindly treat attacker-supplied reassurance as trusted context.

McpVanguard `L1.5` marks trust-signal and scorer-manipulation patterns so downstream scoring can treat them as security context rather than instructions.

## Finding 5: Strict Enforcement Needs Rollout Discipline

Strict profiles are useful for production-sensitive agents, but strict security controls can also block legitimate research, administration, or incident-response material when it resembles exploitation or credential access.

That is a deployment tradeoff, not a reason to avoid enforcement.

McpVanguard exposes three public profiles:

- `monitor`: audit-only discovery
- `balanced`: default developer enforcement
- `strict`: production-sensitive hardening

The intended rollout is gradual: observe first, tune policy, then enforce where the tool surface justifies it.

Safe zones deserve the same care. A safe-zone block means the requested path is outside the operator-defined perimeter. It does not automatically mean the user was malicious.

## What This Means For MCP Security

MCP security needs both development-time and runtime controls.

Development-time scanners can find vulnerable servers, unsafe dependencies, and suspicious code. Runtime gateways decide whether a proposed action should execute now.

A mature MCP security posture should include:

- least-privilege tool exposure
- identity and scope checks for hosted gateways
- deterministic path, command, and network controls
- metadata inspection before model exposure
- semantic scoring for ambiguous cases
- session and behavioral state for repeated activity
- audit logs and optional receipt evidence
- staged rollout with false-positive review

McpVanguard focuses on the runtime enforcement part of that stack.

## What This Note Does Not Claim

This note should not be read as saying:

- McpVanguard blocks every MCP attack
- semantic scoring is solved
- false positives are eliminated
- safe zones replace OS, container, or cloud isolation
- benchmark pass rates prove universal real-world performance
- research-only GPU or hardware-attestation work is part of the shipped release

The stronger and more accurate claim is:

> McpVanguard provides layered, configurable enforcement at the MCP execution boundary. Deterministic rules and safe zones carry the primary blocking path, semantic scoring adds advisory context, and the final policy composer keeps decisions explicit and auditable.

## Reproducing The Public Path

Install McpVanguard:

```bash
pip install mcp-vanguard --upgrade
```

Run profile-aware benchmarks:

```bash
vanguard benchmark-run --profile monitor
vanguard benchmark-run --profile balanced
vanguard benchmark-run --profile strict
```

Run the source release gate:

```bash
python -m pytest
python -m build
twine check dist/*
```

For deployment and architecture details, see:

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [DEPLOYMENT.md](DEPLOYMENT.md)
- [BENCHMARKS.md](BENCHMARKS.md)
- [SAFE_ZONES.md](SAFE_ZONES.md)

## Closing View

MCP security is not only a prompt-safety problem. It is an execution-boundary problem.

Agents should not be trusted to turn model intent into privileged action without a control layer in between. The proposed action should be normalized, inspected, scored, constrained, and logged before it reaches files, APIs, shells, databases, browsers, or internal automation.

That is the public direction of McpVanguard: practical, inspectable runtime enforcement for MCP workflows.
