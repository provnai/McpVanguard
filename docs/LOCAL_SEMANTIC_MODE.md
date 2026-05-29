# Local Semantic Mode

McpVanguard supports a local or offline Layer 2 semantic mode by pointing the semantic scorer at an OpenAI-compatible endpoint that you run yourself. This is the preferred path when you want lower data exposure, local development convenience, or air-gapped experiments.

The current code path is driven by `core/semantic.py` and the `VANGUARD_SEMANTIC_*` environment variables.

## Supported Backends

McpVanguard currently supports these semantic backends:

- Ollama local mode
- OpenAI-compatible custom backends
- OpenAI
- MiniMax

For local or offline use, the practical options are:

- Ollama
- LM Studio exposed as an OpenAI-compatible server
- llama.cpp server exposed as an OpenAI-compatible server
- any other local OpenAI-compatible wrapper

## Recommended Local Setup

If you want a simple local setup, use one of these paths:

### Ollama

```bash
export VANGUARD_SEMANTIC_ENABLED=true
export VANGUARD_SEMANTIC_FAIL_CLOSED=true
export VANGUARD_OLLAMA_URL="http://localhost:11434"
export VANGUARD_OLLAMA_MODEL="phi4-mini"
```

### OpenAI-Compatible Local Server

Use this for LM Studio, llama.cpp server, or another local wrapper that speaks the OpenAI chat-completions API.

```bash
export VANGUARD_SEMANTIC_ENABLED=true
export VANGUARD_SEMANTIC_FAIL_CLOSED=true
export VANGUARD_SEMANTIC_CUSTOM_URL="http://127.0.0.1:1234/v1"
export VANGUARD_SEMANTIC_CUSTOM_MODEL="your-local-model"
export VANGUARD_SEMANTIC_CUSTOM_KEY="local-placeholder"
export VANGUARD_SEMANTIC_THRESHOLD_WARN="0.50"
export VANGUARD_SEMANTIC_THRESHOLD_BLOCK="0.80"
```

## Operating Profiles

### Strict / High-Assurance

- `VANGUARD_SEMANTIC_ENABLED=true`
- `VANGUARD_SEMANTIC_FAIL_CLOSED=true`
- `VANGUARD_SEMANTIC_THRESHOLD_WARN=0.40`
- `VANGUARD_SEMANTIC_THRESHOLD_BLOCK=0.70`
- Prefer a local or private OpenAI-compatible backend if possible

### Balanced Default

- `VANGUARD_SEMANTIC_ENABLED=true`
- `VANGUARD_SEMANTIC_FAIL_CLOSED=true`
- `VANGUARD_SEMANTIC_THRESHOLD_WARN=0.50`
- `VANGUARD_SEMANTIC_THRESHOLD_BLOCK=0.80`
- Use Ollama or a trusted hosted backend

### Cost / Latency Sensitive

- `VANGUARD_SEMANTIC_ENABLED=true`
- `VANGUARD_SEMANTIC_FAIL_CLOSED=false` only if you explicitly accept warning-mode fallback
- `VANGUARD_SEMANTIC_THRESHOLD_WARN=0.60`
- `VANGUARD_SEMANTIC_THRESHOLD_BLOCK=0.85`
- Favor low-latency models and tighter timeouts

### Offline / Air-Gapped

- `VANGUARD_SEMANTIC_ENABLED=true`
- `VANGUARD_SEMANTIC_FAIL_CLOSED=true`
- Use Ollama or a local OpenAI-compatible endpoint
- Keep the endpoint on the same machine or inside the same isolated network

## Recommended Defaults From The Current Sweep

These are the defaults we currently recommend after tuning against the adversarial corpus, benign false-positive corpus, and threshold sweep helpers:

- Local developer mode:
  - `VANGUARD_SEMANTIC_ENABLED=true`
  - `VANGUARD_SEMANTIC_FAIL_CLOSED=true`
  - `VANGUARD_SEMANTIC_THRESHOLD_WARN=0.50`
  - `VANGUARD_SEMANTIC_THRESHOLD_BLOCK=0.80`
- Hosted gateway mode:
  - `VANGUARD_SEMANTIC_ENABLED=true`
  - `VANGUARD_SEMANTIC_FAIL_CLOSED=true`
  - `VANGUARD_SEMANTIC_THRESHOLD_WARN=0.50`
  - `VANGUARD_SEMANTIC_THRESHOLD_BLOCK=0.80`
- High-assurance mode:
  - `VANGUARD_SEMANTIC_ENABLED=true`
  - `VANGUARD_SEMANTIC_FAIL_CLOSED=true`
  - `VANGUARD_SEMANTIC_THRESHOLD_WARN=0.40`
  - `VANGUARD_SEMANTIC_THRESHOLD_BLOCK=0.70`
- Cost / latency sensitive mode:
  - `VANGUARD_SEMANTIC_ENABLED=true`
  - `VANGUARD_SEMANTIC_FAIL_CLOSED=false` only if you explicitly accept warning-mode fallback
  - `VANGUARD_SEMANTIC_THRESHOLD_WARN=0.60`
  - `VANGUARD_SEMANTIC_THRESHOLD_BLOCK=0.85`

For most users, the balanced default is the safest starting point. It keeps fail-closed behavior on, gives enough room for benign quoted or educational text, and still blocks the obvious attack patterns we are tuning for.

## Environment Variables

The current supported variables are:

- `VANGUARD_SEMANTIC_ENABLED`
- `VANGUARD_SEMANTIC_FAIL_CLOSED`
- `VANGUARD_SEMANTIC_TIMEOUT_SECS`
- `VANGUARD_SEMANTIC_THRESHOLD_WARN`
- `VANGUARD_SEMANTIC_THRESHOLD_BLOCK`
- `VANGUARD_SEMANTIC_CUSTOM_URL`
- `VANGUARD_SEMANTIC_CUSTOM_MODEL`
- `VANGUARD_SEMANTIC_CUSTOM_KEY`
- `VANGUARD_OPENAI_API_KEY`
- `VANGUARD_OPENAI_MODEL`
- `VANGUARD_OPENAI_BASE_URL`
- `VANGUARD_MINIMAX_API_KEY`
- `VANGUARD_MINIMAX_MODEL`
- `VANGUARD_MINIMAX_BASE_URL`
- `VANGUARD_OLLAMA_URL`
- `VANGUARD_OLLAMA_MODEL`

## Notes

- The first configured backend wins.
- `VANGUARD_SEMANTIC_CUSTOM_URL` is the best fit for local OpenAI-compatible servers.
- `VANGUARD_SEMANTIC_FAIL_CLOSED=true` is the safest default for gateways.
- For local experimentation, keep the timeout short enough to avoid blocking the proxy loop for too long.

## Troubleshooting

- If local scoring never activates, confirm `VANGUARD_SEMANTIC_ENABLED=true`.
- If the scorer times out, raise `VANGUARD_SEMANTIC_TIMEOUT_SECS` or switch to a faster local model.
- If the backend is OpenAI-compatible but not recognized, confirm the base URL ends with an API root that exposes `/chat/completions`.
- If you see unexpected blocks, compare the same payload against the adversarial and false-positive corpora before changing thresholds.
