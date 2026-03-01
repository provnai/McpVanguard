# 🔧 McpVanguard — Tech Stack Reference

## Python Core Dependencies

```
# requirements.txt
mcp>=1.0.0                  # Official Anthropic MCP Python SDK (stdio transport)
fastmcp>=0.9.0              # FastMCP — Pythonic MCP server/client scaffolding
uvloop>=0.19.0              # Ultra-fast asyncio event loop (2-4x faster)
pyyaml>=6.0                 # YAML rule file loading
httpx>=0.27.0               # Async HTTP client (for Ollama API calls)
supabase>=2.0.0             # Supabase Python client (session/leaderboard data)
typer>=0.12.0               # CLI framework (for `vanguard` CLI tool)
rich>=13.0.0                # Beautiful terminal output (tables, progress bars)
pytest>=8.0.0               # Test framework
pytest-asyncio>=0.23.0      # Async test support
```

## Why Each Library Was Chosen

### `mcp` (Official SDK)
- Maintained by Anthropic
- Native `stdio` transport — zero-config for local proxy
- Handles JSON-RPC framing, message ID tracking, error types
- Source: https://github.com/modelcontextprotocol/python-sdk

### `fastmcp`
- Now part of the official MCP SDK (absorbed in 2024)
- Simplest way to create MCP servers AND intercept/proxy calls
- Wrap any Python function into an MCP tool in 3 lines
- Used for our mock MCP servers in `mcp_servers/`

### `uvloop`
- Drop-in replacement for asyncio's event loop
- Written in Cython, based on libuv (same as Node.js)
- 2–4× faster I/O throughput
- One line to enable: `asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())`
- Critical for hitting our <10ms latency target

### `pyyaml`
- Loads signature rule files from `rules/` directory
- YAML is human-readable → community can contribute rules via PRs
- No schema validation needed for MVP (add `jsonschema` later)

### `httpx`
- Async HTTP client for calling the Ollama REST API (Layer 2 scoring)
- Supports connection pooling — keeps Ollama session warm
- Can also be used for any webhook calls

### `supabase` (Python client)
- Stores session data, exploit submissions, leaderboard scores
- Uses REST + PostgreSQL under the hood
- Free tier: 500MB, unlimited API calls, no credit card needed

### `typer`
- Builds the `vanguard` CLI (`vanguard start`, `vanguard submit`, `vanguard update`)
- Auto-generates `--help` documentation
- Built on top of Click

### `rich`
- Makes terminal output beautiful (tables, colored output, spinners)
- Used for displaying audit logs, block notifications, challenge results

---

## AI / LLM Stack (Layer 2)

### Ollama (Primary — Recommended for hunters)
**Install:** https://ollama.ai (macOS/Linux/Windows)
```bash
# One-time setup
ollama pull phi4-mini     # 2.5GB download — best accuracy
# OR
ollama pull llama3.2:1b   # 0.8GB download — fastest
```

**Why Ollama:**
- Zero-config REST API at `localhost:11434`
- Every hunter can install it without coding
- Model management is automatic
- Free, local, private

**Vanguard integration:**
```python
# core/semantic.py
import httpx

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "phi4-mini"  # configurable via vanguard.yaml

async def score_intent(tool_call: dict) -> float:
    prompt = f"Tool: {tool_call['method']} | Params: {tool_call['params']}"
    async with httpx.AsyncClient() as client:
        r = await client.post(OLLAMA_URL, json={
            "model": MODEL,
            "prompt": prompt,
            "system": SECURITY_SCORER_SYSTEM_PROMPT,
            "format": "json",
            "stream": False
        }, timeout=5.0)
    return r.json()["score"]
```

### llama-cpp-python (Alternative — for embedded/prod)
```bash
pip install llama-cpp-python
```
- Runs GGUF models directly in Python (no Ollama process needed)
- Slightly more complex setup but fully self-contained
- Use when deploying in a Docker container on Railway

---

## Frontend Stack (Vercel)

### Framework: Next.js 14 (App Router)
```
mcpvanguard-web/         # Separate repo or /web subfolder
├── app/
│   ├── page.tsx         # Landing page
│   ├── leaderboard/
│   │   └── page.tsx     # Live leaderboard
│   ├── challenges/
│   │   └── page.tsx     # Challenge list
│   └── docs/
│       └── page.tsx     # Documentation
├── lib/
│   └── supabase.ts      # Supabase client setup
└── components/
    ├── LeaderboardTable.tsx
    └── ChallengeCard.tsx
```

### Why Next.js on Vercel:
- Vercel is the company behind Next.js — zero-config deployment
- Free tier: unlimited deployments, 100GB bandwidth/month
- SSR + ISR for fresh leaderboard data without polling
- Edge functions for any lightweight API routes

### Supabase JS Client (Frontend)
```typescript
// lib/supabase.ts
import { createClient } from '@supabase/supabase-js'

export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
)

// Fetch leaderboard
const { data } = await supabase
  .from('hunters')
  .select('github_handle, total_points')
  .order('total_points', { ascending: false })
  .limit(25)
```

---

## Backend API (Railway)

### Framework: FastAPI
```
arena-api/               # Deployed on Railway
├── main.py              # FastAPI app entry point
├── routes/
│   ├── challenges.py    # GET /challenges
│   ├── submit.py        # POST /submit (PoE submission)
│   └── validate.py      # POST /validate (replay engine)
├── sandbox/
│   └── runner.py        # Docker-sandboxed exploit replay
└── Dockerfile
```

### Railway Setup:
1. Connect Railway to the GitHub repo
2. Railway auto-detects Python → runs `pip install -r requirements.txt`
3. Set env vars in Railway dashboard: `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`
4. Free: $5/month credit (more than enough for API traffic at MVP scale)

### Why FastAPI:
- Async-native (same as the proxy core)
- Auto-generates OpenAPI docs at `/docs`
- Pydantic validation on all inputs
- Fastest Python web framework available

---

## Database (Supabase)

### Supabase Free Tier Limits:
| Resource | Free Limit | Our Usage |
|---|---|---|
| Database size | 500 MB | < 10 MB for MVP |
| API requests | Unlimited | N/A |
| Bandwidth | 2 GB/month | < 100 MB |
| Auth users | 50,000 | < 1,000 |
| Edge Functions | 500K calls | < 10K |

### Row Level Security (RLS):
```sql
-- Hunters can only read their own data
CREATE POLICY "Hunter self-read" ON hunters
  FOR SELECT USING (auth.uid() = id);

-- Anyone can read the leaderboard (public)
CREATE POLICY "Public leaderboard" ON hunters
  FOR SELECT USING (true);

-- Only the service role (Railway API) can update exploit status
CREATE POLICY "Service writes exploits" ON exploits
  FOR UPDATE USING (auth.role() = 'service_role');
```

### Realtime (Leaderboard Live Updates):
Supabase has built-in realtime via WebSockets. The Vercel leaderboard page can subscribe to changes:
```typescript
supabase
  .channel('leaderboard')
  .on('postgres_changes', { event: 'UPDATE', schema: 'public', table: 'hunters' }, 
    (payload) => setLeaderboard(prev => updateEntry(prev, payload.new)))
  .subscribe()
```

---

## CI/CD & Validation Pipeline (GitHub Actions)

### Workflows:
```
.github/workflows/
├── test.yml             # Run pytest on every push/PR
├── validate_poe.yml     # Auto-validate exploit submissions
└── publish.yml          # Publish to PyPI on release tag
```

### Exploit Validation Workflow:
```yaml
# .github/workflows/validate_poe.yml
name: Validate Proof of Exploit
on:
  issues:
    types: [opened]
    
jobs:
  validate:
    if: contains(github.event.issue.labels.*.name, 'exploit-submission')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
          
      - name: Install dependencies
        run: pip install -r requirements.txt
        
      - name: Parse PoE from issue body
        id: parse
        run: python scripts/parse_poe_issue.py "${{ github.event.issue.body }}"
        
      - name: Run sandboxed replay
        run: python scripts/replay_exploit.py --poe ${{ steps.parse.outputs.bundle_path }}
        
      - name: Update Supabase on success
        if: steps.replay.outputs.success == 'true'
        env:
          SUPABASE_URL: ${{ secrets.SUPABASE_URL }}
          SUPABASE_SERVICE_KEY: ${{ secrets.SUPABASE_SERVICE_KEY }}
        run: python scripts/award_points.py --hunter "${{ steps.parse.outputs.hunter }}"
        
      - name: Comment result on issue
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              body: process.env.VALIDATION_RESULT
            })
```

---

## Local Development Setup

```bash
# 1. Clone the- **Repository**: [https://github.com/provnai/McpVanguard](https://github.com/provnai/McpVanguard)

# 2. Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install Ollama (for Layer 2 semantic scoring)
# Download from https://ollama.ai
ollama pull llama3.2:1b

# 5. Set up environment variables
cp .env.example .env
# Edit .env with your Supabase URL and anon key

# 6. Run the proxy (wrapping a real MCP server)
python -m vanguard start --server "npx @modelcontextprotocol/server-filesystem ."

# 7. Run the Arena (challenge mode)
python arena/hunter.py 1

# 8. Run tests
pytest tests/ -v
```

### `.env.example`
```
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-anon-key
SUPABASE_SERVICE_KEY=your-service-key  # Only needed for Railway API
OLLAMA_MODEL=llama3.2:1b              # or phi4-mini
VANGUARD_LOG_LEVEL=INFO
VANGUARD_SEMANTIC_ENABLED=false        # Set true to enable Layer 2
VANGUARD_BEHAVIORAL_ENABLED=true
```
