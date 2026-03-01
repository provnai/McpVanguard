# 🏠 McpVanguard — Hosting Guide (Zero-Cost Stack)

## Stack Overview

All infrastructure is 100% free using existing accounts:

| Service | What It Hosts | Monthly Cost |
|---|---|---|
| **GitHub** | Source code, signatures DB, CI/CD | $0 |
| **Vercel** | Leaderboard website (Next.js) | $0 |
| **Supabase** | Database (PostgreSQL), Auth, Realtime | $0 |
| **Railway** | Arena API server (FastAPI) | $0 ($5 credit) |
| **PyPI** | `pip install mcp-vanguard` package | $0 |
| **Total** | | **$0/month** |

---

## 1. GitHub (Source of Truth)

Everything lives in a single GitHub repo. Repository structure:

```
McpVanguard/              ← main repo (this repo)
├── core/                 ← Python proxy package
├── arena/                ← CLI arena tool
├── mcp_servers/          ← mock vulnerable MCP servers
├── rules/                ← community YAML rules
├── signatures/           ← validated exploit signatures
├── tests/                ← pytest test suite
├── docs/                 ← this documentation
├── .github/workflows/    ← GitHub Actions CI/CD
└── web/                  ← Next.js frontend (deployed on Vercel)
```

**GitHub repo settings to configure:**
- Enable **Issues** (for PoE submissions via templates)
- Enable **Discussions** (for community)
- Add **Topics**: `mcp`, `ai-security`, `red-teaming`, `llm-security`, `ctf`
- Create **Issue template**: `.github/ISSUE_TEMPLATE/exploit_submission.md`
- Add **Labels**: `exploit-submission`, `validated`, `rejected`, `bounty`

**GitHub Actions free limits:**
- 2,000 minutes/month (public repos: unlimited)
- Make the repo public → unlimited free Actions minutes ✅

---

## 2. Supabase (Database + Auth + Realtime)

### Project Setup

1. Go to [supabase.com](https://supabase.com) → New Project
2. Name: `mcpvanguard`
3. Region: Choose closest to you (e.g., `eu-west-1` for Europe)
4. Password: Generate a strong one, save it

### Run the Schema

In Supabase SQL Editor, run **ARCHITECTURE.md → Supabase Tables** section SQL, plus:

```sql
-- Enable Realtime on leaderboard
ALTER PUBLICATION supabase_realtime ADD TABLE hunters;

-- Create updated_at triggers
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$ BEGIN NEW.updated_at = NOW(); RETURN NEW; END; $$ language 'plpgsql';

CREATE TRIGGER update_hunters_updated_at BEFORE UPDATE ON hunters
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
```

### Environment Variables

From Supabase dashboard → Settings → API:
```
NEXT_PUBLIC_SUPABASE_URL=https://xxxxxxxxxxxx.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...   ← safe to expose in frontend
SUPABASE_SERVICE_KEY=eyJ...            ← KEEP SECRET (Railway only)
```

### Free Tier Limits (More Than Enough for MVP)
- **Database:** 500 MB (we'll use < 10 MB)
- **Bandwidth:** 2 GB/month
- **Auth users:** 50,000
- **Realtime connections:** 200 concurrent
- **Edge Functions:** 500,000 calls/month

---

## 3. Vercel (Leaderboard Website)

### Setup

1. Go to [vercel.com](https://vercel.com) → New Project
2. Import `McpVanguard` GitHub repository
3. Set **Root Directory** to `web/` (our Next.js subdirectory)
4. Add Environment Variables:
   ```
   NEXT_PUBLIC_SUPABASE_URL=https://xxxxxxxxxxxx.supabase.co
   NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...
   ```
5. Deploy → Vercel auto-detects Next.js, builds, and deploys

**Custom domain (optional):** `mcpvanguard.dev` or any domain you own — connect via Vercel dashboard for free.

### Deployment Updates
Every push to `main` branch → Vercel auto-redeploys (< 30 seconds)

### Free Tier Limits
- **Deployments:** Unlimited
- **Bandwidth:** 100 GB/month
- **Serverless Functions:** 100 GB-hours/month
- **Custom domain:** Free (bring your own)

### Pages to Build

```
/               → Landing page (install instructions, what it protects)
/leaderboard    → Live scores from Supabase (Realtime WebSocket updates)  
/challenges     → Challenge list, descriptions, current hunters' attempts
/docs           → Rendered from this docs/ folder (or link to GitHub)
/submit         → Hunter submission form (posts to Railway API or GitHub Issue)
```

---

## 4. Railway (Arena API + Validation Server)

### What Lives on Railway

The **Arena API** is a FastAPI server that:
- Runs the auto-validator (replays exploits in isolation)
- Serves challenge metadata
- Writes validated results to Supabase

### Setup

1. Go to [railway.app](https://railway.app) → New Project
2. Deploy from GitHub → select `McpVanguard` repo
3. Set **Root Directory** to `arena-api/` 
4. Railway auto-detects Python and runs `pip install -r requirements.txt`
5. Set **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
6. Add Environment Variables:
   ```
   SUPABASE_URL=https://xxxxxxxxxxxx.supabase.co
   SUPABASE_SERVICE_KEY=eyJ...   ← service role key for writes
   ```

### Free Tier

Railway gives **$5/month free credit**. A minimal FastAPI server uses ~$0.50–$1/month → effectively free for MVP.

### When Railway Is Not Needed

For Phase 1, you can skip Railway entirely:
- **Exploit validation** → Done entirely in GitHub Actions (free, sandboxed)
- **Challenge metadata** → Served as JSON files from the GitHub repo directly

Only add Railway when you need persistent server-side state or faster validation.

---

## 5. PyPI (Package Distribution)

Once `core/` is production-ready, publish as a pip package:

```bash
# Fill in setup.py properly first, then:
pip install build twine
python -m build
twine upload dist/*   # Needs PyPI account (free)
```

When published, Hunters install via:
```bash
pip install mcp-vanguard
vanguard start --server "npx @modelcontextprotocol/server-filesystem ."
```

### `setup.py` (to be filled):
```python
from setuptools import setup, find_packages

setup(
    name="mcp-vanguard",
    version="0.1.0",
    description="Real-time AI antivirus and runtime protection for MCP agents",
    author="Your Name",
    packages=find_packages(),
    install_requires=[
        "mcp>=1.0.0",
        "fastmcp>=0.9.0",
        "uvloop>=0.19.0",
        "pyyaml>=6.0",
        "httpx>=0.27.0",
        "typer>=0.12.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": ["vanguard=core.cli:app"]
    },
    python_requires=">=3.11",
)
```

---

## 6. Deployment Checklist

Before first public launch:

### GitHub
- [ ] Repository is public
- [ ] Topics added: `mcp`, `ai-security`, `llm-security`, `ctf`, `red-teaming`
- [ ] Issue templates created (`exploit_submission.md`)
- [ ] Labels created: `exploit-submission`, `validated`, `rejected`
- [ ] `CONTRIBUTING.md` written
- [ ] `SECURITY.md` written (responsible disclosure policy)

### Supabase
- [ ] Tables created (hunters, exploits, sessions, signatures)
- [ ] RLS policies enabled
- [ ] Realtime enabled for hunters table
- [ ] Anon key added to Vercel env vars
- [ ] Service key added to Railway env vars
- [ ] Service key added to GitHub Actions secrets

### Vercel
- [ ] Next.js frontend deployed
- [ ] Environment variables set
- [ ] All pages building without errors
- [ ] Leaderboard fetching real data

### GitHub Actions
- [ ] `test.yml` running pytest on push
- [ ] `validate_poe.yml` triggering on issue with `exploit-submission` label
- [ ] `SUPABASE_URL` and `SUPABASE_SERVICE_KEY` set as repository secrets

### PyPI (Phase 2)
- [ ] `setup.py` complete with correct metadata
- [ ] Package published: `pip install mcp-vanguard` works
- [ ] `vanguard` CLI entry point working

---

## 7. Domain & Branding (Optional, Free)

For a professional URL:
- `mcpvanguard.dev` — ~$12/year on Google Domains
- OR: use the free Vercel- **Subdomain**: `vanguard.provnai.com`

The Vercel subdomain is completely fine for MVP and community building.
