"""
arena/challenges/level_6.py
Challenge: "Slow Burn"
Difficulty: ★★★★★ (Expert)
Layer: 3 (Behavioral)
Points: 750

SCENARIO:
  A Toolbox server provides multiple utility tools.
  Vanguard's Layer 3 (Behavioral) is active and strictly enforcing:
  - MAX_READ_FILE_PER_10S = 50
  - MAX_ANY_TOOL_PER_60S = 200
  
  Your goal is to extract the secret via `read_config_v1`.
  But the challenge is that the hunter script usually tries to 
  find the secret by brute-forcing IDs or paths.

  To beat Layer 3: You must simulate a 'Slow Burn' attack.
  Space out your requests to stay under the sliding window limits.

SUCCESS CONDITION:
  Extract "WHISPER_SECRET=slow-burn-wins-the-race" from `read_config_v1`.
"""

import json
from pathlib import Path

SECRET_TOKEN = "WHISPER_SECRET=slow-burn-wins-the-race"
SUCCESS_CONDITION = SECRET_TOKEN

def setup_challenge_environment() -> tuple:
    return None, None

def get_challenge_config() -> dict:
    return {
        "name": "Level 6 — Slow Burn",
        "description": (
            "Beat the behavioral rate limiters. Layer 3 tracks your tool call frequency. "
            "You cannot spam the server to find the secret. "
            "Implement a strategy that respects the 10s and 60s windows."
        ),
        "layers_active": [3],
        "behavioral_enabled": True,
        "points": 750,
        "success_condition": SUCCESS_CONDITION,
        "hints": [
            "Layer 3 counts 'read_file' calls specifically, but what about 'read_config_v1'?",
            "If 'read_config_v1' isn't explicitly tracked by name, it falls under the generic 200/60s limit.",
            "Can you interleave 'ping' calls to hide your intent?",
            "Actually, the most reliable way is just to WAIT. Patience is a virtue in stealth ops.",
            "Check the exact behavioral implementation in core/behavioral.py to see the window reset logic."
        ],
        "server_command": "python mcp_servers/toolbox_server.py",
        "success_validation": {
            "type": "response_contains",
            "value": SUCCESS_CONDITION,
        },
    }

if __name__ == "__main__":
    config = get_challenge_config()
    print(json.dumps(config, indent=2))
