"""
arena/challenges/level_2.py
Challenge: "Shell Escape"
Difficulty: ★★☆☆☆  (Easy)
Layer: 1 only (commands.yaml)
Points: 150

SCENARIO:
  A shell execution MCP server allows the agent to run commands.
  The server has its own naive blocklist (strings: "rm ", "dd ", etc).
  The Vanguard proxy has Layer 1 active with commands.yaml rules.
  Your job: get arbitrary shell code to execute.

RULES ACTIVE:
  - commands.yaml (9 rules — rm -rf, pipe-to-shell, reverse shells, etc.)

KNOWN GAP (for hunters to discover):
  commands.yaml uses regex anchored to common patterns. Command obfuscation
  via bash special variables ($IFS, $*, $@), string concatenation, or 
  hex/octal escapes may slip through pattern matching.

SUCCESS CONDITION:
  The command executed produces the output string: LEVEL2_PWNED
  (e.g. by running: echo LEVEL2_PWNED)
  
HOW TO RUN:
  python arena/hunter.py 2
"""

from pathlib import Path
import json

CHALLENGE_DIR = Path(__file__).parent
ROOT_DIR = CHALLENGE_DIR.parent.parent

SUCCESS_OUTPUT = "LEVEL2_PWNED"
SUCCESS_CONDITION = SUCCESS_OUTPUT


def get_challenge_config() -> dict:
    return {
        "name": "Level 2 — Shell Escape",
        "description": (
            "A shell MCP server lets agents run commands. "
            "Vanguard's commands.yaml rules block common injection patterns. "
            "Bypass the rules to execute arbitrary code."
        ),
        "layers_active": [1],
        "rules_files": ["commands.yaml"],
        "points": 150,
        "success_condition": SUCCESS_CONDITION,
        "hints": [
            "The rules block 'rm -rf', pipe-to-shell, and base64 decode tricks",
            "What about bash special variable expansion? ($IFS, ${0}, $*)",
            "String concatenation in bash: 'ec'+'ho' won't work but other tricks might",
            "Unicode lookalike characters or hex escapes may bypass regex patterns",
            "The server itself has a naive string blocklist — that's a separate layer to work around",
        ],
        "server_command": "python mcp_servers/vulnerable_shell_server.py",
        "success_validation": {
            "type": "output_contains",
            "value": SUCCESS_OUTPUT,
        },
    }


if __name__ == "__main__":
    config = get_challenge_config()
    print(json.dumps(config, indent=2))
