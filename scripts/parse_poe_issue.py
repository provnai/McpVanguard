#!/usr/bin/env python3
"""
scripts/parse_poe_issue.py
Parses a GitHub issue body to extract the PoE JSON bundle.
Used by the validate_poe.yml GitHub Action.

Usage:
    python scripts/parse_poe_issue.py "$ISSUE_BODY" > poe_extracted.json
"""

import json
import re
import sys


def extract_poe_from_issue(issue_body: str) -> dict:
    """
    Extract the PoE JSON block from a GitHub issue body.
    Looks for a ```json ... ``` code block in the 'Proof of Exploit' section.
    """
    if not issue_body:
        raise ValueError("Issue body is empty")

    # Look for JSON code block
    json_block_pattern = re.compile(
        r'```json\s*\n([\s\S]*?)\n\s*```',
        re.MULTILINE
    )

    matches = json_block_pattern.findall(issue_body)
    if not matches:
        raise ValueError("No JSON code block found in issue body")

    # Try each JSON block until we find a valid PoE bundle
    for match in matches:
        try:
            data = json.loads(match.strip())
            if "challenge_level" in data and "conversation_log" in data:
                return data
        except json.JSONDecodeError:
            continue

    raise ValueError("No valid PoE bundle found in JSON blocks")


def extract_metadata_from_issue(issue_body: str) -> dict:
    """Extract the hunter's bypass technique description from the issue."""
    technique_pattern = re.compile(
        r'###\s*Bypass Technique\s*\n+(.*?)(?=\n###|\Z)',
        re.DOTALL
    )
    match = technique_pattern.search(issue_body)
    technique = match.group(1).strip() if match else "Not provided"

    return {"bypass_technique": technique}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: parse_poe_issue.py <issue_body>", file=sys.stderr)
        sys.exit(1)

    issue_body = sys.argv[1]

    try:
        poe = extract_poe_from_issue(issue_body)
        meta = extract_metadata_from_issue(issue_body)
        poe.update(meta)

        print(json.dumps(poe, indent=2))
        sys.exit(0)

    except ValueError as e:
        error_output = {
            "error": str(e),
            "validated": False,
        }
        print(json.dumps(error_output, indent=2))
        sys.exit(1)
