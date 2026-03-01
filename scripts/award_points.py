#!/usr/bin/env python3
"""
scripts/award_points.py
Awards points to a hunter in Supabase after a validated exploit.
Used by the validate_poe.yml GitHub Action.

Usage:
    python scripts/award_points.py poe.json replay_result.json github_handle
"""

import json
import os
import sys


def award_points(poe_path: str, result_path: str, github_handle: str):
    """Insert/update hunter record in Supabase and create exploit record."""

    try:
        from supabase import create_client
    except ImportError:
        print("❌ supabase-py not installed. Run: pip install supabase", file=sys.stderr)
        sys.exit(1)

    supabase_url = os.environ.get("SUPABASE_URL")
    supabase_key = os.environ.get("SUPABASE_SERVICE_KEY")

    if not supabase_url or not supabase_key:
        print("❌ SUPABASE_URL or SUPABASE_SERVICE_KEY not set", file=sys.stderr)
        sys.exit(1)

    client = create_client(supabase_url, supabase_key)

    with open(poe_path) as f:
        poe = json.load(f)
    with open(result_path) as f:
        result = json.load(f)

    level = poe.get("challenge_level")
    points = result.get("points_awarded", 0)
    poe_id = poe.get("poe_id")
    bypass_technique = poe.get("bypass_technique", "")

    # Upsert the hunter record
    handle = github_handle.lstrip("@")
    
    existing = client.table("hunters").select("id").eq("github_handle", handle).execute()

    if existing.data:
        hunter_id = existing.data[0]["id"]
        print(f"✅ Found existing hunter: {handle} ({hunter_id})")
    else:
        # Create new hunter
        new_hunter = client.table("hunters").insert({
            "github_handle": handle,
        }).execute()
        hunter_id = new_hunter.data[0]["id"]
        print(f"✅ Created new hunter: {handle} ({hunter_id})")

    # Insert the exploit record
    exploit = client.table("exploits").insert({
        "hunter_id": hunter_id,
        "challenge_level": level,
        "poe_bundle": poe,
        "bypass_technique": bypass_technique,
        "status": "validated",
        "points_awarded": points,
    }).execute()

    print(f"✅ Exploit recorded: level={level} points={points}")
    print(f"✅ Exploit ID: {exploit.data[0]['id']}")

    # The DB trigger (award_points_on_validation) handles the hunter points update
    print(f"\n🏆 {handle} awarded {points} points for Level {level} bypass!")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: award_points.py <poe.json> <replay_result.json> <github_handle>")
        sys.exit(1)

    award_points(
        poe_path=sys.argv[1],
        result_path=sys.argv[2],
        github_handle=sys.argv[3],
    )
