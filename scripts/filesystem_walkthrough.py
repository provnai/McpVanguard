"""Local integration evidence, not customer adoption or a production audit."""
import argparse
from collections import deque
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import pathlib
import platform
import queue
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time

base = pathlib.Path(__file__).parent
node = shutil.which("node")
entry = None
EXPECTED_PYTHON_VERSION = "3.12.14"
EXPECTED_NODE_VERSION = "v24.22.1"
EXPECTED_FILESYSTEM_VERSION = "2.1.0"


def stop_owned_process(process):
    try:
        process.wait(timeout=10)
        return
    except subprocess.TimeoutExpired:
        pass
    if sys.platform == "win32":
        # Kill only this spawned process tree, never all Python/Node processes.
        if process.poll() is None:
            try:
                outcome = subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                         timeout=10, check=False)
                if outcome.returncode and process.poll() is None:
                    process.terminate()
            except (OSError, subprocess.TimeoutExpired):
                if process.poll() is None:
                    process.terminate()
    else:
        process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def sha256_file(path):
    digest = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def directory_sha256(directory):
    root = pathlib.Path(directory)
    digest = hashlib.sha256()
    files = sorted(path for path in root.rglob("*") if path.is_file())
    if any(path.is_symlink() for path in root.rglob("*")):
        raise RuntimeError(f"Symlinks are not accepted in the fixture rules directory: {root}")
    for path in files:
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(bytes.fromhex(sha256_file(path)))
    return digest.hexdigest()


def mcpvanguard_identity():
    matches = [
        distribution for distribution in importlib.metadata.distributions()
        if (distribution.metadata.get("Name") or "").lower().replace("_", "-") == "mcp-vanguard"
    ]
    if len(matches) != 1:
        raise RuntimeError(
            f"Expected exactly one installed mcp-vanguard distribution; found {len(matches)}. "
            "Use a clean virtual environment."
        )

    distribution = matches[0]
    if distribution.version != "2.2.2":
        raise RuntimeError(f"This unpublished walkthrough is pinned to mcp-vanguard==2.2.2; found {distribution.version}")
    files = distribution.files
    if not files:
        raise RuntimeError("The installed mcp-vanguard distribution has no file manifest")

    digest = hashlib.sha256()
    file_count = 0
    for member in sorted(files, key=lambda item: item.as_posix()):
        path = pathlib.Path(distribution.locate_file(member))
        if not path.is_file():
            raise RuntimeError(f"Installed distribution file is missing: {member}")
        digest.update(member.as_posix().encode("utf-8") + b"\0")
        digest.update(bytes.fromhex(sha256_file(path)))
        file_count += 1

    spec = importlib.util.find_spec("core")
    expected_core = pathlib.Path(distribution.locate_file("core/__init__.py")).resolve()
    if spec is None or spec.origin is None or pathlib.Path(spec.origin).resolve() != expected_core:
        raise RuntimeError("Imported McpVanguard source does not match the installed distribution manifest")

    return {
        "distribution": "mcp-vanguard",
        "version": distribution.version,
        "installed_files_sha256": digest.hexdigest(),
        "installed_file_count": file_count,
        "core_module_relative_path": "core/__init__.py",
        "core_module_matches_distribution": True,
    }


def validate_environment():
    if platform.system() != "Windows":
        raise RuntimeError("This walkthrough is verified on Windows only")
    if platform.python_implementation() != "CPython":
        raise RuntimeError("This walkthrough is verified with CPython only")
    if platform.python_version() != EXPECTED_PYTHON_VERSION:
        raise RuntimeError(
            f"This walkthrough is verified with Python {EXPECTED_PYTHON_VERSION}; "
            f"found {platform.python_version()}"
        )
    if not node:
        raise RuntimeError("Node was not found on PATH")
    version = subprocess.run([node, "--version"], capture_output=True, text=True,
                             timeout=5, check=True).stdout.strip()
    if version != EXPECTED_NODE_VERSION:
        raise RuntimeError(
            f"This walkthrough is verified with Node {EXPECTED_NODE_VERSION}; found {version}"
        )
    return version


def python_lock_identity(lock_path):
    lock_path = pathlib.Path(lock_path).resolve()
    locked = {}
    for line in lock_path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", line)
        if match:
            name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
            if name in locked:
                raise RuntimeError(f"Duplicate Python package in lock file: {name}")
            locked[name] = match.group(2)
    if not locked or locked.get("mcp-vanguard") != "2.2.2":
        raise RuntimeError("Python lock must pin mcp-vanguard==2.2.2")
    for name, expected in locked.items():
        try:
            actual = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise RuntimeError(f"Locked Python package is not installed: {name}") from exc
        if actual != expected:
            raise RuntimeError(f"Python lock mismatch for {name}: installed {actual}, expected {expected}")
    return {"sha256": sha256_file(lock_path), "package_count": len(locked)}


def npm_lock_identity(lock_path):
    lock_path = pathlib.Path(lock_path).resolve()
    manifest_path = lock_path.with_name("package.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    package_name = "@modelcontextprotocol/server-filesystem"
    expected_version = EXPECTED_FILESYSTEM_VERSION
    if (manifest.get("dependencies") or {}).get(package_name) != expected_version:
        raise RuntimeError(f"npm manifest must pin {package_name}@{expected_version}")
    root_package = (lock.get("packages") or {}).get("node_modules/" + package_name) or {}
    if root_package.get("version") != expected_version:
        raise RuntimeError(f"npm lock must contain {package_name}@{expected_version}")
    return {
        "manifest_sha256": sha256_file(manifest_path),
        "lock_sha256": sha256_file(lock_path),
        "locked_package_count": len(lock.get("packages") or {}),
    }


def runner_identity():
    commit = None
    repo_root = base.parent.resolve()
    kit_files = [
        base / "filesystem_walkthrough.py",
        base / "filesystem_relay.py",
        base / "filesystem_probe.py",
        base / "run_filesystem_walkthrough.ps1",
        base / "filesystem-evaluation" / "requirements.in",
        base / "filesystem-evaluation" / "requirements.lock",
        base / "filesystem-evaluation" / "package.json",
        base / "filesystem-evaluation" / "package-lock.json",
        repo_root / "tests" / "test_filesystem_walkthrough.py",
        repo_root / "docs" / "FILESYSTEM_WALKTHROUGH.md",
    ]
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo_root,
            capture_output=True, text=True, timeout=5, check=True,
        )
        commit = result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass

    tracking = {}
    file_hashes = {}
    for path in kit_files:
        key = str(path)
        try:
            relative = path.resolve().relative_to(repo_root).as_posix()
            key = relative
            indexed = subprocess.run(
                ["git", "ls-files", "--error-unmatch", "--", relative],
                cwd=repo_root, capture_output=True, text=True, timeout=5, check=False,
            )
            if indexed.returncode == 0:
                state = "tracked"
            elif indexed.returncode == 1:
                # Git emits a pathspec diagnostic for an ordinary untracked file.
                state = "untracked"
            else:
                state = "unknown"
        except (OSError, ValueError, subprocess.SubprocessError):
            state = "unknown"
        tracking[key] = state
        try:
            file_hashes[key] = sha256_file(path) if path.is_file() else None
        except OSError:
            file_hashes[key] = None
    return {
        "repository_head": commit,
        "kit_file_tracking": tracking,
        "kit_file_sha256": file_hashes,
        "script_sha256": sha256_file(__file__),
    }


def read_jsonl(path):
    if not pathlib.Path(path).is_file():
        return []
    events = []
    for line_number, line in enumerate(pathlib.Path(path).read_text(encoding="utf-8").splitlines(), 1):
        try:
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError("Non-object evidence event")
            events.append(event)
        except ValueError as exc:
            raise RuntimeError(f"Invalid JSONL in {path} at line {line_number}") from exc
    return events


def assert_event_ids(events, event_name, expected_ids, mode):
    actual_ids = [event.get("id") for event in events if event.get("event") == event_name]
    if actual_ids != expected_ids:
        raise RuntimeError(f"{mode}: {event_name} IDs {actual_ids!r}, expected {expected_ids!r}")


def verify_upstream_responses(events, expected_ids, tool_error_ids=()):
    responses = [event for event in events if event.get("event") == "upstream_response_received"]
    actual_ids = [event.get("id") for event in responses]
    if actual_ids != expected_ids:
        raise RuntimeError(f"Upstream response IDs {actual_ids!r}, expected {expected_ids!r}")
    expected_errors = set(tool_error_ids)
    for event in responses:
        call_id = event.get("id")
        if event.get("jsonrpc_error") is not False:
            raise RuntimeError(f"Upstream returned a JSON-RPC error for call {call_id}")
        expected_tool_error = call_id in expected_errors
        if event.get("tool_is_error") is not expected_tool_error:
            raise RuntimeError(f"Unexpected upstream tool error state for call {call_id}")


def verify_probe_events(events, expected_ids, mode):
    assert_event_ids(events, "upstream_probe_ready", [1], mode)
    for event_name in ("relay_received", "upstream_process_ingress_received", "upstream_stdin_forwarded",
                       "upstream_response_received"):
        assert_event_ids(events, event_name, expected_ids, mode)
    assert_event_ids(events, "upstream_response_missing", [], mode)
    if any(event.get("event") in ("upstream_probe_failure", "relay_failure") for event in events):
        raise RuntimeError(f"{mode}: probe or relay failure")
    for identity in expected_ids:
        sequence = [event["event"] for event in events if event.get("id") == identity]
        if sequence != ["relay_received", "upstream_process_ingress_received",
                        "upstream_stdin_forwarded", "upstream_response_received"]:
            raise RuntimeError(f"{mode}: incomplete or reordered evidence for {identity}")


def text_content(response):
    result = response.get("result")
    if not isinstance(result, dict):
        return []
    content = result.get("content")
    if not isinstance(content, list):
        return []
    return [item["text"] for item in content
            if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str)]


def verify_guarded_policy_events(audit_path):
    events = [event for event in read_jsonl(audit_path) if event.get("method") == "tools/call"]
    expected = [
        (2, "benign_read", "read_text_file", "ALLOW", True),
        (3, "restricted_read", "read_text_file", "BLOCK", False),
        (4, "benign_write", "write_file", "ALLOW", True),
        (5, "restricted_write", "write_file", "BLOCK", False),
    ]
    if len(events) != len(expected):
        raise RuntimeError(f"Expected {len(expected)} gateway tools/call audit events; found {len(events)}")

    mapped = []
    for event, (call_id, case, tool, action, upstream_called) in zip(events, expected):
        actual_action = (event.get("effective_policy_action") or event.get("decision") or event.get("action") or "").upper()
        explanation = event.get("policy_explanation") or {}
        if event.get("tool_name") != tool or actual_action != action:
            raise RuntimeError(f"Gateway audit mismatch for {case}: {event!r}")
        if explanation.get("upstream_called") is not upstream_called:
            raise RuntimeError(f"Gateway upstream_called mismatch for {case}: {event!r}")
        mapped.append({"call_id": call_id, "case": case, "tool": tool,
                       "decision": actual_action, "upstream_called": upstream_called})
    return mapped


def fixture_environment(root):
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    return {
        "PATH": os.pathsep.join([
            str(pathlib.Path(sys.executable).parent),
            str(pathlib.Path(node).parent),
            str(pathlib.Path(system_root) / "System32"),
        ]),
        "SystemRoot": system_root,
        "WINDIR": system_root,
        "TEMP": str(root),
        "TMP": str(root),
        "VANGUARD_LOG_FILE": str(root / "audit.log"),
        "VANGUARD_AUDIT_FORMAT": "json",
    }


def run(root, policy, mode):
    guarded = mode == "guarded"
    log = root / ("guarded-upstream.jsonl" if guarded else "raw-upstream.jsonl")
    roots = [root] if mode == "broad" else [root / "input", root / "output"]
    upstream = [sys.executable, str(base / "filesystem_relay.py"), str(log),
                node, str(entry), *(str(path) for path in roots)]
    arguments = upstream
    if guarded:
        # The gateway parses --server with shlex on every platform.
        command = shlex.join(upstream)
        arguments = [sys.executable, "-m", "core.cli", "start", "--profile", "balanced",
                     "--rules-dir", str(policy), "--server", command]
    environment = fixture_environment(root)
    process = subprocess.Popen(arguments, cwd=root, env=environment, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    replies = queue.Queue(maxsize=8)
    errors = deque(maxlen=40)
    reader_failed = threading.Event()
    readers_stopped = threading.Event()

    def stdout():
        while not readers_stopped.is_set():
            line = process.stdout.readline(4 * 1024 * 1024 + 1)
            if not line:
                return
            if len(line) > 4 * 1024 * 1024 or not line.endswith("\n"):
                reader_failed.set()
                return
            try:
                response = json.loads(line)
            except ValueError:
                response = {"_protocol_error": "non-JSON stdout line"}
            if not isinstance(response, dict):
                response = {"_protocol_error": "non-object JSON stdout message"}
            try:
                replies.put(response, timeout=0.1)
            except queue.Full:
                reader_failed.set()
                return

    def stderr():
        while not readers_stopped.is_set():
            line = process.stderr.readline(65537)
            if not line:
                return
            errors.append(line)

    readers = [threading.Thread(target=stdout, daemon=True),
               threading.Thread(target=stderr, daemon=True)]
    for reader in readers:
        reader.start()

    def send(method, params, identity=None):
        request = {"jsonrpc": "2.0", "method": method, "params": params}
        if identity is not None:
            request["id"] = identity
        process.stdin.write(json.dumps(request) + "\n")
        process.stdin.flush()
        if identity is None:
            return None
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if reader_failed.is_set():
                raise RuntimeError("Runner response queue or frame limit exceeded")
            try:
                response = replies.get(timeout=max(.01, deadline - time.monotonic()))
            except queue.Empty as exc:
                raise TimeoutError(f"No response to {method} in {mode} mode") from exc
            if "_protocol_error" in response:
                raise RuntimeError(response["_protocol_error"])
            if response.get("id") != identity:
                raise RuntimeError("Duplicate or unexpected response ID at runner")
            return response
        raise TimeoutError(method)

    try:
        initialized = send("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                           "clientInfo": {"name": "disposable-fixture", "version": "1"}}, 1)
        if "result" not in initialized:
            raise RuntimeError(initialized)
        send("notifications/initialized", {})
        calls = {}
        cases = [("benign_read", "read_text_file", {"path": str(root / "input/public.txt")}),
                 ("restricted_read", "read_text_file", {"path": str(root / "private/internal.txt")}),
                 ("benign_write", "write_file", {"path": str(root / "output/report.txt"), "content": "fixture report"}),
                 ("restricted_write", "write_file", {"path": str(root / "input/no-write.txt"),
                  "content": "guarded modification" if guarded else "raw modification"})]
        for identity, (label, name, params) in enumerate(cases, 2):
            calls[label] = send("tools/call", {"name": name, "arguments": params}, identity)
        for label in ("benign_read", "benign_write"):
            if "result" not in calls[label] or calls[label]["result"].get("isError", False):
                raise RuntimeError(calls[label])
        if text_content(calls["benign_read"]) != ["public fixture"]:
            raise RuntimeError("The allowed read did not return the exact fixture content")
        output_file = root / "output" / "report.txt"
        if not output_file.is_file() or output_file.read_bytes() != b"fixture report":
            raise RuntimeError("The allowed write did not produce the expected output file")
        if mode == "broad" and text_content(calls["restricted_read"]) != ["private synthetic fixture"]:
            raise RuntimeError("The broad-root control did not return the exact private fixture")
        for label in ("restricted_read", "restricted_write"):
            if guarded:
                if calls[label].get("error", {}).get("data", {}).get("blocked_by") != "McpVanguard":
                    raise RuntimeError(calls[label])
            elif mode == "native" and label == "restricted_read":
                if not calls[label].get("result", {}).get("isError", False):
                    raise RuntimeError("Native roots failed to reject private read")
            elif "result" not in calls[label] or calls[label]["result"].get("isError", False):
                raise RuntimeError(calls[label])
        input_file = root / "input" / "no-write.txt"
        expected_input = "original fixture" if guarded else "raw modification"
        if not input_file.is_file() or input_file.read_bytes() != expected_input.encode("utf-8"):
            raise RuntimeError(f"{mode}: input file did not match its expected post-call content")
        return calls, log, root / "audit.log"
    except Exception as exc:
        raise RuntimeError(f"{exc}; {''.join(errors)[-2000:]}") from exc
    finally:
        try:
            try:
                process.stdin.close()
            except OSError:
                pass
            stop_owned_process(process)
        finally:
            readers_stopped.set()
            for reader in readers:
                reader.join(timeout=2)
            for stream, reader in zip((process.stdout, process.stderr), readers):
                try:
                    if not reader.is_alive():
                        stream.close()
                except OSError:
                    pass
            if process.returncode != 0:
                raise RuntimeError(f"{mode}: upstream/gateway process exited {process.returncode}")
            if any(reader.is_alive() for reader in readers):
                raise RuntimeError(f"{mode}: transport reader did not stop")
            if reader_failed.is_set():
                raise RuntimeError(f"{mode}: reader queue or frame limit exceeded")
            if not replies.empty():
                raise RuntimeError(f"{mode}: unexpected trailing response")



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-entry", type=pathlib.Path, required=True,
                        help="Installed official filesystem dist/index.js")
    parser.add_argument("--python-lock", type=pathlib.Path,
                        help="Hash-locked Python requirements used to create this environment")
    parser.add_argument("--npm-lock", type=pathlib.Path,
                        help="npm package-lock.json used to install the upstream server")
    parser.add_argument("--summary", action="store_true",
                        help="Print a concise comparison instead of JSON")
    args = parser.parse_args()
    global entry
    entry = args.server_entry.resolve()
    if not entry.is_file():
        parser.error("An installed official filesystem server entry point is required")
    package = json.loads((entry.parent.parent / "package.json").read_text(encoding="utf-8"))
    if (package.get("name") != "@modelcontextprotocol/server-filesystem"
            or package.get("version") != EXPECTED_FILESYSTEM_VERSION):
        parser.error(
            f"This walkthrough is verified with server-filesystem {EXPECTED_FILESYSTEM_VERSION} only"
        )
    try:
        node_version = validate_environment()
        if bool(args.python_lock) != bool(args.npm_lock):
            raise RuntimeError("Pass both --python-lock and --npm-lock, or neither")
        lock_identity = None
        if args.python_lock and args.npm_lock:
            lock_identity = {
                "python": python_lock_identity(args.python_lock),
                "npm": npm_lock_identity(args.npm_lock),
            }
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    try:
        product_identity = mcpvanguard_identity()
    except (OSError, RuntimeError) as exc:
        parser.error(f"Cannot verify the installed McpVanguard artifact: {exc}")

    package_path = entry.parent.parent / "package.json"
    upstream_identity = {
        "name": package["name"],
        "version": package["version"],
        "package_json_sha256": sha256_file(package_path),
        "entry_sha256": sha256_file(entry),
    }
    reports = {}
    with tempfile.TemporaryDirectory(prefix="mcpvanguard-filesystem-") as folder:
        for mode in ("broad", "native", "guarded"):
            root = pathlib.Path(folder) / mode
            for directory in ("input", "private", "output", "policy"):
                (root / directory).mkdir(parents=True)
            (root / "input/public.txt").write_text("public fixture", encoding="utf-8")
            (root / "private/internal.txt").write_text("private synthetic fixture", encoding="utf-8")
            (root / "input/no-write.txt").write_text("original fixture", encoding="utf-8")
            protected_before = sha256_file(root / "input/no-write.txt")
            policy = root / "policy"
            (policy / "safe_zones.yaml").write_text(json.dumps([
                {"tool": "read_text_file", "allowed_prefixes": [str(root / "input")], "recursive": True},
                {"tool": "write_file", "allowed_prefixes": [str(root / "output")], "recursive": True},
            ]), encoding="utf-8")
            calls, log, audit_log = run(root, policy, mode)
            events = read_jsonl(log)
            expected_forwarded_ids = [2, 4] if mode == "guarded" else [2, 3, 4, 5]
            verify_probe_events(events, expected_forwarded_ids, mode)
            verify_upstream_responses(
                events, expected_forwarded_ids,
                tool_error_ids=[3] if mode == "native" else [],
            )
            assert_event_ids(events, "upstream_response_missing", [], mode)
            unchanged = (root / "input/no-write.txt").read_text(encoding="utf-8") == "original fixture"
            protected_after = sha256_file(root / "input/no-write.txt")
            if mode == "guarded" and protected_before != protected_after:
                raise RuntimeError("Guarded protected fixture hash changed")
            if unchanged != (mode == "guarded"):
                raise RuntimeError(f"{mode}: unexpected input write effect")
            if mode == "guarded":
                forwarded = [item for item in events if item.get("event") == "relay_received"]
                paths = [item["arguments"]["path"] for item in forwarded]
                if paths != [str(root / "input/public.txt"), str(root / "output/report.txt")]:
                    raise RuntimeError("Unexpected guarded upstream paths")
                policy_events = verify_guarded_policy_events(audit_log)
            else:
                policy_events = None
            reports[mode] = {
                "benign_read": "allowed", "benign_write": "allowed",
                "private_read": "allowed" if mode == "broad" else "blocked",
                "input_write": "blocked" if mode == "guarded" else "allowed",
                "allowed_read_content_verified": True,
                "allowed_write_effect_verified": True,
                "output_file_sha256": sha256_file(root / "output" / "report.txt"),
                "input_file_sha256": sha256_file(root / "input" / "no-write.txt"),
                "relay_received_call_ids": expected_forwarded_ids,
                "upstream_response_call_ids": expected_forwarded_ids,
                "upstream_ingress_call_ids": [event["id"] for event in events
                                              if event.get("event") == "upstream_process_ingress_received"],
                "upstream_forwarded_call_ids": [event["id"] for event in events
                                                if event.get("event") == "upstream_stdin_forwarded"],
                "upstream_probe_ready": True,
                "upstream_response_missing_ids": [],
                "protected_fixture_sha256_before": protected_before,
                "protected_fixture_sha256_after": protected_after,
                "blocked_before_relay_call_ids": [3, 5] if mode == "guarded" else [],
                "input_unchanged": unchanged,
                "ruleset_sha256": directory_sha256(policy) if mode == "guarded" else None,
                "gateway_policy_events": policy_events,
            }
    if args.summary:
        print("PASS: disposable files only; not an OS sandbox")
        print("Mode       Public read  Report write  Private read  Input write  Relay/response")
        for mode, report in reports.items():
            print(f"{mode:<10} {report['benign_read']:<12} {report['benign_write']:<13} "
                  f"{report['private_read']:<13} {report['input_write']:<12} "
                  f"{len(report['relay_received_call_ids'])}/{len(report['upstream_response_call_ids'])}")
        return
    print(json.dumps({"scope": "disposable-synthetic-local-files",
                      "mcpvanguard": product_identity,
                      "runner": runner_identity(),
                      "upstream": upstream_identity,
                      "environment": {"python": platform.python_version(),
                                      "python_implementation": platform.python_implementation(),
                                      "python_build": platform.python_build(),
                                      "pip": importlib.metadata.version("pip"),
                                      "platform": platform.platform(),
                                      "node": node_version},
                      "profiles": {"guarded": "balanced", "broad": None, "native": None},
                      "gateway_audit_correlation": "sequential_tool_call_order; audit schema has no JSON-RPC request ID",
                      "dependency_locks": lock_identity,
                      "cases": reports, "passed": True}, indent=2))


if __name__ == "__main__":
    main()
