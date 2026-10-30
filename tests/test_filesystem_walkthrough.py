"""The optional real-server example never downloads or uses existing data roots."""
import importlib.util
from pathlib import Path

import pytest
import json
import subprocess
import sys
from types import SimpleNamespace
import queue
import threading
import time


VALID_INITIALIZE = {"protocolVersion": "2025-11-25", "capabilities": {},
                    "serverInfo": {"name": "synthetic-fixture", "version": "1"}}


def read_frame(process):
    frames = queue.Queue()
    threading.Thread(target=lambda: frames.put(process.stdout.readline()), daemon=True).start()
    try:
        return frames.get(timeout=5)
    except queue.Empty:
        process.kill()
        process.communicate(timeout=5)
        pytest.fail("Timed out waiting for a frame")


def start_probe_fixture(tmp_path, behavior="ok", initialize_result=...):
    if initialize_result is ...:
        initialize_result = VALID_INITIALIZE
    child = tmp_path / "child.py"
    child.write_text(
        "import json, sys\n"
        f"behavior = {behavior!r}\n"
        "for line in sys.stdin.buffer:\n"
        " message = json.loads(line)\n"
        " if message['method'] == 'initialize':\n"
        f"  result = {{'jsonrpc':'2.0','id':message['id'],'result':{initialize_result!r}}}\n"
        "  if behavior == 'bad_init': result = {'jsonrpc':'2.0','id':message['id'],'error':{'code':-1,'message':'no'}}\n"
        "  print(json.dumps(result), flush=True)\n"
        "  continue\n"
        " if behavior == 'missing': break\n"
        " if behavior == 'crash': sys.exit(17)\n"
        " if behavior == 'malformed': print('{bad', flush=True); break\n"
        " if behavior == 'nonobject': print('[]', flush=True); break\n"
        " result = {'jsonrpc':'2.0','id':999 if behavior == 'unexpected' else message['id'],'result':{'content':[]}}\n"
        " print(json.dumps(result), flush=True)\n"
        " if behavior == 'duplicate': print(json.dumps(result), flush=True)\n",
        encoding="utf-8")
    probe = Path(__file__).resolve().parents[1] / "scripts/filesystem_probe.py"
    log = tmp_path / "probe.jsonl"
    process = subprocess.Popen([sys.executable, str(probe), str(log), sys.executable, str(child)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return process, log


def initialize_probe(process):
    process.stdin.write(b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n')
    process.stdin.flush()
    assert json.loads(read_frame(process))["id"] == 1


@pytest.mark.parametrize("behavior", ["missing", "crash", "malformed", "nonobject", "unexpected", "duplicate"])
def test_probe_fails_on_invalid_or_incomplete_child_exchange(tmp_path, behavior):
    process, log = start_probe_fixture(tmp_path, behavior)
    initialize_probe(process)
    process.communicate(b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_text_file"}}\n', timeout=10)
    assert process.returncode != 0
    events = [json.loads(line) for line in log.read_text().splitlines()]
    assert sum(e["event"] == "upstream_probe_ready" for e in events) == 1
    assert any(e["event"] == "upstream_probe_failure" for e in events)
    if behavior != "duplicate":
        assert any(e["event"] == "upstream_response_missing" and e["id"] == 2 for e in events)


@pytest.mark.parametrize("frame", [b'[]\n', b'{bad\n', b'null\n',
    b'{"jsonrpc":"2.0","id":2,"id":3,"method":"initialize"}\n'])
def test_probe_rejects_malformed_input_before_forwarding(tmp_path, frame):
    process, log = start_probe_fixture(tmp_path)
    process.communicate(frame, timeout=10)
    assert process.returncode != 0
    events = [json.loads(line) for line in log.read_text().splitlines()]
    assert not any(e["event"] in ("upstream_probe_ready", "upstream_stdin_forwarded") for e in events)


def test_probe_rejects_duplicate_request_ids(tmp_path):
    process, log = start_probe_fixture(tmp_path)
    initialize_probe(process)
    frame = b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_text_file"}}\n'
    process.communicate(frame + frame, timeout=10)
    assert process.returncode != 0
    assert "Duplicate request ID" in log.read_text()


def test_unsuccessful_initialize_never_marks_probe_ready(tmp_path):
    process, log = start_probe_fixture(tmp_path, "bad_init")
    process.communicate(b'{"jsonrpc":"2.0","id":1,"method":"initialize"}\n', timeout=10)
    assert process.returncode != 0
    assert '"event": "upstream_probe_ready"' not in log.read_text()


@pytest.mark.parametrize("result", [
    None, [], {},
    {**VALID_INITIALIZE, "protocolVersion": None},
    {**VALID_INITIALIZE, "protocolVersion": 20251125},
    {**VALID_INITIALIZE, "protocolVersion": "2025-06-18"},
    {**VALID_INITIALIZE, "capabilities": []},
    {**VALID_INITIALIZE, "capabilities": None},
    {**VALID_INITIALIZE, "serverInfo": None},
    {**VALID_INITIALIZE, "serverInfo": {}},
    {**VALID_INITIALIZE, "serverInfo": {"name": 1, "version": "1"}},
    {**VALID_INITIALIZE, "serverInfo": {"name": "fixture", "version": 1}},
    {**VALID_INITIALIZE, "serverInfo": {"name": " ", "version": "1"}},
    {**VALID_INITIALIZE, "serverInfo": {"name": "fixture", "version": ""}},
    {k: v for k, v in VALID_INITIALIZE.items() if k != "capabilities"},
    {k: v for k, v in VALID_INITIALIZE.items() if k != "protocolVersion"},
    {k: v for k, v in VALID_INITIALIZE.items() if k != "serverInfo"},
])
def test_malformed_initialize_shape_never_marks_ready(tmp_path, result):
    process, log = start_probe_fixture(tmp_path, initialize_result=result)
    process.communicate(b'{"jsonrpc":"2.0","id":1,"method":"initialize"}\n', timeout=10)
    assert process.returncode != 0
    events = [json.loads(line) for line in log.read_text().splitlines()]
    assert not any(e["event"] == "upstream_probe_ready" for e in events)
    assert any(e["event"] == "upstream_probe_failure" for e in events)


def test_initialize_optional_fields_are_not_required(tmp_path):
    process, log = start_probe_fixture(tmp_path)
    process.communicate(b'{"jsonrpc":"2.0","id":1,"method":"initialize"}\n', timeout=10)
    assert process.returncode == 0
    events = [json.loads(line) for line in log.read_text().splitlines()]
    assert sum(e["event"] == "upstream_probe_ready" for e in events) == 1


@pytest.mark.parametrize("role", ["probe", "relay"])
def test_stalled_child_stdin_write_has_bounded_failure(tmp_path, role):
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    child = tmp_path / "never_drains.py"
    child.write_text("import json, sys, time\n"
                     "request = json.loads(sys.stdin.buffer.readline())\n"
                     f"print(json.dumps({{'jsonrpc':'2.0','id':request['id'],'result':{VALID_INITIALIZE!r}}}), flush=True)\n"
                     "time.sleep(60)\n", encoding="utf-8")
    log = tmp_path / "events"
    invocation = (f"import sys; sys.path.insert(0, {str(scripts)!r}); "
                  "from filesystem_probe import run_transport; "
                  f"sys.exit(run_transport({str(log)!r}, [sys.executable, {str(child)!r}], role={role!r}, timeout=.5))")
    process = subprocess.Popen([sys.executable, "-c", invocation], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    initialize_probe(process)
    frame = (json.dumps({"jsonrpc":"2.0", "id":2, "method":"tools/call",
                         "params":{"name":"write_file", "arguments":{"content":"x" * (2 * 1024 * 1024)}}}) + "\n").encode()
    started = time.monotonic()
    process.communicate(frame, timeout=8)
    assert process.returncode != 0
    assert time.monotonic() - started < 5
    events = [json.loads(line) for line in log.read_text().splitlines()]
    assert any("Child stdin write timeout" in e.get("reason", "") for e in events)
    assert not any(e["event"] == "upstream_stdin_forwarded" and e["id"] == 2 for e in events)
    if role == "probe":
        assert any(e["event"] == "upstream_response_missing" and e["id"] == 2 for e in events)


def test_probe_child_launch_failure_is_fatal(tmp_path):
    probe = Path(__file__).resolve().parents[1] / "scripts/filesystem_probe.py"
    log = tmp_path / "events"
    result = subprocess.run([sys.executable, str(probe), str(log), str(tmp_path / "absent.exe")],
                            input=b"", capture_output=True, timeout=10)
    assert result.returncode != 0
    assert '"event": "upstream_probe_failure"' in log.read_text()
    assert '"event": "upstream_probe_ready"' not in log.read_text()


@pytest.mark.parametrize("role", ["probe", "relay"])
def test_client_not_consuming_stdout_fails_and_reaps_child(tmp_path, role):
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    child = tmp_path / "large_reply.py"
    pid_file = tmp_path / "child.pid"
    child.write_text("import json, os, sys, time\n"
        f"with open({str(pid_file)!r}, 'w') as f: f.write(str(os.getpid()))\n"
        "request=json.loads(sys.stdin.buffer.readline())\n"
        f"print(json.dumps({{'jsonrpc':'2.0','id':request['id'],'result':{VALID_INITIALIZE!r}}}), flush=True)\n"
        "request=json.loads(sys.stdin.buffer.readline())\n"
        "print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':{'content':'x'*(2*1024*1024)}}), flush=True)\n"
        "time.sleep(60)\n", encoding="utf-8")
    log = tmp_path / "events"
    invocation = (f"import sys; sys.path.insert(0, {str(scripts)!r}); "
        "from filesystem_probe import run_transport; "
        f"sys.exit(run_transport({str(log)!r}, [sys.executable, {str(child)!r}], role={role!r}, timeout=.8))")
    process = subprocess.Popen([sys.executable, "-c", invocation], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        initialize_probe(process)
        process.stdin.write(b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_text_file"}}\n')
        process.stdin.flush()
        started = time.monotonic()
        # Do not drain stdout, even while waiting for failure. communicate() here
        # would hide the backpressure that this regression must exercise.
        process.wait(timeout=14)
        assert process.returncode != 0
        # .8s I/O deadline, up to 10s terminate/kill waits, 1s worker
        # cleanup, plus a small scheduling allowance on Windows.
        assert time.monotonic() - started < 14
        events = [json.loads(line) for line in log.read_text().splitlines()]
        assert any("Client stdout write timeout" in e.get("reason", "") for e in events)
        assert not any(e["event"] == "upstream_response_missing" and e["id"] == 2 for e in events)
        if sys.platform == "win32":
            import ctypes
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.OpenProcess.restype = ctypes.c_void_p
            kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
            kernel.CloseHandle.argtypes = [ctypes.c_void_p]
            handle = kernel.OpenProcess(0x100000, False, int(pid_file.read_text()))
            if handle:
                try:
                    assert kernel.WaitForSingleObject(handle, 0) == 0, "Child is still running"
                finally:
                    kernel.CloseHandle(handle)
            else:
                assert ctypes.get_last_error() == 87, "Cannot establish child termination"
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)


def test_probe_frame_limit_rejects_oversized_input(tmp_path):
    process, log = start_probe_fixture(tmp_path)
    process.communicate(b" " * (4 * 1024 * 1024 + 1) + b"\n", timeout=8)
    assert process.returncode != 0
    assert '"event": "upstream_probe_ready"' not in log.read_text()
    assert "frame limit" in log.read_text()


def test_late_writer_does_not_continue_with_remaining_bytes(monkeypatch):
    path = Path(__file__).resolve().parents[1] / "scripts/filesystem_probe.py"
    spec = importlib.util.spec_from_file_location("late_writer_probe", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    entered, release = threading.Event(), threading.Event()
    calls = []

    def stalled_write(descriptor, data):
        calls.append(bytes(data))
        entered.set()
        release.wait(timeout=3)
        return 1

    monkeypatch.setattr(module.os, "write", stalled_write)
    monkeypatch.setattr(module.os, "dup", lambda descriptor: descriptor)
    monkeypatch.setattr(module.os, "close", lambda descriptor: None)
    writers = []
    try:
        with pytest.raises(TimeoutError):
            module.write_child_frame(SimpleNamespace(fileno=lambda: 123), b"original bytes", time.monotonic() + .15, writers)
        assert entered.is_set()
    finally:
        release.set()
        for writer in writers:
            writer.join(timeout=2)
    assert len(calls) == 1
    assert all(not writer.is_alive() for writer in writers)


def test_probe_timeout_records_missing_initialize_response(tmp_path):
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    log = tmp_path / "events"
    invocation = (f"import sys; sys.path.insert(0, {str(scripts)!r}); "
                  "from filesystem_probe import run_transport; "
                  f"sys.exit(run_transport({str(log)!r}, [sys.executable, '-c', 'import time; time.sleep(10)'], timeout=.2))")
    result = subprocess.run([sys.executable, "-c", invocation],
                            input=b'{"jsonrpc":"2.0","id":1,"method":"initialize"}\n',
                            capture_output=True, timeout=5)
    assert result.returncode != 0
    events = [json.loads(line) for line in log.read_text().splitlines()]
    assert any(e["event"] == "upstream_response_missing" and e["id"] == 1 for e in events)
    assert not any(e["event"] == "upstream_probe_ready" for e in events)


def test_runner_rejects_blocked_id_observed_at_probe():
    module = load_example()
    events = [{"event":"upstream_probe_ready", "id":1}] + [
        {"event":name, "id":identity} for identity in (2, 4)
        for name in ("relay_received", "upstream_process_ingress_received",
                     "upstream_stdin_forwarded", "upstream_response_received")]
    events.append({"event":"upstream_process_ingress_received", "id":3})
    with pytest.raises(RuntimeError):
        module.verify_probe_events(events, [2, 4], "guarded")


def test_probe_preserves_original_request_bytes(tmp_path):
    child = tmp_path / "capture.py"
    capture = tmp_path / "wire.bin"
    child.write_text("import json, sys\n" + f"capture = {str(capture)!r}\n" +
        "for line in sys.stdin.buffer:\n"
        " with open(capture, 'ab') as f: f.write(line)\n"
        " m=json.loads(line)\n"
        f" result = {VALID_INITIALIZE!r} if m['method'] == 'initialize' else {{}}\n"
        " print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':result}), flush=True)\n", encoding="utf-8")
    probe = Path(__file__).resolve().parents[1] / "scripts/filesystem_probe.py"
    process = subprocess.Popen([sys.executable, str(probe), str(tmp_path / "events"), sys.executable, str(child)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    initialize_probe(process)
    frame = b'  {"jsonrpc": "2.0", "id":2, "method":"tools/call", "params":{"name":"write_file", "arguments":{"content":"a  b"}}}  \r\n'
    process.communicate(frame, timeout=10)
    assert process.returncode == 0
    assert capture.read_bytes().endswith(frame)


def test_child_frame_short_writes_preserve_every_byte(monkeypatch):
    path = Path(__file__).resolve().parents[1] / "scripts/filesystem_probe.py"
    spec = importlib.util.spec_from_file_location("short_write_probe", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    written = bytearray()

    def short_write(descriptor, data):
        assert descriptor == 123
        count = min(3, len(data))
        written.extend(data[:count])
        return count

    monkeypatch.setattr(module.os, "write", short_write)
    monkeypatch.setattr(module.os, "dup", lambda descriptor: descriptor)
    monkeypatch.setattr(module.os, "close", lambda descriptor: None)
    original = b'  {"payload":"a  b\\n"}  \r\n'
    workers = []
    module.write_child_frame(SimpleNamespace(fileno=lambda: 123), original, time.monotonic() + 2, workers)
    assert bytes(written) == original
    for worker in workers:
        worker.join(timeout=1)
        assert not worker.is_alive()


@pytest.mark.parametrize("event_name", ["upstream_probe_ready", "upstream_process_ingress_received",
    "upstream_stdin_forwarded", "upstream_response_received"])
def test_runner_rejects_missing_and_duplicate_probe_evidence(event_name):
    module = load_example()
    events = [{"event":"upstream_probe_ready", "id":1}] + [
        {"event":name, "id":2} for name in ("relay_received", "upstream_process_ingress_received",
                                           "upstream_stdin_forwarded", "upstream_response_received")]
    module.verify_probe_events(events, [2], "guarded")
    missing = [e for e in events if e["event"] != event_name]
    with pytest.raises(RuntimeError):
        module.verify_probe_events(missing, [2], "guarded")
    with pytest.raises(RuntimeError):
        module.verify_probe_events(events + [next(e for e in events if e["event"] == event_name)], [2], "guarded")


def load_example():
    path = Path(__file__).resolve().parents[1] / "scripts/filesystem_walkthrough.py"
    spec = importlib.util.spec_from_file_location("filesystem_walkthrough", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_missing_entry_fails_before_starting_process(monkeypatch, tmp_path):
    module = load_example()
    monkeypatch.setattr(module.sys, "argv", ["walkthrough", "--server-entry", str(tmp_path / "absent.js")])
    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **k: pytest.fail("Process started"))
    with pytest.raises(SystemExit) as error:
        module.main()
    assert error.value.code == 2


def test_windows_timeout_targets_only_owned_tree(monkeypatch):
    module = load_example()
    monkeypatch.setattr(module.sys, "platform", "win32")
    calls = []
    waits = iter([False, True])

    def wait(timeout):
        if not next(waits):
            raise subprocess.TimeoutExpired("fixture", timeout)

    process = SimpleNamespace(pid=123456, wait=wait, poll=lambda: None,
                              terminate=lambda: pytest.fail("Unexpected fallback"))
    monkeypatch.setattr(module.subprocess, "run", lambda command, **kwargs:
                        calls.append(command) or SimpleNamespace(returncode=0))
    module.stop_owned_process(process)
    assert calls == [["taskkill", "/PID", "123456", "/T", "/F"]]


def test_windows_timeout_skips_taskkill_if_owned_process_has_exited(monkeypatch):
    module = load_example()
    monkeypatch.setattr(module.sys, "platform", "win32")
    wait_calls = []

    def wait(timeout):
        wait_calls.append(timeout)
        if len(wait_calls) == 1:
            raise subprocess.TimeoutExpired("fixture", timeout)
        return 0

    process = SimpleNamespace(pid=123456, wait=wait, poll=lambda: 0,
                              terminate=lambda: pytest.fail("Unexpected terminate"))
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: pytest.fail("Stale PID targeted"))

    module.stop_owned_process(process)

    assert wait_calls == [10, 10]


def test_relay_redacts_content_but_preserves_wire_request(tmp_path):
    upstream = tmp_path / "fixture_server.py"
    handler_log = tmp_path / "handler.jsonl"
    upstream.write_text(
        "import json, sys\n"
        f"handler_log = {str(handler_log)!r}\n"
        "for line in sys.stdin:\n"
        " message = json.loads(line)\n"
        " if message.get('method') == 'tools/call':\n"
        "  with open(handler_log, 'a', encoding='utf-8') as stream:\n"
        "   stream.write(json.dumps({'id': message.get('id'), 'name': message['params']['name']}) + '\\n')\n"
        f" result = {VALID_INITIALIZE!r} if message['method'] == 'initialize' else {{'content':[{{'type':'text','text':'ok'}}]}}\n"
        " response = {'jsonrpc': '2.0', 'id': message.get('id'), 'result': result}\n"
        " print(json.dumps(response), flush=True)\n",
        encoding="utf-8",
    )
    log = tmp_path / "reachability.jsonl"
    relay = Path(__file__).resolve().parents[1] / "scripts/filesystem_relay.py"
    request = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
        "name": "write_file", "arguments": {"path": "synthetic.txt", "content": "secret-marker"}}}
    process = subprocess.Popen([sys.executable, str(relay), str(log), sys.executable, str(upstream)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    init = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
    process.stdin.write(init)
    process.stdin.flush()
    assert json.loads(read_frame(process))["id"] == 1
    result, errors = process.communicate((json.dumps(request) + "\n").encode(), timeout=15)
    assert process.returncode == 0, errors
    response = json.loads(result)
    assert response["id"] == 2
    assert response["result"]["content"][0]["text"] == "ok"
    events = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert [event["event"] for event in events] == ["upstream_probe_ready", "relay_received",
        "upstream_process_ingress_received", "upstream_stdin_forwarded", "upstream_response_received"]
    assert events[1]["arguments"]["path"] == "synthetic.txt"
    assert events[1]["arguments"]["content"] == "[redacted]"
    assert events[-1]["jsonrpc_error"] is False
    assert [json.loads(line) for line in handler_log.read_text(encoding="utf-8").splitlines()] == [
        {"id": 2, "name": "write_file"}
    ]
    assert "secret-marker" not in log.read_text(encoding="utf-8")


def test_guarded_audit_events_bind_each_expected_call_and_boundary(tmp_path):
    module = load_example()
    audit_log = tmp_path / "audit.jsonl"
    events = [
        {"method": "tools/call", "tool_name": "read_text_file", "effective_policy_action": "ALLOW",
         "policy_explanation": {"upstream_called": True}},
        {"method": "tools/call", "tool_name": "read_text_file", "effective_policy_action": "BLOCK",
         "policy_explanation": {"upstream_called": False}},
        {"method": "tools/call", "tool_name": "write_file", "effective_policy_action": "ALLOW",
         "policy_explanation": {"upstream_called": True}},
        {"method": "tools/call", "tool_name": "write_file", "effective_policy_action": "BLOCK",
         "policy_explanation": {"upstream_called": False}},
    ]
    audit_log.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")

    mapped = module.verify_guarded_policy_events(audit_log)

    assert [(item["call_id"], item["decision"], item["upstream_called"]) for item in mapped] == [
        (2, "ALLOW", True), (3, "BLOCK", False), (4, "ALLOW", True), (5, "BLOCK", False)
    ]
    with pytest.raises(RuntimeError, match="Gateway audit mismatch"):
        events[1]["effective_policy_action"] = "ALLOW"
        audit_log.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
        module.verify_guarded_policy_events(audit_log)


def test_fixture_environment_does_not_inherit_credentials_or_runtime_overrides(monkeypatch, tmp_path):
    module = load_example()
    monkeypatch.setenv("OPENAI_API_KEY", "fixture-secret")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "fixture-secret")
    monkeypatch.setenv("PYTHONPATH", "attacker-module-path")
    monkeypatch.setenv("NODE_OPTIONS", "--require attacker-module")

    environment = module.fixture_environment(tmp_path)

    assert "OPENAI_API_KEY" not in environment
    assert "AWS_ACCESS_KEY_ID" not in environment
    assert "PYTHONPATH" not in environment
    assert "NODE_OPTIONS" not in environment
    assert environment["TEMP"] == str(tmp_path)
    assert environment["TMP"] == str(tmp_path)
    assert str(Path(module.sys.executable).parent) in environment["PATH"]


def test_text_content_returns_only_text_blocks():
    module = load_example()

    assert module.text_content({"result": {"content": [
        {"type": "text", "text": "fixture"},
        {"type": "image", "data": "ignored"},
        {"type": "text", "text": 123},
    ]}}) == ["fixture"]
    assert module.text_content({"error": {"message": "blocked"}}) == []


def test_guarded_relay_evidence_excludes_blocked_call_ids():
    module = load_example()
    events = [
        {"event": "relay_received", "id": 2},
        {"event": "upstream_response_received", "id": 2},
        {"event": "relay_received", "id": 4},
        {"event": "upstream_response_received", "id": 4},
    ]

    module.assert_event_ids(events, "relay_received", [2, 4], "guarded")
    module.assert_event_ids(events, "upstream_response_received", [2, 4], "guarded")
    with pytest.raises(RuntimeError, match="expected \\[2, 3, 4\\]"):
        module.assert_event_ids(events, "relay_received", [2, 3, 4], "guarded")


def test_upstream_response_evidence_checks_protocol_and_tool_results():
    module = load_example()
    events = [
        {"event": "upstream_response_received", "id": 2,
         "jsonrpc_error": False, "tool_is_error": False},
        {"event": "upstream_response_received", "id": 3,
         "jsonrpc_error": False, "tool_is_error": True},
    ]

    module.verify_upstream_responses(events, [2, 3], tool_error_ids=[3])

    events[0]["jsonrpc_error"] = True
    with pytest.raises(RuntimeError, match="JSON-RPC error"):
        module.verify_upstream_responses(events, [2, 3], tool_error_ids=[3])

    events[0]["jsonrpc_error"] = False
    events[1]["tool_is_error"] = False
    with pytest.raises(RuntimeError, match="tool error state"):
        module.verify_upstream_responses(events, [2, 3], tool_error_ids=[3])


def test_ruleset_digest_changes_when_policy_content_changes(tmp_path):
    module = load_example()
    rules = tmp_path / "rules"
    rules.mkdir()
    policy = rules / "safe_zones.yaml"
    policy.write_text("- tool: read_text_file\n", encoding="utf-8")
    first = module.directory_sha256(rules)
    assert module.directory_sha256(rules) == first

    policy.write_text("- tool: write_file\n", encoding="utf-8")
    assert module.directory_sha256(rules) != first


def test_wrong_server_version_fails_before_starting_process(monkeypatch, tmp_path):
    module = load_example()
    dist = tmp_path / "dist"
    dist.mkdir()
    entry = dist / "index.js"
    entry.write_text("", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        '{"name":"@modelcontextprotocol/server-filesystem","version":"0.0.0"}', encoding="utf-8")
    monkeypatch.setattr(module, "node", "node")
    monkeypatch.setattr(module.sys, "argv", ["walkthrough", "--server-entry", str(entry)])
    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **k: pytest.fail("Process started"))
    with pytest.raises(SystemExit) as error:
        module.main()
    assert error.value.code == 2


@pytest.mark.parametrize(
    ("os_name", "python_version", "python_implementation", "node_version", "message"),
    [
        ("Linux", "3.12.14", "CPython", "v24.22.1", "Windows only"),
        ("Windows", "3.13.0", "CPython", "v24.22.1", "Python 3.12.14"),
        ("Windows", "3.12.14", "PyPy", "v24.22.1", "CPython only"),
        ("Windows", "3.12.14", "CPython", "v22.21.1", "Node v24.22.1"),
    ],
)
def test_unverified_environment_is_rejected(monkeypatch, os_name, python_version,
                                            python_implementation, node_version, message):
    module = load_example()
    monkeypatch.setattr(module.platform, "system", lambda: os_name)
    monkeypatch.setattr(module.platform, "python_version", lambda: python_version)
    monkeypatch.setattr(module.platform, "python_implementation", lambda: python_implementation)
    monkeypatch.setattr(module, "node", "node")
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs:
                        SimpleNamespace(stdout=node_version))

    with pytest.raises(RuntimeError, match=message):
        module.validate_environment()


def test_python_lock_checks_every_locked_distribution(monkeypatch, tmp_path):
    module = load_example()
    lock = tmp_path / "requirements.lock"
    lock.write_text(
        "mcp-vanguard==2.2.2\n"
        "anyio==4.15.1\n",
        encoding="utf-8",
    )
    installed = {"mcp-vanguard": "2.2.2", "anyio": "4.15.1"}
    monkeypatch.setattr(module.importlib.metadata, "version", lambda name: installed[name])

    identity = module.python_lock_identity(lock)

    assert identity["package_count"] == 2
    assert identity["sha256"] == module.sha256_file(lock)
    installed["anyio"] = "4.15.2"
    with pytest.raises(RuntimeError, match="Python lock mismatch for anyio"):
        module.python_lock_identity(lock)


def test_npm_lock_requires_exact_upstream_dependency(tmp_path):
    module = load_example()
    manifest = tmp_path / "package.json"
    lock = tmp_path / "package-lock.json"
    manifest.write_text(json.dumps({"dependencies": {
        "@modelcontextprotocol/server-filesystem": "2.1.0"}}), encoding="utf-8")
    lock.write_text(json.dumps({"packages": {
        "": {},
        "node_modules/@modelcontextprotocol/server-filesystem": {"version": "2.1.0"},
    }}), encoding="utf-8")

    identity = module.npm_lock_identity(lock)
    assert identity["locked_package_count"] == 2
    assert identity["lock_sha256"] == module.sha256_file(lock)

    lock.write_text(json.dumps({"packages": {
        "node_modules/@modelcontextprotocol/server-filesystem": {"version": "2.0.1"},
    }}), encoding="utf-8")
    with pytest.raises(RuntimeError, match="npm lock must contain"):
        module.npm_lock_identity(lock)


def test_runner_report_distinguishes_repository_head_from_untracked_kit(monkeypatch):
    module = load_example()

    def fake_git(command, **kwargs):
        if command[:3] == ["git", "rev-parse", "HEAD"]:
            return SimpleNamespace(returncode=0, stdout="commit-id\n", stderr="")
        if command[:3] == ["git", "ls-files", "--error-unmatch"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="error: pathspec did not match")
        pytest.fail(f"Unexpected Git command: {command}")

    monkeypatch.setattr(module.subprocess, "run", fake_git)

    identity = module.runner_identity()

    assert identity["repository_head"] == "commit-id"
    assert "source_commit" not in identity
    assert identity["kit_file_tracking"]
    assert set(identity["kit_file_tracking"].values()) == {"untracked"}
    assert set(identity["kit_file_sha256"]) == set(identity["kit_file_tracking"])
    assert all(len(digest) == 64 for digest in identity["kit_file_sha256"].values())
    assert identity["kit_file_sha256"]["scripts/filesystem_walkthrough.py"] == identity["script_sha256"]


def test_runner_report_marks_indexed_kit_files_as_tracked(monkeypatch):
    module = load_example()

    def fake_git(command, **kwargs):
        if command[:3] == ["git", "rev-parse", "HEAD"]:
            return SimpleNamespace(returncode=0, stdout="commit-id\n", stderr="")
        if command[:3] == ["git", "ls-files", "--error-unmatch"]:
            return SimpleNamespace(returncode=0, stdout=command[-1] + "\n", stderr="")
        pytest.fail(f"Unexpected Git command: {command}")

    monkeypatch.setattr(module.subprocess, "run", fake_git)

    identity = module.runner_identity()

    assert set(identity["kit_file_tracking"].values()) == {"tracked"}
