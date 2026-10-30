"""Observe stdio outside the unchanged official filesystem server handler."""
import argparse
import json
import os
import queue
import subprocess
import sys
import threading
import time

MAX_FRAME_BYTES = 4 * 1024 * 1024
MAX_QUEUED_FRAMES = 8
MAX_REQUESTS = 64


def parse_object(line):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON member")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError("Invalid JSON constant")

    message = json.loads(line, object_pairs_hook=unique_pairs, parse_constant=invalid_constant)
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        raise ValueError("Expected a JSON-RPC object")
    return message


def request_key(value):
    if type(value) not in (int, str):
        raise ValueError("Request ID must be an integer or string")
    return (type(value).__name__, value)


def write_event(log, event):
    data = (json.dumps(event, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        if os.write(descriptor, data) != len(data):
            raise OSError("Incomplete evidence write")
    finally:
        os.close(descriptor)


def validate_initialize_result(result):
    """Validate required InitializeResult fields for this kit's supported protocol."""
    if not isinstance(result, dict):
        raise ValueError("Initialize result must be an object")
    if result.get("protocolVersion") != "2025-11-25":
        raise ValueError("Unsupported initialize protocolVersion")
    if not isinstance(result.get("capabilities"), dict):
        raise ValueError("Initialize capabilities must be an object")
    info = result.get("serverInfo")
    if not isinstance(info, dict):
        raise ValueError("Initialize serverInfo must be an object")
    for field in ("name", "version"):
        if not isinstance(info.get(field), str) or not info[field].strip():
            raise ValueError(f"Initialize serverInfo.{field} must be a non-empty string")


def write_child_frame(stream, frame, deadline, writers, label="Child stdin"):
    """Keep blocked OS pipe writes off the thread enforcing the deadline."""
    writers[:] = [writer for writer in writers if writer.is_alive()]
    descriptor = os.dup(stream.fileno())
    finished = threading.Event()
    cancelled = threading.Event()
    errors = []

    def write():
        try:
            remaining = memoryview(frame)
            while remaining:
                if cancelled.is_set() or time.monotonic() >= deadline:
                    raise TimeoutError(f"{label} write deadline expired")
                count = os.write(descriptor, remaining)
                if count <= 0:
                    raise OSError("Incomplete child stdin write")
                remaining = remaining[count:]
        except Exception as exc:
            errors.append(exc)
        finally:
            os.close(descriptor)
            finished.set()

    writer = threading.Thread(target=write, daemon=True)
    writers.append(writer)
    writer.start()
    if not finished.wait(max(0, deadline - time.monotonic())):
        cancelled.set()
        raise TimeoutError(f"{label} write timeout")
    if errors:
        raise errors[0]
    # os.write bypasses Python buffering; completion means the entire original
    # frame entered the pipe. No buffered flush may block the deadline thread.


def run_transport(log, command, role="probe", timeout=30.0):
    """Forward original frames; reject uncorrelated or incomplete exchanges."""
    pending, seen = {}, set()
    child = None
    initialized = input_closed = output_closed = False
    shutdown_deadline = None
    messages = queue.Queue(maxsize=MAX_QUEUED_FRAMES)
    writers = []
    stopped = threading.Event()
    reader_failed = threading.Event()
    readers = []
    last_activity = time.monotonic()

    def enqueue(item):
        if stopped.is_set():
            return False
        try:
            messages.put(item, timeout=min(timeout, 0.1))
            return True
        except queue.Full:
            reader_failed.set()
            return False

    def reader(stream, direction):
        try:
            while not stopped.is_set():
                line = stream.readline(MAX_FRAME_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_FRAME_BYTES or not line.endswith(b"\n"):
                    reader_failed.set()
                    return
                if not enqueue((direction, line)):
                    return
        except Exception:
            reader_failed.set()
        finally:
            enqueue((direction, None))

    try:
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr)
        for stream, direction in ((sys.stdin.buffer, "input"), (child.stdout, "output")):
            thread = threading.Thread(target=reader, args=(stream, direction), daemon=True)
            readers.append(thread)
            thread.start()
        while True:
            now = time.monotonic()
            if reader_failed.is_set():
                raise RuntimeError("Reader failed, frame limit exceeded, or frame queue full")
            if now - last_activity > timeout:
                raise RuntimeError("Transport idle timeout")
            if any(now - item["started"] > timeout for item in pending.values()):
                raise RuntimeError("Response timeout")
            if shutdown_deadline is not None and now > shutdown_deadline:
                raise RuntimeError("Child shutdown timeout")
            if output_closed:
                if pending:
                    raise RuntimeError("Child closed stdout with missing responses")
                if not input_closed:
                    raise RuntimeError("Child closed stdout before input shutdown")
                status = child.poll()
                if status is not None:
                    if status != 0:
                        raise RuntimeError("Child exited unsuccessfully")
                    if not initialized:
                        raise RuntimeError("No successful initialize response")
                    return 0
            try:
                direction, line = messages.get(timeout=0.05)
            except queue.Empty:
                continue
            last_activity = time.monotonic()
            if direction == "reader_failure":
                raise RuntimeError("Transport reader failed")
            if line is None:
                if direction == "input":
                    input_closed = True
                    shutdown_deadline = time.monotonic() + timeout
                    child.stdin.close()
                else:
                    output_closed = True
                continue
            message = parse_object(line)
            if direction == "input":
                method = message.get("method")
                if not isinstance(method, str) or "result" in message or "error" in message:
                    raise ValueError("Expected request or notification")
                params = message.get("params", {})
                if not isinstance(params, dict):
                    raise ValueError("Request params must be an object")
                if method == "initialize" and (initialized or any(p["method"] == method for p in pending.values())):
                    raise ValueError("Duplicate initialize request")
                if method != "initialize" and not initialized:
                    raise ValueError("Request before successful initialization")
                if method in ("initialize", "tools/call") and "id" not in message:
                    raise ValueError("Request ID is required")
                if "id" in message:
                    key = request_key(message["id"])
                    if key in seen:
                        raise ValueError("Duplicate request ID")
                    if len(seen) >= MAX_REQUESTS:
                        raise ValueError("Fixture request limit exceeded")
                    seen.add(key)
                    pending[key] = {"id": message["id"], "method": method,
                                    "name": params.get("name"), "started": time.monotonic()}
                if method == "tools/call":
                    arguments = params.get("arguments", {})
                    if not isinstance(params.get("name"), str) or not isinstance(arguments, dict):
                        raise ValueError("Malformed tool call")
                    event = {"event": "relay_received" if role == "relay" else "upstream_process_ingress_received",
                             "id": message["id"], "name": params["name"]}
                    if role == "relay":
                        event["arguments"] = {k: v if k in ("path", "source", "destination") else "[redacted]"
                                              for k, v in arguments.items()}
                    write_event(log, event)
                deadline = time.monotonic() + timeout
                if pending:
                    deadline = min(deadline, min(p["started"] + timeout for p in pending.values()))
                write_child_frame(child.stdin, line, deadline, writers)
                if method == "tools/call" and role == "probe":
                    write_event(log, {"event": "upstream_stdin_forwarded", "id": message["id"],
                                      "name": params["name"]})
            else:
                if "method" in message or "id" not in message or ("result" in message) == ("error" in message):
                    raise ValueError("Malformed response")
                key = request_key(message["id"])
                request = pending.get(key)
                if request is None:
                    raise ValueError("Duplicate or unexpected response ID")
                result = message.get("result")
                if request["method"] == "initialize":
                    if "error" in message:
                        raise ValueError("Initialize did not succeed")
                    validate_initialize_result(result)
                    initialized = True
                    if role == "probe":
                        write_event(log, {"event": "upstream_probe_ready", "id": request["id"]})
                if request["method"] == "tools/call" and role == "probe":
                    write_event(log, {"event": "upstream_response_received", "id": request["id"],
                                      "name": request["name"], "jsonrpc_error": "error" in message,
                                      "tool_is_error": bool(result.get("isError", False))
                                      if isinstance(result, dict) else None})
                request["response_received"] = True
                write_child_frame(sys.stdout.buffer, line, request["started"] + timeout,
                                  writers, label="Client stdout")
                pending.pop(key)
    except Exception as exc:
        write_event(log, {"event": "upstream_probe_failure" if role == "probe" else "relay_failure",
                          "reason": type(exc).__name__ + ": " + str(exc)})
        for request in pending.values():
            if role == "probe" and not request.get("response_received", False):
                write_event(log, {"event": "upstream_response_missing", "id": request["id"],
                                  "name": request["name"]})
        return 1
    finally:
        stopped.set()
        if child is not None:
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
            cleanup_deadline = time.monotonic() + 1
            for worker in writers + readers:
                worker.join(timeout=max(0, cleanup_deadline - time.monotonic()))
            child.stdin.close()
            # A descendant may retain stdout. Never wait for a buffered-reader
            # lock held by a blocked daemon; process exit releases its handles.
            if len(readers) > 1 and not readers[1].is_alive():
                child.stdout.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.command:
        parser.error("An upstream command is required")
    return run_transport(args.log, args.command)


if __name__ == "__main__":
    sys.exit(main())
