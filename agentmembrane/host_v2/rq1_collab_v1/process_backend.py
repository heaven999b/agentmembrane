"""Trusted native-service RPC over inherited pipes, with a private scorer process.

Process separation is useful for interface testing; SAME-UID separation is NOT
hostile-code isolation. This module deliberately reports that limitation. Actors
are never allowed to provide worker source paths, method names, or scorer input.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import queue
import selectors
import subprocess
import sys
import threading
import time

MAX_FRAME = 8_000_000


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result: raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _loads(raw):
    def finite(value):
        number=float(value)
        if not math.isfinite(number): raise ValueError("nonfinite_json")
        return number
    return json.loads(raw, object_pairs_hook=_pairs,
        parse_float=finite,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite_json")))


def _encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False,
                      separators=(",", ":")).encode() + b"\n"


class NativeProcessFailure(RuntimeError):
    def __init__(self, code, *, commit_unknown=False):
        super().__init__(code)
        self.code, self.commit_unknown = code, commit_unknown


class PipeWorker:
    """Controller-owned process. Private pipes bind a session, not model JSON IDs."""
    def __init__(self, python: str, *, mode: str, source_root: str | None = None,
                 suite: str = "workspace", task_id: str = "user_task_8",
                 benchmark_version: str = "v1", timeout: float = 45):
        if mode not in {"native", "evaluator", "probe"}:
            raise ValueError("unknown_worker_mode")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("worker_timeout_must_be_positive_finite")
        self.timeout, self.seq, self.mode = timeout, 0, mode
        self.closed = False
        self.poisoned = False
        self._request_lock = threading.Lock()
        command = [python, "-I", "-S", str(Path(__file__).resolve()), "--worker", mode,
                   "--suite", suite, "--task-id", task_id, "--benchmark-version", benchmark_version]
        venv_lib = Path(python).absolute().parent.parent / "lib"
        # Explicit dependency tree, no execution of unrelated .pth/plugin code.
        if venv_lib.is_dir():
            candidates = sorted(venv_lib.glob("python*/site-packages"))
            if len(candidates) == 1: command.extend(["--dependency-site", str(candidates[0])])
        if source_root: command.extend(["--source-root", source_root])
        # No inherited API keys, user config, user PYTHONPATH, or HOME.
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0, close_fds=True,
            env={"PATH":"/usr/bin:/bin", "PYDANTIC_DISABLE_PLUGINS":"__all__", "PYTHONUNBUFFERED":"1"})
        # A blocking file.write can wait forever before _receive sees a timeout.
        # This is a controller-owned POSIX pipe; there is no blocking fallback.
        try:
            os.set_blocking(self.process.stdin.fileno(), False)
        except (OSError, AttributeError):
            self.shutdown()
            raise NativeProcessFailure("native_nonblocking_transport_unavailable") from None
        self.inbox = queue.Queue()
        self.reader = threading.Thread(target=self._reader, daemon=True)
        self.reader.start()
        try:
            self.ready = self._receive(deadline=time.monotonic() + self.timeout,
                                       commit_unknown=False)
            if self.ready.get("kind") != "ready":
                raise NativeProcessFailure("native_worker_not_ready")
        except Exception:
            self.shutdown()
            raise

    def _reader(self):
        while True:
            raw = self.process.stdout.readline(MAX_FRAME + 1)
            self.inbox.put(raw)
            if not raw or len(raw) > MAX_FRAME: break

    def _receive(self, *, deadline=None, commit_unknown=True):
        deadline = time.monotonic() + self.timeout if deadline is None else deadline
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise NativeProcessFailure("native_worker_timeout", commit_unknown=commit_unknown)
        try: raw = self.inbox.get(timeout=remaining)
        except queue.Empty: raise NativeProcessFailure("native_worker_timeout", commit_unknown=commit_unknown) from None
        if not raw or len(raw) > MAX_FRAME or not raw.endswith(b"\n"):
            raise NativeProcessFailure("native_worker_invalid_frame", commit_unknown=commit_unknown)
        try: value = _loads(raw)
        except (ValueError, UnicodeError): raise NativeProcessFailure("native_worker_nonjson", commit_unknown=commit_unknown) from None
        if not isinstance(value, dict): raise NativeProcessFailure("native_worker_nonobject", commit_unknown=commit_unknown)
        return value

    def _send(self, frame: bytes, *, deadline: float) -> None:
        """Bound partial writes and readiness waits by the SAME request deadline."""
        descriptor = self.process.stdin.fileno()
        pending = memoryview(frame)
        with selectors.DefaultSelector() as selector:
            selector.register(descriptor, selectors.EVENT_WRITE)
            while pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise NativeProcessFailure("native_worker_send_timeout", commit_unknown=True)
                if not selector.select(remaining):
                    raise NativeProcessFailure("native_worker_send_timeout", commit_unknown=True)
                # Recheck after readiness: select may return as the deadline
                # expires, and a ready pipe does not imply the entire frame fits.
                if time.monotonic() >= deadline:
                    raise NativeProcessFailure("native_worker_send_timeout", commit_unknown=True)
                try:
                    written = os.write(descriptor, pending)
                except (BlockingIOError, InterruptedError):
                    continue
                if written <= 0:
                    raise NativeProcessFailure("native_worker_transport_error", commit_unknown=True)
                pending = pending[written:]

    def request(self, method: str, *, deadline_monotonic: float | None = None, **params):
        # One call occupies the framed stream. A second caller cannot race the
        # sequence or consume another call's response; waiting also has a bound.
        deadline = time.monotonic() + self.timeout
        if deadline_monotonic is not None:
            if type(deadline_monotonic) not in (int, float) or not math.isfinite(deadline_monotonic):
                raise ValueError("invalid_native_request_deadline")
            deadline = min(deadline, deadline_monotonic)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise NativeProcessFailure("native_worker_timeout_before_send")
        if not self._request_lock.acquire(timeout=remaining):
            raise NativeProcessFailure("native_worker_request_busy")
        try:
            return self._request(method, params, deadline=deadline)
        finally:
            self._request_lock.release()

    def _request(self, method: str, params: dict, *, deadline: float):
        if self.closed: raise NativeProcessFailure("native_worker_closed")
        if self.poisoned: raise NativeProcessFailure("native_worker_requires_explicit_recovery", commit_unknown=True)
        allowed = {"native":{"snapshot","call"}, "evaluator":{"score", "goal_record", "attack_score"}, "probe":{"probe"}}
        if method not in allowed[self.mode]: raise NativeProcessFailure("worker_method_not_exposed")
        next_seq = self.seq + 1
        frame = _encode({"seq":next_seq,"method":method,"params":params})
        if len(frame) > MAX_FRAME: raise NativeProcessFailure("native_request_too_large")
        if time.monotonic() >= deadline:
            raise NativeProcessFailure("native_worker_timeout_before_send")
        # Known-unsent encoding/frame errors above consume no worker sequence.
        self.seq = next_seq
        try:
            self._send(frame, deadline=deadline)
            reply = self._receive(deadline=deadline)
            if (type(reply.get("seq")) is not int or reply.get("seq") != self.seq
                    or type(reply.get("ok")) is not bool or set(reply) != {"seq","ok","value"}):
                raise NativeProcessFailure("native_worker_response_mismatch", commit_unknown=True)
            if not reply["ok"]: raise NativeProcessFailure("native_worker_failed", commit_unknown=method=="call")
            return reply["value"]
        except NativeProcessFailure as exc:
            if exc.commit_unknown:
                self.poisoned = True
            raise
        except (BrokenPipeError, OSError, ValueError):
            self.poisoned = True
            raise NativeProcessFailure("native_worker_transport_error", commit_unknown=True) from None

    def shutdown(self):
        if self.closed: return
        self.closed = True
        if self.process.stdin: self.process.stdin.close()
        try: self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try: self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        if self.process.stdout: self.process.stdout.close()

    def __enter__(self): return self
    def __exit__(self, *args): self.shutdown()


class ProcessNativeTask:
    """NativeTask-compatible trusted RPC client; checker runs in a NEW process."""
    def __init__(self, python: str, source_root: str, suite: str, task_id: str,
                 *, benchmark_version: str = "v1", timeout: float = 45):
        self.arguments = dict(python=python, source_root=source_root, suite=suite,
            task_id=task_id, benchmark_version=benchmark_version, timeout=timeout)
        self.worker = PipeWorker(mode="native", **self.arguments)
        self._trusted_calls = []
        self._score_cache = {}
        self._episode_deadline = None
        self._admission_closed = False
        self.prompt, self.record, self.tool_specs = (self.worker.ready[x] for x in ("prompt","record","tool_specs"))
        self.record = {**self.record, "execution_boundary":"trusted_pipe_process_same_uid_not_containment"}

    def begin_episode(self, *, deadline_monotonic: float):
        if self._episode_deadline is not None or self._admission_closed:
            raise ValueError("native_episode_already_bound_or_closed")
        if (type(deadline_monotonic) not in (int, float) or not math.isfinite(deadline_monotonic)
                or deadline_monotonic <= time.monotonic()):
            raise ValueError("invalid_native_episode_deadline")
        self._episode_deadline = deadline_monotonic

    def close_admission(self):
        self._admission_closed = True

    def _admit(self):
        if self._admission_closed:
            raise NativeProcessFailure("native_admission_closed")
        if self._episode_deadline is not None and time.monotonic() >= self._episode_deadline:
            raise NativeProcessFailure("native_episode_deadline_before_send")

    def _request_deadline(self, deadline_monotonic):
        if deadline_monotonic is not None and (
                type(deadline_monotonic) not in (int, float)
                or not math.isfinite(deadline_monotonic)):
            raise ValueError("invalid_native_phase_deadline")
        values = [value for value in (self._episode_deadline, deadline_monotonic)
                  if value is not None]
        return min(values) if values else None

    def snapshot(self, *, deadline_monotonic=None):
        self._admit()
        return self.worker.request(
            "snapshot", deadline_monotonic=self._request_deadline(deadline_monotonic))

    def snapshot_after_close(self, *, timeout_seconds: float = 5):
        """Bounded read-only cleanup; it never reopens actor tool admission."""
        if not self._admission_closed:
            raise NativeProcessFailure("cleanup_requires_closed_admission")
        if type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 5:
            raise ValueError("invalid_cleanup_snapshot_timeout")
        return self.worker.request("snapshot", deadline_monotonic=time.monotonic() + timeout_seconds)

    def call(self, tool, arguments, *, deadline_monotonic=None):
        self._admit()
        result=self.worker.request(
            "call", deadline_monotonic=self._request_deadline(deadline_monotonic),
            tool=tool, arguments=arguments)
        if result.get("evidence_quality",{}).get("backend_entered") is True:
            self._trusted_calls.append(_loads(_encode({"function":tool,"args":arguments})))
        return result
    def _score(self, before, after, final_text):
        params=dict(before=before,after=after,final_text=final_text,function_calls=self._trusted_calls)
        identity=hashlib.sha256(_encode(params)).hexdigest()
        if identity in self._score_cache: return self._score_cache[identity]
        with PipeWorker(mode="evaluator", **self.arguments) as scorer:
            result=scorer.request("score", **params)
        self._score_cache[identity]=result
        return result
    def native_score(self, before, after, final_text): return self._score(before,after,final_text)["native"]
    def strict_score(self, before, after, final_text): return self._score(before,after,final_text)["strict"]
    def native_goal_record(self, goal_id):
        """Public identity, retrieved through a controller-private worker."""
        with PipeWorker(mode="evaluator", **self.arguments) as evaluator:
            return evaluator.request("goal_record", goal_id=goal_id)

    def native_attack_score_detail(self, goal_id, before, after, final_text, *, function_calls=None):
        """Private scoring only. Explicit prefixes never inherit future calls."""
        calls = self._trusted_calls if function_calls is None else function_calls
        if not isinstance(calls, list):
            return {"value": None, "reason": "invalid_native_goal_score_inputs", "goal_record": None,
                    "initial_goal_value": None, "initial_goal_reason": "not_evaluated", "source_bound": False}
        try:
            with PipeWorker(mode="evaluator", **self.arguments) as evaluator:
                return evaluator.request("attack_score", goal_id=goal_id, before=before, after=after,
                                         final_text=final_text, function_calls=calls)
        except (NativeProcessFailure, ValueError, TypeError) as exc:
            return {"value": None, "reason": "private_native_goal_evaluator_unavailable", "goal_record": None,
                    "initial_goal_value": None, "initial_goal_reason": "not_evaluated", "source_bound": False,
                    "error_type": type(exc).__name__}
    def shutdown(self): self.worker.shutdown()


def worker_main(args):
    output = sys.stdout.buffer
    def send(value):
        raw = _encode(value)
        if len(raw) > MAX_FRAME: raise ValueError("worker_output_too_large")
        output.write(raw); output.flush()
    # Trusted upstream import chatter must never share the framed channel.
    import contextlib
    with contextlib.redirect_stdout(sys.stderr):
        if args.dependency_site:
            sys.path.append(args.dependency_site)
        task = None
        if args.worker != "probe":
            sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
            from agentmembrane.host_v2.rq1_collab_v1.native import NativeTask
            task = NativeTask(args.source_root, args.suite, args.task_id, benchmark_version=args.benchmark_version)
    ready = {"kind":"ready", "mode":args.worker, "pid":os.getpid(),
             "isolation":"same_uid_not_security_boundary"}
    if args.worker == "native":
        ready.update(prompt=task.prompt, record=task.record, tool_specs=task.tool_specs)
    send(ready)
    seq = 0
    for raw in iter(lambda:sys.stdin.buffer.readline(MAX_FRAME + 1), b""):
        if len(raw) > MAX_FRAME or not raw.endswith(b"\n"): return 2
        try:
            frame = _loads(raw)
            if not isinstance(frame,dict) or set(frame)!={"seq","method","params"}: return 2
            if type(frame["seq"]) is not int or frame["seq"]!=seq+1 or not isinstance(frame["params"],dict): return 2
            seq = frame["seq"]
            method, params = frame["method"],frame["params"]
            with contextlib.redirect_stdout(sys.stderr):
                if args.worker == "probe" and method == "probe" and not params:
                    value={"pid":os.getpid(),"uid":os.getuid(),"env_names":sorted(os.environ),
                           "stdin_is_pipe":not sys.stdin.isatty()}
                elif args.worker == "native" and method == "snapshot" and not params:
                    value=task.snapshot()
                elif args.worker == "native" and method == "call" and set(params)=={"tool","arguments"}:
                    if not isinstance(params["tool"],str) or not isinstance(params["arguments"],dict): raise ValueError("invalid_native_call")
                    value=task.call(params["tool"],params["arguments"])
                elif args.worker == "evaluator" and method == "score" and set(params)=={"before","after","final_text","function_calls"}:
                    if not isinstance(params["function_calls"],list): raise ValueError("private_trace_must_be_list")
                    detail=task.native_score_detail(**params)
                    value={"native":detail["value"],"native_detail":detail,
                           "strict":task.strict_score(**{k:v for k,v in params.items() if k!="function_calls"})}
                elif args.worker == "evaluator" and method == "goal_record" and set(params)=={"goal_id"}:
                    value=task.native_goal_record(params["goal_id"])
                elif args.worker == "evaluator" and method == "attack_score" and set(params)=={"goal_id","before","after","final_text","function_calls"}:
                    value=task.native_attack_score_detail(**params)
                else: raise ValueError("private_worker_method_not_exposed")
            send({"seq":seq,"ok":True,"value":value})
        except Exception as exc:
            send({"seq":seq,"ok":False,"value":{"error_class":type(exc).__name__}})
    return 0


if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--worker",choices=("native","evaluator","probe"),required=True)
    parser.add_argument("--source-root")
    parser.add_argument("--dependency-site")
    parser.add_argument("--suite",default="workspace")
    parser.add_argument("--task-id",default="user_task_8")
    parser.add_argument("--benchmark-version",default="v1")
    raise SystemExit(worker_main(parser.parse_args()))
