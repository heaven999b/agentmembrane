"""Per-cell ownership of the manifest-bound CLIProxy lifecycle.

The caller supplies only an activated manifest and cell identity.  This module
reloads the exact route binding, imports the hash-bound local lifecycle runner,
starts one fresh proxy instance, performs one no-retry readiness request, and
creates the only transport that may serve the cell.  After actor execution it
clears the in-process credential, stops the proxy, verifies removal of the
private secret root, and returns a hash-chained receipt suitable for the cell's
execution seal.

The lifecycle runner and its account material remain local inputs.  No secret,
private path, response body, or account identifier enters the receipt.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import types
import urllib.error
import urllib.parse
import urllib.request

from ..rq1_collab_v1.audit import _write_new, canonical, file_hash, strict_loads
from ..rq1_collab_v3.contract import clone, digest
from ..rq1_collab_v3.proxy_transport import BoundProxyTransport
from ..rq1_collab_v6.contract import PHASE_SCHEDULE
from .contract import FORMAL_PROTOCOL, MODEL_PROFILES


CELL_LIFECYCLE_SCHEMA = "rq1-agentdojo-three-tier-cell-proxy-lifecycle-receipt/1"
CELL_LIFECYCLE_PATH = "artifacts/proxy-lifecycle-receipt.json"
_HEX64 = re.compile(r"[0-9a-f]{64}")


class ProxyLifecycleFailure(RuntimeError):
    """Stable failure codes only; never interpolate a private value."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "redirect_not_allowed", headers, fp)


def _binding_file(value: object, label: str) -> Path:
    if (type(value) is not dict or not {"path", "sha256"} <= set(value)
            or type(value.get("path")) is not str
            or not _HEX64.fullmatch(str(value.get("sha256", "")))):
        raise ProxyLifecycleFailure("lifecycle_binding_invalid:" + label)
    path = Path(value["path"])
    if path.is_symlink() or not path.is_file():
        raise ProxyLifecycleFailure("lifecycle_bound_file_missing:" + label)
    try:
        actual = file_hash(path)
    except OSError as exc:
        raise ProxyLifecycleFailure(
            "lifecycle_bound_file_unreadable:" + label) from exc
    if actual != value["sha256"]:
        raise ProxyLifecycleFailure("lifecycle_bound_file_changed:" + label)
    return path.resolve(strict=True)


def _route_runtime_binding(manifest: dict) -> dict:
    source = manifest.get("source_bindings", {}).get("route_runtime_binding")
    path = _binding_file(source, "route_runtime_binding")
    try:
        value = strict_loads(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise ProxyLifecycleFailure("route_runtime_binding_unreadable") from exc
    if (type(value) is not dict
            or value.get("route_runtime_binding_sha256")
               != manifest.get("route_runtime_binding_sha256")
            or value.get("route_runtime_binding_sha256")
               != digest({key: clone(item) for key, item in value.items()
                          if key != "route_runtime_binding_sha256"})):
        raise ProxyLifecycleFailure("route_runtime_binding_mismatch")
    _binding_file(value.get("lifecycle_runner"), "lifecycle_runner")
    binary_path = _binding_file(
        value.get("cli_proxy_binary"), "cli_proxy_binary")
    _binding_file(value.get("attestation"), "attestation")
    if not os.access(binary_path, os.X_OK):
        raise ProxyLifecycleFailure("bound_cli_proxy_binary_not_executable")
    route_source = value.get("route")
    route_path = _binding_file(route_source, "route")
    try:
        route = strict_loads(route_path.read_bytes())
    except (OSError, ValueError) as exc:
        raise ProxyLifecycleFailure("bound_route_unreadable") from exc
    if (type(route_source) is not dict or route_source.get("route") != route
            or type(route) is not dict
            or route.get("schema_version") != "rq1-provider-route/1"
            or set(route) != {
                "schema_version", "endpoint", "credential_env", "account_label"
            }):
        raise ProxyLifecycleFailure("bound_route_mismatch")
    parsed = urllib.parse.urlsplit(route["endpoint"])
    if (parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.port is None
            or parsed.path != "/v1/chat/completions"
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment
            or not re.fullmatch(
                r"[A-Z][A-Z0-9_]{0,127}", str(route["credential_env"]))) :
        raise ProxyLifecycleFailure("bound_route_not_explicit_loopback")
    policy = value.get("formal_lifecycle_policy")
    if (type(policy) is not dict
            or policy.get("route_instance_scope")
               != "one_fresh_dedicated_instance_per_cell"
            or policy.get("workers") != 1
            or policy.get("request_retry") != 0
            or policy.get("max_retry_credentials") != 1
            or policy.get("automatic_cell_retry") is not False
            or policy.get("stop_and_secret_cleanup_after_every_cell") is not True
            or policy.get(
                "revalidate_route_account_binary_and_config_before_every_cell")
               is not True):
        raise ProxyLifecycleFailure("formal_lifecycle_policy_mismatch")
    return value


def _load_bound_runner(path: Path, expected_sha256: str) -> types.ModuleType:
    if path.suffix != ".py" or file_hash(path) != expected_sha256:
        raise ProxyLifecycleFailure("bound_lifecycle_runner_changed")
    name = "_rq1_bound_lifecycle_" + expected_sha256
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ProxyLifecycleFailure("bound_lifecycle_runner_not_importable")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise ProxyLifecycleFailure("bound_lifecycle_runner_import_failed") from exc
    if not callable(getattr(module, "start", None)) \
            or not callable(getattr(module, "stop", None)):
        raise ProxyLifecycleFailure("bound_lifecycle_runner_interface_missing")
    return module


def _secure_key(root: Path, key_path: Path) -> str:
    if root.is_symlink() or key_path.is_symlink():
        raise ProxyLifecycleFailure("lifecycle_private_path_symlink")
    try:
        resolved_root = root.resolve(strict=True)
        resolved_key = key_path.resolve(strict=True)
        root_info = resolved_root.stat()
        key_info = resolved_key.stat()
    except OSError as exc:
        raise ProxyLifecycleFailure("lifecycle_private_path_missing") from exc
    try:
        resolved_key.relative_to(resolved_root)
    except ValueError as exc:
        raise ProxyLifecycleFailure("lifecycle_key_outside_private_root") from exc
    if (not stat.S_ISDIR(root_info.st_mode)
            or not stat.S_ISREG(key_info.st_mode)
            or root_info.st_uid != os.getuid() or key_info.st_uid != os.getuid()
            or stat.S_IMODE(root_info.st_mode) != 0o700
            or stat.S_IMODE(key_info.st_mode) != 0o600
            or not 8 <= key_info.st_size <= 4096):
        raise ProxyLifecycleFailure("lifecycle_private_path_permissions_invalid")
    try:
        key = resolved_key.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise ProxyLifecycleFailure("lifecycle_key_unreadable") from exc
    if not key or len(key) > 4096 or any(ord(char) < 33 or ord(char) > 126
                                        for char in key):
        raise ProxyLifecycleFailure("lifecycle_key_invalid")
    return key


def _readiness(endpoint: str, credential: str) -> None:
    models_url = endpoint[:-len("/chat/completions")] + "/models"
    req = urllib.request.Request(
        models_url,
        headers={"Authorization": "Bearer " + credential,
                 "Accept": "application/json"},
        method="GET",
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(req, timeout=10) as response:
            body = response.read(1_000_001)
            status = response.status
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
        raise ProxyLifecycleFailure("per_cell_proxy_readiness_failed") from exc
    if status != 200 or len(body) > 1_000_000:
        raise ProxyLifecycleFailure("per_cell_proxy_readiness_failed")
    try:
        value = strict_loads(body)
    except (ValueError, UnicodeError) as exc:
        raise ProxyLifecycleFailure("per_cell_proxy_readiness_invalid") from exc
    entries = value.get("data") if type(value) is dict else None
    model_ids = ({row.get("id") for row in entries if type(row) is dict}
                 if type(entries) is list else set())
    required = {profile["model"] for profile in MODEL_PROFILES.values()}
    if not required <= model_ids:
        raise ProxyLifecycleFailure("per_cell_required_model_unavailable")


def _event(*, sequence: int, kind: str, attempt_id: str,
           pid: int, endpoint_sha256: str, parent: str | None) -> dict:
    body = {
        "sequence": sequence,
        "kind": kind,
        "attempt_id": attempt_id,
        "proxy_pid": pid,
        "endpoint_sha256": endpoint_sha256,
        "status": "confirmed",
        "parent_event_sha256": parent,
    }
    return {**body, "event_sha256": digest(body)}


class PerCellProxyLifecycle:
    """One-shot process, readiness, transport, stop, and cleanup owner."""

    def __init__(self, *, manifest: dict, cell: dict, collector):
        self.manifest = manifest
        self.cell = cell
        self.collector = collector
        self.binding = _route_runtime_binding(manifest)
        self.route = clone(self.binding["route"]["route"])
        self._runner_path = _binding_file(
            self.binding["lifecycle_runner"], "lifecycle_runner")
        self._runner = _load_bound_runner(
            self._runner_path, self.binding["lifecycle_runner"]["sha256"])
        self._root: Path | None = None
        self._key_path: Path | None = None
        self._credential: str | None = None
        self._pid: int | None = None
        self._transport: BoundProxyTransport | None = None
        self._events: list[dict] = []
        self._closed = False
        self._receipt: dict | None = None
        self._attempt_id = digest({
            "formal_manifest_sha256": manifest.get("manifest_sha256"),
            "episode_id": cell.get("episode_id"),
            "collector_id": strict_loads(
                (collector.run_dir / ".collector.lock").read_bytes()
            ).get("collector_id"),
        })
        self._endpoint_sha256 = hashlib.sha256(
            self.route["endpoint"].encode("utf-8")).hexdigest()

    def _append(self, kind: str) -> None:
        parent = self._events[-1]["event_sha256"] if self._events else None
        self._events.append(_event(
            sequence=len(self._events) + 1,
            kind=kind,
            attempt_id=self._attempt_id,
            pid=self._pid or 0,
            endpoint_sha256=self._endpoint_sha256,
            parent=parent,
        ))

    def start(self) -> BoundProxyTransport:
        if self._root is not None or self._closed:
            raise ProxyLifecycleFailure("per_cell_proxy_lifecycle_reuse")
        # Revalidate every bound file immediately before process creation.
        self.binding = _route_runtime_binding(self.manifest)
        accounting = {
            "inventory_http_requests": 0,
            "total_http_requests": 0,
        }
        try:
            result = self._runner.start(accounting)
        except BaseException as exc:
            active = accounting.get("_active_private_root")
            if type(active) is str:
                candidate = Path(active)
                if candidate.exists() and not candidate.is_symlink():
                    self._root = candidate
                    self._key_path = candidate / "client-key"
                    try:
                        raw_pid = (candidate / "pid").read_text(
                            encoding="ascii").strip()
                        self._pid = int(raw_pid) if raw_pid.isdigit() else None
                    except OSError:
                        self._pid = None
            if not isinstance(exc, Exception):
                raise
            raise ProxyLifecycleFailure("per_cell_proxy_start_failed") from exc
        if type(result) is dict:
            if type(result.get("root")) is str:
                self._root = Path(result["root"])
            if type(result.get("client_key_file")) is str:
                self._key_path = Path(result["client_key_file"])
            if type(result.get("pid")) is int:
                self._pid = result["pid"]
        if (type(result) is not dict or result.get("status") != "ready"
                or type(result.get("root")) is not str
                or type(result.get("client_key_file")) is not str
                or type(result.get("pid")) is not int
                or result["pid"] <= 1):
            raise ProxyLifecycleFailure("per_cell_proxy_start_result_invalid")
        self._append("proxy_process_started")
        self.collector.emit("formal_proxy_process_started", {
            "formal_manifest_sha256": self.manifest["manifest_sha256"],
            "episode_id": self.cell["episode_id"],
            "attempt_id": self._attempt_id,
            "proxy_pid": self._pid,
            "endpoint_sha256": self._endpoint_sha256,
        }, evidence_quality="formal_controller_process_boundary")
        self._credential = _secure_key(self._root, self._key_path)
        _readiness(self.route["endpoint"], self._credential)
        self._append("readiness_probe_passed")
        self.collector.emit("formal_proxy_readiness_passed", {
            "formal_manifest_sha256": self.manifest["manifest_sha256"],
            "episode_id": self.cell["episode_id"],
            "attempt_id": self._attempt_id,
            "proxy_pid": self._pid,
            "endpoint_sha256": self._endpoint_sha256,
            "request_retry": 0,
        }, evidence_quality="formal_controller_readiness_boundary")
        self._transport = BoundProxyTransport(
            self.route["endpoint"], self.route["credential_env"],
            credential=self._credential,
            timeout_seconds=PHASE_SCHEDULE["model_request_hard_timeout_seconds"],
            hard_timeout_seconds=PHASE_SCHEDULE[
                "model_request_hard_timeout_seconds"],
        )
        return self._transport

    def finish_before_seal(self, *, model_request_count: int) -> dict:
        if self._closed or self._receipt is not None:
            raise ProxyLifecycleFailure("per_cell_proxy_lifecycle_reuse")
        if (self._root is None or self._key_path is None or self._pid is None
                or self._transport is None or len(self._events) != 2
                or type(model_request_count) is not int
                or model_request_count < 0):
            raise ProxyLifecycleFailure("per_cell_proxy_not_ready_for_close")
        self._append("formal_actor_run_closed")
        # Destroy every controller-held reference before deleting the key file.
        self._transport._credential = None
        self._transport._bound_credential = None
        self._credential = None
        try:
            stopped = self._runner.stop(self._root)
        except Exception as exc:
            raise ProxyLifecycleFailure("per_cell_proxy_stop_failed") from exc
        if (type(stopped) is not dict
                or stopped.get("status") not in {"stopped", "already_stopped"}
                or stopped.get("root_removed") is not True
                or stopped.get("pid") != self._pid):
            raise ProxyLifecycleFailure("per_cell_proxy_stop_result_invalid")
        self._append("proxy_process_stopped")
        if self._root.exists() or self._key_path.exists():
            raise ProxyLifecycleFailure("per_cell_proxy_secret_cleanup_failed")
        self._append("secret_cleanup_completed")
        body = {
            "schema_version": CELL_LIFECYCLE_SCHEMA,
            "formal_protocol_version": FORMAL_PROTOCOL,
            "formal_manifest_sha256": self.manifest["manifest_sha256"],
            "episode_id": self.cell["episode_id"],
            "formal_cell_sha256": digest(self.cell),
            "route_runtime_binding_sha256": self.binding[
                "route_runtime_binding_sha256"],
            "lifecycle_runner_sha256": self.binding[
                "lifecycle_runner"]["sha256"],
            "cli_proxy_binary_sha256": self.binding[
                "cli_proxy_binary"]["sha256"],
            "route_sha256": self.binding["route"]["sha256"],
            "attempt_id": self._attempt_id,
            "proxy_pid": self._pid,
            "endpoint_sha256": self._endpoint_sha256,
            "events": clone(self._events),
            "workers": 1,
            "request_retry": 0,
            "automatic_cell_retry": False,
            "model_request_count": model_request_count,
            "secret_values_persisted": False,
            "private_paths_persisted": False,
        }
        self._receipt = {**body, "receipt_sha256": digest(body)}
        self._closed = True
        self.collector.emit("formal_proxy_lifecycle_completed", {
            "formal_manifest_sha256": self.manifest["manifest_sha256"],
            "episode_id": self.cell["episode_id"],
            "attempt_id": self._attempt_id,
            "receipt_sha256": self._receipt["receipt_sha256"],
            "model_request_count": model_request_count,
            "secret_cleanup_completed": True,
        }, evidence_quality="formal_controller_pre_seal_lifecycle")
        return clone(self._receipt)

    def cleanup_after_failure(self) -> dict:
        """Best-effort mandatory cleanup before sealing a failed attempt."""
        if self._transport is not None:
            self._transport._credential = None
            self._transport._bound_credential = None
        self._credential = None
        if self._root is None:
            self._closed = True
            return {"process_stop_confirmed": True,
                    "secret_cleanup_confirmed": True}
        if not self._root.exists():
            # Missing files alone do not prove that the process exited.
            stopped = self._closed
            if not stopped and self._pid is not None:
                try:
                    os.kill(self._pid, 0)
                except ProcessLookupError:
                    stopped = True
                except PermissionError:
                    stopped = False
            self._closed = stopped
            return {"process_stop_confirmed": stopped,
                    "secret_cleanup_confirmed": True}
        stop_confirmed = False
        try:
            stopped = self._runner.stop(self._root)
            if self._pid is None and type(stopped) is dict \
                    and type(stopped.get("pid")) is int:
                self._pid = stopped["pid"]
            stop_confirmed = (type(stopped) is dict
                              and stopped.get("status") in {
                                  "stopped", "already_stopped"}
                              and stopped.get("root_removed") is True
                              and stopped.get("pid") == self._pid)
        except Exception:
            stop_confirmed = False
        secret_cleanup = not self._root.exists() and (
            self._key_path is None or not self._key_path.exists())
        self._closed = stop_confirmed and secret_cleanup
        return {
            "process_stop_confirmed": stop_confirmed,
            "secret_cleanup_confirmed": secret_cleanup,
        }


def validate_cell_lifecycle_receipt(value: dict, *, manifest: dict,
                                    cell: dict) -> dict:
    """Validate the exact ordered process receipt bound to one formal cell."""
    binding = _route_runtime_binding(manifest)
    required = {
        "schema_version", "formal_protocol_version", "formal_manifest_sha256",
        "episode_id", "formal_cell_sha256", "route_runtime_binding_sha256",
        "lifecycle_runner_sha256", "cli_proxy_binary_sha256", "route_sha256",
        "attempt_id", "proxy_pid", "endpoint_sha256", "events", "workers",
        "request_retry", "automatic_cell_retry", "model_request_count",
        "secret_values_persisted", "private_paths_persisted", "receipt_sha256",
    }
    unsigned = ({key: clone(item) for key, item in value.items()
                 if key != "receipt_sha256"} if type(value) is dict else {})
    endpoint = binding.get("route", {}).get("route", {}).get("endpoint")
    if (type(value) is not dict or set(value) != required
            or value.get("schema_version") != CELL_LIFECYCLE_SCHEMA
            or value.get("formal_protocol_version") != FORMAL_PROTOCOL
            or value.get("formal_manifest_sha256") != manifest.get("manifest_sha256")
            or value.get("episode_id") != cell.get("episode_id")
            or value.get("formal_cell_sha256") != digest(cell)
            or value.get("route_runtime_binding_sha256")
               != binding.get("route_runtime_binding_sha256")
            or value.get("lifecycle_runner_sha256")
               != binding.get("lifecycle_runner", {}).get("sha256")
            or value.get("cli_proxy_binary_sha256")
               != binding.get("cli_proxy_binary", {}).get("sha256")
            or value.get("route_sha256")
               != binding.get("route", {}).get("sha256")
            or not _HEX64.fullmatch(str(value.get("attempt_id", "")))
            or type(value.get("proxy_pid")) is not int or value["proxy_pid"] <= 1
            or value.get("endpoint_sha256")
               != hashlib.sha256(str(endpoint).encode("utf-8")).hexdigest()
            or value.get("workers") != 1 or value.get("request_retry") != 0
            or value.get("automatic_cell_retry") is not False
            or type(value.get("model_request_count")) is not int
            or value["model_request_count"] < 0
            or value.get("secret_values_persisted") is not False
            or value.get("private_paths_persisted") is not False
            or value.get("receipt_sha256") != digest(unsigned)):
        raise ValueError("formal_cell_proxy_lifecycle_receipt_invalid")
    kinds = [
        "proxy_process_started", "readiness_probe_passed",
        "formal_actor_run_closed", "proxy_process_stopped",
        "secret_cleanup_completed",
    ]
    events = value.get("events")
    if type(events) is not list or len(events) != len(kinds):
        raise ValueError("formal_cell_proxy_lifecycle_event_chain_invalid")
    parent = None
    for sequence, (event, kind) in enumerate(zip(events, kinds), 1):
        event_unsigned = ({key: clone(item) for key, item in event.items()
                          if key != "event_sha256"}
                          if type(event) is dict else {})
        if (type(event) is not dict or set(event) != {
                "sequence", "kind", "attempt_id", "proxy_pid",
                "endpoint_sha256", "status", "parent_event_sha256",
                "event_sha256"}
                or event.get("sequence") != sequence
                or event.get("kind") != kind
                or event.get("attempt_id") != value["attempt_id"]
                or event.get("proxy_pid") != value["proxy_pid"]
                or event.get("endpoint_sha256") != value["endpoint_sha256"]
                or event.get("status") != "confirmed"
                or event.get("parent_event_sha256") != parent
                or event.get("event_sha256") != digest(event_unsigned)):
            raise ValueError("formal_cell_proxy_lifecycle_event_chain_invalid")
        parent = event["event_sha256"]
    return clone(value)


def _rehearsal_event(*, sequence: int, kind: str, attempt_id: str,
                     pid: int, endpoint: str, parent: str | None) -> dict:
    body = {
        "sequence": sequence,
        "kind": kind,
        "attempt_id": attempt_id,
        "proxy_pid": pid,
        "loopback_endpoint": endpoint,
        "status": "confirmed",
        "parent_event_sha256": parent,
    }
    return {**body, "event_sha256": digest(body)}


def rehearse_bound_proxy_lifecycle(*, route_binding_path: str | Path,
                                   code_bundle_sha256: str,
                                   output: str | Path) -> dict:
    """Create one zero-model, zero-sample lifecycle qualification receipt.

    The rehearsal proves the exact bound runner can start, pass one readiness
    request, stop, and delete its secret root.  It never creates a formal cell
    and cannot enter the study result set.
    """
    route_path = Path(route_binding_path)
    source = {"path": str(route_path.resolve()), "sha256": file_hash(route_path)}
    raw_binding = strict_loads(route_path.read_bytes())
    manifest = {
        "route_runtime_binding_sha256": raw_binding.get(
            "route_runtime_binding_sha256"),
        "source_bindings": {"route_runtime_binding": source},
    }
    binding = _route_runtime_binding(manifest)
    if not _HEX64.fullmatch(str(code_bundle_sha256)):
        raise ValueError("formal_code_bundle_sha256_required")
    runner_path = _binding_file(binding["lifecycle_runner"], "lifecycle_runner")
    runner = _load_bound_runner(
        runner_path, binding["lifecycle_runner"]["sha256"])
    route = binding["route"]["route"]
    accounting = {"inventory_http_requests": 0, "total_http_requests": 0}
    root = None
    key_path = None
    pid = None
    started = None
    try:
        started = runner.start(accounting)
        if (type(started) is not dict or started.get("status") != "ready"
                or type(started.get("root")) is not str
                or type(started.get("client_key_file")) is not str
                or type(started.get("pid")) is not int
                or started["pid"] <= 1):
            raise ProxyLifecycleFailure("lifecycle_rehearsal_start_invalid")
        root = Path(started["root"])
        key_path = Path(started["client_key_file"])
        pid = started["pid"]
        credential = _secure_key(root, key_path)
        _readiness(route["endpoint"], credential)
        credential = None
        stopped = runner.stop(root)
        if (type(stopped) is not dict
                or stopped.get("status") not in {"stopped", "already_stopped"}
                or stopped.get("root_removed") is not True
                or stopped.get("pid") != pid
                or root.exists() or key_path.exists()):
            raise ProxyLifecycleFailure("lifecycle_rehearsal_cleanup_invalid")
        kinds = [
            "proxy_process_started", "readiness_probe_passed",
            "proxy_process_stopped", "secret_cleanup_completed",
        ]
        attempt_id = digest({
            "code_bundle_sha256": code_bundle_sha256,
            "route_runtime_binding_sha256": binding[
                "route_runtime_binding_sha256"],
            "proxy_pid": pid,
        })
        events = []
        for sequence, kind in enumerate(kinds, 1):
            events.append(_rehearsal_event(
                sequence=sequence, kind=kind, attempt_id=attempt_id,
                pid=pid, endpoint=route["endpoint"],
                parent=(events[-1]["event_sha256"] if events else None),
            ))
        body = {
            "schema_version": (
                "rq1-agentdojo-three-tier-production-proxy-lifecycle-"
                "receipt/2"),
            "formal_protocol_version": FORMAL_PROTOCOL,
            "code_bundle_sha256": code_bundle_sha256,
            "route_runtime_binding_sha256": binding[
                "route_runtime_binding_sha256"],
            "lifecycle_runner_sha256": binding[
                "lifecycle_runner"]["sha256"],
            "cli_proxy_binary_sha256": binding[
                "cli_proxy_binary"]["sha256"],
            "route_sha256": binding["route"]["sha256"],
            "attestation_sha256": binding["attestation"]["sha256"],
            "proxy_config_policy_sha256": binding[
                "proxy_config_policy_sha256"],
            "attempt_id": attempt_id,
            "proxy_pid": pid,
            "loopback_endpoint": route["endpoint"],
            "events": events,
            "workers": 1,
            "request_retry": 0,
            "automatic_cell_retry": False,
            "generation_calls": 0,
            "formal_actor_calls": 0,
            "research_sample_count": 0,
        }
        receipt = {**body, "receipt_sha256": digest(body)}
        _write_new(Path(output).resolve(), canonical(receipt) + b"\n")
        return receipt
    except BaseException:
        if root is None:
            active = accounting.get("_active_private_root")
            if type(active) is str:
                candidate = Path(active)
                if candidate.exists() and not candidate.is_symlink():
                    root = candidate
        if root is not None and root.exists():
            try:
                runner.stop(root)
            except Exception:
                pass
        raise
