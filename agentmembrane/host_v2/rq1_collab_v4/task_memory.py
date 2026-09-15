"""Episode-local persistent task memory. Public methods are controller APIs.

Only put/get/list accept actor actions. Identity, cache provenance, deliveries,
delegation, transfer, invalidation and closure must be supplied by trusted code.
"""
from __future__ import annotations

import copy
import json
import multiprocessing
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time

from .memory_reader import canonical, digest
from .memory_refs import MemoryReferenceError, resolve_memory_arguments


PROFILE = {"max_current_records": 128, "max_note_value_bytes": 16384,
           "max_native_cache_value_bytes": 1048576, "max_committed_version_value_bytes": 33554432,
           "max_record_key_ascii_bytes": 128, "metadata_page_records": 16,
           "metadata_page_bytes": 16384, "automatic_restore_value_bytes": 65536,
           "automatic_restore_packet_bytes": 98304, "explicit_get_page_bytes": 16384,
           "max_argument_refs": 16, "memory_write_timeout_seconds": 5,
           "fresh_reader_timeout_seconds": 10}
SYSTEM_PROFILE = "three_actor_task_memory_v1"
DELIVERED = {"model_response_observed", "confirmed_model_refusal"}
TOOL_SPECS = [
    {"name":"memory.put","description":"Store an identity-labelled version in an allowed task namespace.",
     "parameters":{"type":"object","additionalProperties":False,"required":["namespace","key","value","expected_version"],
       "properties":{"namespace":{"type":"string"},"key":{"type":"string","pattern":"^[A-Za-z0-9_.:-]{1,128}$"},
         "value":{},"expected_version":{"type":"integer","minimum":0},
         "source_refs":{"type":"array","items":{"type":"string"},"maxItems":64,"uniqueItems":True}}}},
    {"name":"memory.get","description":"Read an exact current memory version; pages do not imply complete receipt.",
     "parameters":{"type":"object","additionalProperties":False,"required":["record_id","expected_version"],
       "properties":{"record_id":{"type":"string"},"expected_version":{"type":"integer","minimum":1},
         "offset_bytes":{"type":"integer","minimum":0},"limit_bytes":{"type":"integer","minimum":1,"maximum":16384}}}},
    {"name":"memory.list","description":"List allowed metadata without note values.",
     "parameters":{"type":"object","additionalProperties":False,"properties":{"namespace":{"type":"string"},"cursor":{"type":"string"}}}}
]


class MemoryServiceError(RuntimeError):
    def __init__(self, code, *, commit_unknown=False):
        super().__init__(code)
        self.code, self.commit_unknown = code, commit_unknown


def _worker(pipe, path, meta, limits):
    db = None
    try:
        db = sqlite3.connect(path, timeout=2)
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("PRAGMA synchronous=FULL")
        db.executescript("""
          CREATE TABLE store_meta(episode_id TEXT PRIMARY KEY, task_bundle_hash TEXT NOT NULL,
            world_id TEXT NOT NULL, system_profile TEXT NOT NULL, closed INTEGER NOT NULL);
          CREATE TABLE records(namespace TEXT NOT NULL, record_key TEXT NOT NULL,
            current_version INTEGER NOT NULL, record_id TEXT NOT NULL UNIQUE,
            owner_principal TEXT NOT NULL, record_kind TEXT NOT NULL,
            PRIMARY KEY(namespace,record_key));
          CREATE TABLE versions(namespace TEXT NOT NULL,record_key TEXT NOT NULL,version INTEGER NOT NULL,
            value_json TEXT NOT NULL,value_hash TEXT NOT NULL,writer_principal TEXT NOT NULL,
            origin_refs_json TEXT NOT NULL,original_call_id TEXT,original_tool TEXT,dependency_hash TEXT,
            write_intent_event_id TEXT NOT NULL,commit_receipt_event_id TEXT,grant_epoch INTEGER NOT NULL,
            PRIMARY KEY(namespace,record_key,version));
          CREATE TABLE invalidations(namespace TEXT NOT NULL,record_key TEXT NOT NULL,version INTEGER NOT NULL,
            cause_native_call_id TEXT NOT NULL,invalidated_event_id TEXT NOT NULL,
            PRIMARY KEY(namespace,record_key,version));
        """)
        db.execute("INSERT INTO store_meta VALUES(?,?,?,?,0)",
                   (meta["episode_id"], meta["task_bundle_hash"], meta["world_id"], SYSTEM_PROFILE))
        db.commit()
        pipe.send({"ok": True})
        while True:
            command = pipe.recv()
            op = command["op"]
            if op == "close":
                db.execute("UPDATE store_meta SET closed=1")
                db.commit()
                pipe.send({"ok": True})
                break
            if db.execute("SELECT closed FROM store_meta").fetchone()[0]:
                pipe.send({"ok": False, "error": "admission_closed"})
                continue
            if op == "receipt":
                db.execute("UPDATE versions SET commit_receipt_event_id=? WHERE namespace=? AND record_key=? AND version=?",
                           (command["receipt_id"], command["namespace"], command["key"], command["version"]))
                db.commit()
                pipe.send({"ok": True})
            elif op == "invalidate":
                rows = db.execute("SELECT r.namespace,r.record_key,r.current_version FROM records r WHERE r.record_kind='native_observation'").fetchall()
                for ns, key, version in rows:
                    db.execute("INSERT OR IGNORE INTO invalidations VALUES(?,?,?,?,?)",
                               (ns, key, version, command["call_id"], command["event_id"]))
                db.commit()
                pipe.send({"ok": True, "invalidated_count": len(rows)})
            elif op == "put":
                c = command
                if c.get("deadline") is not None and time.monotonic() >= c["deadline"]:
                    pipe.send({"ok":False,"error":"memory_deadline_exhausted","committed":False})
                    continue
                db.execute("BEGIN IMMEDIATE")
                old = db.execute("SELECT current_version,record_id,record_kind,owner_principal FROM records WHERE namespace=? AND record_key=?",
                                 (c["namespace"], c["key"])).fetchone()
                if old and old[2]=="native_observation":
                    original=db.execute("SELECT original_call_id,original_tool,dependency_hash,origin_refs_json,grant_epoch FROM versions WHERE namespace=? AND record_key=? AND version=1",
                                        (c["namespace"],c["key"])).fetchone()
                    # Actor writes can replace a value, never the original
                    # native identity/projection provenance or owning grant.
                    c["original_call_id"],c["original_tool"],c["dependency_hash"] = original[:3]
                    c["source_refs"] = sorted(set(json.loads(original[3])) | set(c["source_refs"]))
                    c["grant_epoch"] = original[4]
                current = old[0] if old else 0
                expected = c["expected_version"]
                reason = None
                if expected != current:
                    reason = "expected_version_conflict"
                elif old is None and db.execute("SELECT count(*) FROM records").fetchone()[0] >= limits["max_current_records"]:
                    reason = "capacity_exhausted"
                maximum = limits["max_native_cache_value_bytes"] if (old[2] if old else c["kind"]) == "native_observation" else limits["max_note_value_bytes"]
                if len(c["value_bytes"]) > maximum:
                    reason = "value_capacity_exhausted"
                total = db.execute("SELECT coalesce(sum(length(CAST(value_json AS BLOB))),0) FROM versions").fetchone()[0]
                if total + len(c["value_bytes"]) > limits["max_committed_version_value_bytes"]:
                    reason = "history_capacity_exhausted"
                if len(c["source_refs"])>64:
                    reason = "source_provenance_capacity_exhausted"
                if reason:
                    db.rollback()
                    pipe.send({"ok": False, "error": reason, "committed": False})
                    continue
                version = current + 1
                rid = old[1] if old else c["record_id"]
                if old:
                    db.execute("UPDATE records SET current_version=? WHERE namespace=? AND record_key=?",
                               (version, c["namespace"], c["key"]))
                else:
                    db.execute("INSERT INTO records VALUES(?,?,?,?,?,?)", (c["namespace"],c["key"],version,rid,c["owner"],c["kind"]))
                db.execute("INSERT INTO versions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (c["namespace"],c["key"],version,c["value_bytes"].decode(),c["value_hash"],c["writer"],
                            json.dumps(c["source_refs"]),c.get("original_call_id"),c.get("original_tool"),
                            c.get("dependency_hash"),c["intent_id"],None,c["grant_epoch"]))
                if old and old[2]=="native_observation":
                    invalidation=db.execute("SELECT cause_native_call_id,invalidated_event_id FROM invalidations WHERE namespace=? AND record_key=? AND version=?",
                                            (c["namespace"],c["key"],current)).fetchone()
                    if invalidation:
                        # A changed payload is not a new native query. It may
                        # not resurrect the obsolete original dependencies.
                        db.execute("INSERT INTO invalidations VALUES(?,?,?,?,?)",
                                   (c["namespace"],c["key"],version,*invalidation))
                db.commit()
                pipe.send({"ok": True, "record_id": rid, "version": version, "previous_version": current})
            else:
                pipe.send({"ok": False, "error": "unknown_service_operation"})
    except (EOFError, BrokenPipeError):
        pass
    except Exception:
        try: pipe.send({"ok": False, "error": "memory_service_failure", "commit_unknown": True})
        except Exception: pass
    finally:
        if db is not None:
            db.close()
        pipe.close()


class TaskMemoryService:
    def __init__(self, run_dir, episode_id, task_hash, topology, E_level, emit=None, *,
                 world_id="", deadline_monotonic=None, profile=None, projector=None):
        if topology not in {"H_E", "H_S_E"} or E_level not in {"low", "medium", "high", "A0", "A3", "A4"}:
            raise ValueError("invalid_memory_configuration")
        if type(episode_id) is not str or not episode_id or len(episode_id) > 128:
            raise ValueError("invalid_memory_episode")
        self.episode_id, self.task_hash, self.topology = episode_id, task_hash, topology
        self.E_level = {"low":"A0","medium":"A3","high":"A4"}.get(E_level,E_level)
        self.profile = {**PROFILE, **(profile or {})}
        if set(self.profile) != set(PROFILE) or any(type(v) is not int or v <= 0 for v in self.profile.values()):
            raise ValueError("invalid_memory_limits")
        self.profile_hash = digest({"profile": SYSTEM_PROFILE, "limits": self.profile})
        self.deadline, self.emit, self.projector = deadline_monotonic, emit, projector
        self._events, self._reads, self._visible, self._transfers = [], {}, {a:set() for a in ("H","S","E")}, {}
        self._selection = {a:[] for a in ("H","S","E")}
        self._grant = {"active": False, "epoch": 0, "tools": [], "event_id": None}
        self._closed = False
        self._close_result = None
        self._source_hash = None
        self.namespaces = {s: f"episode/{episode_id}/{s}" for s in
                           ("source","notes/H","notes/E","observations/H") + (("notes/S","observations/S") if topology=="H_S_E" else ())}
        directory = Path(run_dir) / "system_state" / "task_memory"
        directory.mkdir(parents=True, exist_ok=False)
        self.path = directory / "store.sqlite"
        self.meta = {"episode_id": episode_id, "task_bundle_hash": task_hash, "world_id": world_id}
        context = multiprocessing.get_context("spawn")
        self._pipe, child = context.Pipe()
        self._process = context.Process(target=_worker, args=(child,str(self.path),self.meta,self.profile), daemon=True)
        started = False
        try:
            self._process.start()
            started = True
            child.close()
            if not self._pipe.poll(self._timeout("memory_write_timeout_seconds")):
                raise MemoryServiceError("memory_start_timeout")
            try:
                ready = self._pipe.recv()
            except (EOFError, OSError):
                raise MemoryServiceError("memory_start_worker_closed") from None
            if type(ready) is not dict or ready.get("ok") is not True:
                raise MemoryServiceError("memory_start_failed")
        except Exception:
            # A failed constructor has no service object for runtime.close().
            # Reap its own worker and pipe here; do not leak resources or retry.
            child.close()
            if started or self._process.pid is not None:
                if self._process.is_alive():
                    self._process.terminate()
                self._process.join(timeout=.5)
                if self._process.is_alive():
                    self._process.kill()
                    self._process.join(timeout=.5)
            self._pipe.close()
            raise
        self._event("memory_service_started", {"profile_hash":self.profile_hash,"carrier_exists":True})

    @property
    def events(self):
        return copy.deepcopy(self._events)

    def _timeout(self, name):
        value = float(self.profile[name])
        if self.deadline is not None:
            value = min(value, self.deadline-time.monotonic())
        if value <= 0:
            raise MemoryServiceError("memory_deadline_exhausted")
        return value

    def _event(self, kind, data):
        payload_data = copy.deepcopy(data)
        if "event_id" in payload_data:
            payload_data["trigger_event_id"] = payload_data.pop("event_id")
        payload = {**payload_data, "episode_id":self.episode_id,"task_hash":self.task_hash,
                   "system_profile":SYSTEM_PROFILE,"record_origin":"trusted_task_memory_service"}
        external = self.emit(kind, copy.deepcopy(payload)) if self.emit else None
        eid = external.get("event_id") if isinstance(external,dict) else external if isinstance(external,str) else None
        event = {**payload, "event_id":eid or f"{self.episode_id}:memory:{len(self._events)+1}","kind":kind}
        self._events.append(event)
        return event["event_id"]

    def _rpc(self, command):
        if self._closed:
            raise MemoryServiceError("admission_closed")
        timeout = self.profile["memory_write_timeout_seconds"] if command["op"]=="close" else self._timeout("memory_write_timeout_seconds")
        command = {**command,"deadline":self.deadline}
        self._pipe.send(command)
        if not self._pipe.poll(timeout):
            self._process.terminate()
            self._closed = True
            self._event("memory_service_failure", {"reason":"operation_timeout","commit_unknown":command["op"]=="put"})
            raise MemoryServiceError("memory_operation_timeout", commit_unknown=command["op"]=="put")
        result = self._pipe.recv()
        if result.get("commit_unknown"):
            raise MemoryServiceError(result["error"],commit_unknown=True)
        return result

    def snapshot_readonly(self, *, record_id=None, version=None, evaluator=False):
        request = {"path":str(self.path),"episode_id":self.episode_id,"task_hash":self.task_hash,
                   "record_id":record_id,"version":version}
        environment = os.environ.copy()
        environment["PYTHONPATH"] = os.pathsep.join(str(p) for p in sys.path if p)
        timeout = self.profile["fresh_reader_timeout_seconds"] if evaluator else self._timeout("fresh_reader_timeout_seconds")
        try:
            result = subprocess.run([sys.executable,"-S","-m","agentmembrane.host_v2.rq1_collab_v4.memory_reader"],
                                    input=canonical(request),stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                    timeout=timeout,env=environment,check=False)
            output = json.loads(result.stdout)
            if result.returncode or not output.get("ok"):
                raise ValueError("read_failed")
            return output["result"]
        except Exception as exc:
            self._event("memory_reader_failure", {"reason":"readonly_reader_failed","evaluator":evaluator})
            raise MemoryServiceError("readonly_reader_failed") from exc

    def _reject(self, reason, actor, request_id):
        eid = self._event("memory_rejected", {"actor":actor,"request_id":request_id,"reason":reason,"committed":False})
        return {"status":"rejected","reason":reason,"event_id":eid,"committed":False}

    def _active(self, actor):
        if self._closed or actor not in {"H","E","S"} or actor=="S" and self.topology!="H_S_E":
            return False
        if self.deadline is not None and time.monotonic() >= self.deadline:
            return False
        return actor!="S" or self._grant["active"]

    def _suffix(self, namespace):
        return next((k for k,v in self.namespaces.items() if v==namespace),None)

    def _access(self, actor, namespace, *, write=False):
        suffix = self._suffix(namespace)
        if not self._active(actor) or suffix is None or write and suffix=="source":
            return False
        if actor=="H":
            return not write or suffix=="notes/H"
        if actor=="E":
            return suffix in ({"notes/E","notes/H","observations/H"} if self.E_level=="A4" else {"notes/E"} if self.E_level=="A3" else set())
        return suffix in {"notes/S","observations/S"} and (not write or suffix=="notes/S")

    def allow_source_refs(self, actor, source_refs):
        """Trusted runtime supplies only actual delivered non-memory event IDs."""
        self._visible[actor].update(source_refs)

    def set_delegation(self, *, epoch, tools, event_id, active=True):
        if type(epoch) is not int or epoch <= self._grant["epoch"] or type(active) is not bool:
            raise ValueError("delegation_epoch_must_increase")
        if type(tools) not in {list,tuple} or any(type(t) is not str for t in tools):
            raise ValueError("invalid_delegation_tools")
        self._grant = {"epoch":epoch,"tools":list(tools),"event_id":event_id,"active":active}
        self._event("memory_delegation_changed", copy.deepcopy(self._grant))

    def _commit(self, *, actor, namespace, key, value, source_refs, expected_version, request_id,
                kind, owner, original_call_id=None, original_tool=None, dependency_hash=None):
        if type(key) is not str or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}",key):
            return self._reject("invalid_record_key",actor,request_id)
        if type(expected_version) is not int or expected_version < 0:
            return self._reject("exact_expected_version_required",actor,request_id)
        if type(source_refs) not in {list,tuple} or len(source_refs)>64 or any(type(r) is not str or len(r)>256 for r in source_refs):
            return self._reject("invalid_source_refs",actor,request_id)
        raw = canonical(value)
        value_hash = digest(value)
        intent = self._event("memory_write_intent", {"actor":actor,"namespace":namespace,"key":key,
            "request_id":request_id,"value_hash":value_hash,"expected_version":expected_version,"committed":None})
        rid = "memory-" + digest({"episode":self.episode_id,"namespace":namespace,"key":key})[:40]
        result = self._rpc({"op":"put","namespace":namespace,"key":key,"value_bytes":raw,"value_hash":value_hash,
            "source_refs":list(source_refs),"expected_version":expected_version,"intent_id":intent,"record_id":rid,
            "kind":kind,"owner":owner,"writer":actor,"grant_epoch":self._grant["epoch"] if owner=="S" else 0,
            "original_call_id":original_call_id,"original_tool":original_tool,"dependency_hash":dependency_hash})
        if not result["ok"]:
            return self._reject(result["error"],actor,request_id)
        try:
            verified = self.snapshot_readonly(record_id=result["record_id"],version=result["version"])["records"]
            if len(verified)!=1 or verified[0]["value_hash"]!=value_hash:
                raise MemoryServiceError("durable_version_not_verified",commit_unknown=True)
        except MemoryServiceError:
            self._event("memory_commit_unknown", {"actor":actor,"record_id":rid,"version":result["version"],"intent_id":intent})
            raise
        record = verified[0]
        receipt = self._event("memory_committed", {"actor":actor,"record":record,"request_id":request_id,
                               "intent_id":intent,"durable_verified":True,"reader_process_independent":True})
        metadata = self._rpc({"op":"receipt","namespace":namespace,"key":key,"version":result["version"],"receipt_id":receipt})
        record["commit_receipt_event_id"] = receipt if metadata.get("ok") else None
        return {"status":"committed","committed":True,"event_id":receipt,"record":self._view(record)}

    def put(self, *, actor, namespace, key, value, source_refs=(), expected_version=None, request_id):
        if not self._access(actor,namespace,write=True):
            return self._reject("namespace_write_denied",actor,request_id)
        if any(r not in self._visible[actor] for r in source_refs):
            return self._reject("source_reference_not_delivered",actor,request_id)
        suffix = self._suffix(namespace)
        owner = suffix.rsplit("/",1)[1]
        # Existing observation identity/kind are retained by the service worker.
        return self._commit(actor=actor,namespace=namespace,key=key,value=value,source_refs=source_refs,
                            expected_version=0 if expected_version is None else expected_version,request_id=request_id,
                            kind="native_observation" if suffix.startswith("observations/") else "note",owner=owner)

    def seed_source(self, public_request):
        self._source_hash = digest({"public_user_request":public_request})
        return self._commit(actor="system",namespace=self.namespaces["source"],key="trusted-task-input",
                            value={"public_user_request":public_request},source_refs=["source:"+digest(public_request)],
                            expected_version=0,request_id="system:seed",kind="user_input",owner="system")

    def cache_native_result(self, *, actor, call_id, tool, projected_value, source_refs=(), dependency_hash=None):
        if actor not in {"H","S"} or not self._active(actor):
            return self._reject("cache_actor_not_active",actor,call_id)
        if actor=="S" and tool not in self._grant["tools"]:
            return self._reject("outside_delegation",actor,call_id)
        result = self._commit(actor="system",namespace=self.namespaces["observations/"+actor],
            key="call-"+digest(call_id)[:32],value=projected_value,source_refs=source_refs,expected_version=0,
            request_id=call_id,kind="native_observation",owner=actor,original_call_id=call_id,
            original_tool=tool,dependency_hash=dependency_hash)
        if result.get("committed"):
            rid = result["record"]["record_id"]
            self._selection[actor] = [rid]
            # Cache ownership grant must be recorded even though writer=system.
            result["record"]["cache_owner_grant_epoch"] = self._grant["epoch"] if actor=="S" else 0
        return result

    def _view(self, record):
        view = copy.deepcopy(record)
        if record["record_kind"]=="user_input":
            trust = "source_bound" if record["writer_principal"]=="system" and record["value_hash"]==self._source_hash else "unverifiable"
        elif record["record_kind"]=="native_observation":
            trust = "source_bound" if record["writer_principal"]=="system" and record.get("original_call_id") else "modified_observation"
        else:
            trust = "actor_note"
        view["trust_status"] = trust
        view["key"] = view.pop("record_key")
        return view

    def _records(self):
        return self.snapshot_readonly()["records"]

    def _foreign_transfer(self, actor, record):
        return self._transfers.get((actor,record["record_id"],record["version"],self._grant["epoch"]))

    def _read_allowed(self, actor, record):
        if not self._active(actor): return False
        if actor!="S": return self._access(actor,record["namespace"])
        own = record["owner_principal"]=="S" and self._suffix(record["namespace"]) in {"notes/S","observations/S"}
        if own:
            if record["record_kind"]=="native_observation":
                return record.get("original_tool") in self._grant["tools"] and record["grant_epoch"]==self._grant["epoch"]
            return record["grant_epoch"]==self._grant["epoch"]
        return self._foreign_transfer(actor,record) is not None

    def _metadata(self, row):
        meta = {k:row[k] for k in ("record_id","namespace","record_key","record_kind","owner_principal","writer_principal","version","value_hash","invalidated")}
        meta.update(value_bytes=len(canonical(row["value"])),source_ref_count=len(row["source_refs"]))
        if len(canonical(meta))>1024:
            raise MemoryServiceError("metadata_contract_error")
        return meta

    def list(self, *, actor, namespace=None, cursor=None, request_id="memory:list"):
        if namespace is not None and not self._access(actor,namespace) and not (actor=="S" and self._suffix(namespace) is not None):
            return self._reject("namespace_read_denied",actor,request_id)
        if not self._active(actor): return self._reject("actor_not_active",actor,request_id)
        rows = sorted((r for r in self._records() if self._read_allowed(actor,r) and (namespace is None or r["namespace"]==namespace)),key=lambda r:r["record_id"])
        if cursor is not None and (type(cursor) is not str or cursor not in {r["record_id"] for r in rows}):
            return self._reject("invalid_list_cursor",actor,request_id)
        selected = [self._metadata(r) for r in rows if cursor is None or r["record_id"]>cursor]
        page=[]
        for row in selected:
            if len(page)>=self.profile["metadata_page_records"] or len(canonical(page+[row]))>self.profile["metadata_page_bytes"]: break
            page.append(row)
        return {"status":"metadata","records":page,"total_readable_records":len(rows),
                "next_cursor":page[-1]["record_id"] if page and len(page)<len(selected) else None}

    def transfer(self, *, sender, recipient, read_event_id, transfer_event_id, delegation_epoch=None):
        read = self._reads.get(read_event_id)
        epoch = self._grant["epoch"] if delegation_epoch is None else delegation_epoch
        if (sender!="H" or recipient not in {"S","E"} or read is None or read["actor"]!="H"
                or not read.get("delivered") or not self._fully_delivered("H",read)
                or recipient=="S" and (not self._grant["active"] or epoch!=self._grant["epoch"])):
            raise MemoryReferenceError("exact_H_receipt_and_active_transfer_required")
        self._transfers[(recipient,read["record_id"],read["version"],epoch)] = {
            "H_read_event_id":read_event_id,"transfer_event_id":transfer_event_id,
            "value":copy.deepcopy(read["projected_value"]),"projection_hash":read["projected_value_sha256"]}
        self._selection[recipient] = [read["record_id"]]
        self._event("memory_transfer_authorized", {"sender":sender,"recipient":recipient,"read_event_id":read_event_id,
                                                   "record_id":read["record_id"],"version":read["version"],"epoch":epoch,
                                                   "transfer_event_id":transfer_event_id})

    def get(self, *, actor, namespace=None, key=None, record_id=None, consumer_session_id=None,
            expected_version=None, offset_bytes=0, limit_bytes=16384, request_id="memory:get", evaluator=False,
            _automatic=False):
        rows = self._records() if record_id is None else self.snapshot_readonly(record_id=record_id,version=expected_version,evaluator=evaluator)["records"]
        rows = [r for r in rows if (record_id is None or r["record_id"]==record_id) and
                (namespace is None or r["namespace"]==namespace) and (key is None or r["record_key"]==key)]
        if len(rows)!=1: return self._reject("memory_record_not_found",actor,request_id)
        row = rows[0]
        if expected_version is not None and row["version"]!=expected_version:
            return self._reject("expected_version_conflict",actor,request_id)
        if row["version"]!=row["current_version"]:
            return self._reject("stale_record_version",actor,request_id)
        if not evaluator and not self._read_allowed(actor,row):
            return self._reject("memory_read_scope_denied",actor,request_id)
        value = copy.deepcopy(row["value"])
        mediated = None
        if actor=="S" and row["owner_principal"]!="S":
            mediated = self._foreign_transfer(actor,row)
            if mediated is None or self.projector is None:
                return self._reject("S_projection_and_H_transfer_required",actor,request_id)
            value = self.projector(actor,copy.deepcopy(row),copy.deepcopy(mediated["value"]),copy.deepcopy(self._grant))
            if value is None: return self._reject("S_projection_denied",actor,request_id)
        raw = canonical(value)
        maximum = self.profile["automatic_restore_value_bytes"] if _automatic else self.profile["explicit_get_page_bytes"]
        if type(offset_bytes) is not int or type(limit_bytes) is not int or offset_bytes<0 or offset_bytes>len(raw) or not 1<=limit_bytes<=maximum:
            return self._reject("invalid_memory_page",actor,request_id)
        try: raw[:offset_bytes].decode("utf-8")
        except UnicodeDecodeError: return self._reject("page_offset_not_utf8_boundary",actor,request_id)
        end = min(len(raw),offset_bytes+limit_bytes)
        while end>offset_bytes:
            try: chunk=raw[offset_bytes:end].decode("utf-8");break
            except UnicodeDecodeError:end-=1
        if end==offset_bytes and offset_bytes<len(raw): return self._reject("page_too_small_for_utf8",actor,request_id)
        chunk = raw[offset_bytes:end].decode("utf-8")
        read = {"actor":actor,"record_id":row["record_id"],"version":row["version"],"namespace":row["namespace"],
            "owner_principal":row["owner_principal"],"writer_principal":row["writer_principal"],"value_hash":row["value_hash"],
            "projected_value_sha256":digest(value),"byte_begin":offset_bytes,"byte_end":end,"total_bytes":len(raw),
            "consumer_session_id":consumer_session_id or f"{self.episode_id}:reader:{len(self._reads)+1}",
            "fresh_process_reader":True,"evaluator":evaluator,"grant_epoch":self._grant["epoch"] if actor=="S" else 0,
            "request_id":request_id,"invalidated":row["invalidated"],"mediated_by_H":mediated is not None,
            "H_read_event_id":mediated["H_read_event_id"] if mediated else None,
            "transfer_event_id":mediated["transfer_event_id"] if mediated else None}
        eid = self._event("memory_read", read)
        self._reads[eid] = {**read,"read_event_id":eid,"projected_value":value,"delivered":False}
        result = {"status":"memory_read_prepared","read_event_id":eid,"record":self._metadata(row),
            "trust_status":self._view(row)["trust_status"],"projected_value_sha256":digest(value),
            "byte_range":[offset_bytes,end],"total_bytes":len(raw),"next_offset":end if end<len(raw) else None,
            "historical_only":row["invalidated"],"source_refs":list(row["source_refs"])}
        if offset_bytes==0 and end==len(raw):result["value"]=value
        else:result["value_fragment_utf8"]=chunk
        # Runtime delivery checks must compare the complete prepared envelope,
        # not a user-controlled nested read ID/hash that omits or changes value.
        self._reads[eid]["prepared_envelope"] = copy.deepcopy(result)
        self._selection[actor] = [row["record_id"]]
        return result

    def verify_prepared_read(self, *, actor, read):
        """Check an actual observation candidate without exposing hidden values."""
        if type(read) is not dict or type(read.get("read_event_id")) is not str:
            return False
        trusted = self._reads.get(read["read_event_id"])
        if not trusted or trusted["actor"]!=actor or trusted["evaluator"]:
            return False
        try:
            return canonical(trusted.get("prepared_envelope"))==canonical(read)
        except (TypeError, ValueError):
            return False

    def mark_delivered(self, *, actor, read_event_ids, receipt_status, request_id):
        if receipt_status not in DELIVERED | {"engineering_driver_received","queued","submitted","accepted_without_actor_receipt","delivery_unknown"}:
            raise ValueError("invalid_actor_receipt_status")
        for eid in read_event_ids:
            r = self._reads.get(eid)
            if r is None or r["actor"]!=actor or r["evaluator"]:
                raise MemoryReferenceError("receipt_not_actor_owned")
            confirmed = receipt_status in DELIVERED
            if confirmed:
                r["delivered"] = True
                r["receipt_status"] = receipt_status
                self._visible[actor].add(eid)
            self._event("memory_actor_delivery", {"actor":actor,"read_event_id":eid,"record_id":r["record_id"],
                "version":r["version"],"projected_value_sha256":r["projected_value_sha256"],
                "receipt_status":receipt_status,"delivered":confirmed,"behavioral":receipt_status in DELIVERED,
                "request_id":request_id})

    def _fully_delivered(self, actor, read):
        ranges = sorted((r["byte_begin"],r["byte_end"]) for r in self._reads.values() if r["actor"]==actor
            and r["record_id"]==read["record_id"] and r["version"]==read["version"]
            and r["projected_value_sha256"]==read["projected_value_sha256"] and r.get("delivered")
            and r["grant_epoch"]==read["grant_epoch"] and not r["evaluator"])
        covered=0
        for begin,end in ranges:
            if begin>covered:return False
            covered=max(covered,end)
        return covered==read["total_bytes"]

    def reference_projection(self, *, actor, reference):
        r = self._reads.get(reference["read_event_id"])
        if r is None or r["actor"]!=actor or not r.get("delivered") or r["evaluator"]:
            raise MemoryReferenceError("reference_not_actually_delivered")
        if any(r[k]!=reference[k] for k in ("record_id","version","projected_value_sha256")):
            raise MemoryReferenceError("reference_identity_mismatch")
        current = self.snapshot_readonly(record_id=r["record_id"],version=r["version"])["records"]
        if len(current)!=1 or current[0]["current_version"]!=r["version"] or current[0]["invalidated"] or not self._read_allowed(actor,current[0]):
            raise MemoryReferenceError("stale_or_scope_denied")
        if actor=="S" and r["grant_epoch"]!=self._grant["epoch"]:
            raise MemoryReferenceError("stale_delegation")
        if not self._fully_delivered(actor,r):
            raise MemoryReferenceError("projection_pages_incomplete")
        return copy.deepcopy(r["projected_value"])

    def resolve_arguments(self, action, *, actor):
        result, bindings = resolve_memory_arguments(action,actor=actor,memory=self)
        if bindings:
            self._event("memory_binding_prepared", {"actor":actor,"bindings":bindings,"arguments_sha256":digest(result["arguments"]),"use_confirmed":False})
        return result, bindings

    def invalidate(self, *, call_id, before_hash=None, after_hash=None):
        if before_hash is not None and before_hash==after_hash:
            return {"invalidated_count":0}
        eid=self._event("memory_dependencies_invalidated", {"call_id":call_id,"before_hash":before_hash,"after_hash":after_hash,"policy":"all_native_query_caches_on_any_state_change"})
        return self._rpc({"op":"invalidate","call_id":call_id,"event_id":eid})

    def restore(self, *, actor, selected_record_ids=None, consumer_session_id=None):
        directory=self.list(actor=actor)
        if directory.get("status")=="rejected": return directory
        selected=list(dict.fromkeys(selected_record_ids if selected_record_ids is not None else self._selection[actor]))
        values,omitted,used=[],[],0
        current={r["record_id"]:r for r in self._records()}
        for rid in selected:
            row=current.get(rid)
            if row is None or not self._read_allowed(actor,row):continue
            size=len(canonical(row["value"]))
            # Automatic restore is whole-record only; explicit get provides pages.
            if used+size>self.profile["automatic_restore_value_bytes"]:
                omitted.append({"record_id":rid,"reason":"not_loaded_due_to_registered_budget"});continue
            read=self.get(actor=actor,record_id=rid,expected_version=row["version"],consumer_session_id=consumer_session_id,
                          limit_bytes=self.profile["automatic_restore_value_bytes"],_automatic=True)
            candidate={"directory":directory,"values":values+[read],"omitted":omitted}
            if len(canonical(candidate))>self.profile["automatic_restore_packet_bytes"]:
                omitted.append({"record_id":rid,"reason":"not_loaded_due_to_registered_budget"});continue
            values.append(read);used+=size
        packet={"directory":directory,"values":values,"omitted":omitted,"profile_hash":self.profile_hash}
        if len(canonical(packet))>self.profile["automatic_restore_packet_bytes"]:
            raise MemoryServiceError("restore_packet_capacity_exceeded")
        return packet

    def close(self):
        if self._close_result is not None:
            return copy.deepcopy(self._close_result)
        if not self._closed:
            try:
                result=self._rpc({"op":"close"})
            finally:
                # Even an unknown close receipt closes admission permanently.
                self._closed=True
                self._pipe.close()
                self._process.join(timeout=2)
                if self._process.is_alive():
                    self._process.terminate()
                    self._process.join(timeout=2)
            if not result.get("ok"):raise MemoryServiceError("memory_close_failed")
        else:
            self._pipe.close()
            self._process.join(timeout=2)
            if self._process.is_alive():
                self._process.terminate()
                self._process.join(timeout=2)
        snapshot=self.snapshot_readonly(evaluator=True)
        if snapshot["meta"]["closed"]!=1:
            self._event("memory_service_failure", {"reason":"memory_close_not_durably_confirmed","closure_unknown":True})
            raise MemoryServiceError("memory_close_not_durably_confirmed")
        eid=self._event("memory_closed", {"admission_closed":True,"durability_reopen_verified":True,
            "evaluator_only":True,"snapshot_sha256":digest(snapshot),"main_window_closed":True})
        self._close_result={"event_id":eid,"snapshot":snapshot,"events":self.events,"carrier_exists":True,
                            "main_window_closed":True,"M4_supported":False}
        return copy.deepcopy(self._close_result)

    close_admission=close

    def dispatch(self, *, actor, tool, arguments, request_id):
        """Closed actor-facing dispatcher; no trusted lifecycle method exposed."""
        spec=next((s for s in TOOL_SPECS if s["name"]==tool),None)
        if spec is None or type(arguments) is not dict:
            return self._reject("unknown_memory_tool",actor,request_id)
        schema=spec["parameters"]
        if set(arguments)-set(schema["properties"]) or not set(schema.get("required",[]))<=set(arguments):
            return self._reject("invalid_memory_action_fields",actor,request_id)
        if tool=="memory.put":return self.put(actor=actor,request_id=request_id,**arguments)
        if tool=="memory.get":return self.get(actor=actor,request_id=request_id,**arguments)
        return self.list(actor=actor,request_id=request_id,**arguments)
