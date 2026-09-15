"""Exact, delivered-projection-only references; no expressions or fallbacks."""
from __future__ import annotations

import copy
import re

from .memory_reader import digest


class MemoryReferenceError(ValueError):
    pass


def json_pointer(value, pointer):
    if type(pointer) is not str or len(pointer) > 1024:
        raise MemoryReferenceError("invalid_source_pointer")
    if pointer == "":
        return copy.deepcopy(value)
    if not pointer.startswith("/"):
        raise MemoryReferenceError("invalid_source_pointer")
    for segment in pointer[1:].split("/"):
        if re.search(r"~(?![01])", segment):
            raise MemoryReferenceError("invalid_pointer_escape")
        segment = segment.replace("~1", "/").replace("~0", "~")
        if type(value) is dict and segment in value:
            value = value[segment]
        elif type(value) is list and re.fullmatch(r"0|[1-9][0-9]*", segment) and int(segment) < len(value):
            value = value[int(segment)]
        else:
            raise MemoryReferenceError("source_field_not_delivered")
    return copy.deepcopy(value)


def resolve_memory_arguments(action, *, actor, memory):
    """Only prepare binding; caller must check native schema/scope and ingress."""
    if type(action) is not dict or action.get("type") != "tool_action":
        raise MemoryReferenceError("references_require_tool_action")
    if set(action) - {"type", "tool", "arguments", "argument_refs", "source_refs"}:
        raise MemoryReferenceError("unknown_action_field")
    if type(action.get("arguments")) is not dict or type(action.get("tool")) is not str:
        raise MemoryReferenceError("invalid_tool_arguments")
    refs = action.get("argument_refs")
    if refs is None:
        return copy.deepcopy(action), []
    if action["tool"].startswith("memory.") or type(refs) is not dict or not 1 <= len(refs) <= 16:
        raise MemoryReferenceError("invalid_reference_destination")
    visible = action.get("source_refs", [])
    if type(visible) is not list or any(type(r) is not str for r in visible) or len(visible) != len(set(visible)):
        raise MemoryReferenceError("invalid_source_refs")
    merged = copy.deepcopy(action["arguments"])
    bindings = []
    for destination, ref in refs.items():
        if type(destination) is not str or not re.fullmatch(r"/[A-Za-z_][A-Za-z0-9_]{0,127}", destination):
            raise MemoryReferenceError("top_level_destination_required")
        key = destination[1:]
        if key in merged:
            raise MemoryReferenceError("literal_reference_conflict")
        if type(ref) is not dict or set(ref) != {"record_id", "version", "field_pointer", "read_event_id", "projected_value_sha256"}:
            raise MemoryReferenceError("invalid_reference_fields")
        if (type(ref["version"]) is not int or ref["version"] < 1
                or type(ref["record_id"]) is not str or not 1 <= len(ref["record_id"]) <= 128
                or type(ref["read_event_id"]) is not str or not 1 <= len(ref["read_event_id"]) <= 256
                or type(ref["projected_value_sha256"]) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", ref["projected_value_sha256"])
                or ref["read_event_id"] not in visible):
            raise MemoryReferenceError("unbound_reference")
        # The service validates current version, actual receipt, grant and pages.
        delivered = memory.reference_projection(actor=actor, reference=ref)
        value = json_pointer(delivered, ref["field_pointer"])
        merged[key] = value
        bindings.append({**copy.deepcopy(ref), "destination": destination,
                         "extracted_value_sha256": digest(value)})
    result = copy.deepcopy(action)
    result["arguments"] = merged
    result.pop("argument_refs", None)
    for binding in bindings:
        binding["arguments_sha256"] = digest(merged)
        binding["original_action_sha256"] = digest(action)
        binding["use_confirmed"] = False
    return result, bindings
