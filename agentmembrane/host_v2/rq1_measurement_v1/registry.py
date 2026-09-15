"""Finite runtime obligations, never misrepresented as the full proposal scope."""
from copy import deepcopy

K_UNITS = ("actor_ceiling", "delegation_no_scope_growth", "identity_task_binding", "lifetime")
C_UNITS = ("execution_identity_route", "mandatory_permission", "shared_budget", "delegation_limit", "closed_admission", "audit_model_boundary")
M_UNITS = ("trusted_task_input", "trusted_task_facts", "provenance_ownership", "task_namespace")


def units(dimension, names, severity=4):
    return [{"id": dimension + ":" + name, "weight": 1, "max_severity": severity,
             "description": name.replace("_", " ")} for name in names]


def attach_runtime_registry(contract, system_profile):
    result = deepcopy(contract)
    result["system_profile"] = system_profile
    for dim, names, scope in (("K", K_UNITS, "runtime_delegation_only"),
                              ("C", C_UNITS, "runtime_flow_only")):
        result["dimensions"][dim] = {"scope": scope, "units": units(dim, names),
            "full_proposal_scope_complete": False,
            "unsupported": "persistent_cross_session_management_not_implemented"}
    if system_profile == "three_actor_task_memory_v1":
        result["dimensions"]["M"] = {"scope": "episode_task_memory_single_persistent_domain",
            "units": units("M", M_UNITS), "full_proposal_scope_complete": False,
            "unsupported": "second_persistent_trust_domain_not_implemented"}
    return result
