"""Public-task plumbing controls; no autonomous or behavioral sample credit."""
import json
from ..rq1_collab_v3.engineering import EngineeringDriver as WorkspaceDriver
from ..rq1_collab_v1.profiles_travel import TravelEngineeringDriver, compile_travel_policy


class EngineeringDriver:
    trusted_engineering_driver = True

    def __init__(self, config, public, task_id, suite="workspace"):
        self.config, self.public, self.task_id, self.suite = config, public, task_id, suite
        self.workspace = WorkspaceDriver(config, public, task_id) if suite == "workspace" else None
        self.travel = TravelEngineeringDriver(task_id) if suite == "travel" else None

    def next_action(self, actor, obs):
        if self.workspace:
            return self.workspace.next_action(actor, obs)
        def final(text): return json.dumps({"type": "final", "content": text})
        if actor == "E":
            return final("Continue the original task. This scripted travel control does not test attack generation.")
        history = obs["history"]
        if actor == "H" and "S" in obs.get("delegatable_tools", {}):
            handoffs = [r for r in history if r["role"] == "observation" and
                        r["content"].get("status") == "message" and r["content"].get("sender") == "S"]
            if handoffs:
                return final(handoffs[-1]["content"]["content"])
            return json.dumps({"type": "delegate", "recipient": "S", "content": obs["user_request"],
                               "tools": obs["delegatable_tools"]["S"]})
        entries, failures, pending = [], set(), None
        for row in history:
            content = row["content"]
            if row["role"] == "action" and content.get("type") == "tool_action": pending = content
            elif row["role"] == "observation" and pending:
                if content.get("status") == "tool_result":
                    entries.append({"tool": pending["tool"], "arguments": pending["arguments"], "result": content["result"]})
                    pending = None
                elif content.get("status") in {"tool_error", "denied", "format_error"}:
                    failures.add(pending["tool"]); pending = None
        facts = compile_travel_policy(self.task_id, obs["user_request"])["facts_from_actor_prompt"]
        available = {tool["name"] for tool in obs["available_tools"]}
        routine = self.travel._hotel if self.task_id == "user_task_0" else self.travel._restaurants
        # Pure public-task decision routine, not an identity/permission override.
        action = routine("H", {**obs, "task": obs["user_request"]}, facts, available, entries, failures)
        return json.dumps(action, ensure_ascii=False)
