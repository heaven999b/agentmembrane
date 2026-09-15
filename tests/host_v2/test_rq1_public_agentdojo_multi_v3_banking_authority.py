from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest

from agentmembrane.host_v2.rq1_public_agentdojo_multi_v3.domain_authority.banking import (
    BANKING_TOOL_AUTHORITY,
    PROFILE,
)
from agentmembrane.host_v2.rq1_public_agentdojo_multi_v3.domain_authority.core import (
    AuthorityContractError,
    validate_native_tool_coverage,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
PINNED_RUNTIME = (
    REPO_ROOT
    / "experiments/host_boundary_v2/runtime_envs/"
    "agentdojo-0.1.35-py3123-lock-395e3d0a5921"
)

EXPECTED_READS = {
    "get_iban": (),
    "get_balance": (),
    "get_most_recent_transactions": ("n",),
    "get_scheduled_transactions": (),
    "read_file": ("file_path",),
    "get_user_info": (),
}
EXPECTED_MUTATIONS = {
    "send_money": ("recipient", "amount"),
    "schedule_transaction": ("recipient", "amount", "recurring"),
    "update_scheduled_transaction": (
        "id",
        "recipient",
        "amount",
        "recurring",
    ),
    "update_password": ("password",),
    "update_user_info": ("first_name", "last_name", "street", "city"),
}
EXPECTED_GRANT_HASHES = {
    "user_task_0": "3d4429e23367e21a657bd439e8f040d26bb909ee26586475f022d0db3102b2a5",
    "user_task_2": "51f596ab8a408e4ddf1fae46cb555af4104cf5a0029a6e46efda594d8c4fc4e4",
    "user_task_3": "5e2fcc38d009c904f70ba4aeca34dfb97b35ce5ef4398b3a664503d24c640395",
}


def _run_pinned_native_audit() -> dict:
    script = textwrap.dedent(
        f"""
        import json
        from pathlib import Path
        import sys
        from types import SimpleNamespace

        repository = Path({str(REPO_ROOT)!r})
        sys.path[:0] = [
            str(repository),
            str(repository / "data/host_boundary_v2/upstream/agentdojo/src"),
        ]

        from agentdojo.task_suite.load_suites import get_suite
        from agentmembrane.host_v2.rq1_public_agentdojo_multi_v3.domain_authority.banking import (
            PROFILE,
            build_banking_authority,
            decide_banking,
        )
        from agentmembrane.host_v2.rq1_public_agentdojo_multi_v3.domain_authority.core import (
            AuthorityContractError,
        )

        suite = get_suite("v1", "banking")
        native_names = [tool.name for tool in suite.tools]
        selected = (
            ("user_task_0", "injection_task_5"),
            ("user_task_2", "injection_task_4"),
            ("user_task_3", "injection_task_1"),
        )
        rows = []

        def forbidden_checker(*args, **kwargs):
            raise AssertionError("a checker was called by static authority")

        # If the authority builder or decider consults either dispatcher this
        # locked-runtime test fails immediately.
        suite._check_user_task_utility = forbidden_checker
        suite._check_injection_task_security = forbidden_checker

        for user_task_id, paired_task_id in selected:
            user_task = suite.get_user_task_by_id(user_task_id)
            grant = build_banking_authority(suite, user_task)
            repeated = build_banking_authority(suite, user_task)
            active_proxy = SimpleNamespace(
                suite=suite,
                environment={{"untrusted_active_state": paired_task_id}},
                pair_role="adversarial",
            )
            from_active = build_banking_authority(active_proxy, user_task)

            environment = user_task.init_environment(
                suite.load_and_inject_default_environment({{}})
            )
            pre_environment = environment.model_copy(deep=True)
            user_calls = tuple(user_task.ground_truth(pre_environment))
            benign = [decide_banking(grant, call).as_json() for call in user_calls]

            paired_task = suite.get_injection_task_by_id(paired_task_id)
            paired_calls = tuple(paired_task.ground_truth(pre_environment))
            paired_final = decide_banking(grant, paired_calls[-1]).as_json()

            granted_functions = {{call.function for call in user_calls}}
            ungranted_read_name = next(
                row.function
                for row in PROFILE.tools
                if row.mode == "controlled_read"
                and row.function not in granted_functions
            )
            ungranted_read = decide_banking(
                grant,
                {{"function": ungranted_read_name, "args": {{}}}},
            ).as_json()
            unknown = decide_banking(
                grant,
                {{"function": "unknown_mutating_tool", "args": {{"target": "x"}}}},
            ).as_json()

            history_windows = {{}}
            if user_task_id == "user_task_3":
                for label, args in (
                    ("omitted", {{}}),
                    ("one", {{"n": 1}}),
                    ("ten", {{"n": 10}}),
                    ("hundred", {{"n": 100}}),
                    ("zero", {{"n": 0}}),
                    ("too_large", {{"n": 101}}),
                    ("boolean", {{"n": True}}),
                    ("non_integer", {{"n": "10"}}),
                ):
                    try:
                        decision = decide_banking(
                            grant,
                            {{
                                "function": "get_most_recent_transactions",
                                "args": args,
                            }},
                        ).as_json()
                    except AuthorityContractError as exc:
                        decision = {{
                            "failed_closed": True,
                            "error_type": type(exc).__name__,
                        }}
                    history_windows[label] = decision
                repeated_history = [
                    decide_banking(
                        grant,
                        {{"function": "get_most_recent_transactions", "args": {{}}}},
                    ).as_json()
                    for _ in range(2)
                ]
                unrelated_read = decide_banking(
                    grant,
                    {{"function": "read_file", "args": {{"file_path": "other.txt"}}}},
                ).as_json()
            else:
                repeated_history = []
                unrelated_read = None

            mutation = next(
                call
                for call in reversed(user_calls)
                if PROFILE.tool(call.function).mode == "controlled_mutation"
            )
            varied_args = dict(mutation.args)
            varied_args["subject"] = "non-authority memo may change"
            varied_args["date"] = "2099-12-31"
            nonauthority_variant = decide_banking(
                grant,
                {{"function": mutation.function, "args": varied_args}},
            ).as_json()
            changed_authority_args = dict(mutation.args)
            if mutation.function == "send_money":
                changed_authority_args["recipient"] = "DIFFERENT-RECIPIENT"
            else:
                changed_authority_args["id"] = 999999
            changed_authority = decide_banking(
                grant,
                {{"function": mutation.function, "args": changed_authority_args}},
            ).as_json()

            optional_none = None
            if mutation.function == "update_scheduled_transaction":
                none_args = dict(mutation.args)
                none_args.update({{"recipient": None, "recurring": None}})
                optional_none = decide_banking(
                    grant,
                    {{"function": mutation.function, "args": none_args}},
                ).as_json()

            grant_json = grant.as_json()
            encoded_grant = json.dumps(grant_json, sort_keys=True)
            rows.append(
                {{
                    "user_task_id": user_task_id,
                    "grant_sha256": grant.grant_sha256,
                    "repeat_sha256": repeated.grant_sha256,
                    "active_proxy_sha256": from_active.grant_sha256,
                    "entry_count": len(grant.entries),
                    "ground_truth_count": len(user_calls),
                    "benign": benign,
                    "paired_final": paired_final,
                    "paired_final_function": paired_calls[-1].function,
                    "ungranted_read": ungranted_read,
                    "unknown": unknown,
                    "nonauthority_variant": nonauthority_variant,
                    "changed_authority": changed_authority,
                    "history_windows": history_windows,
                    "repeated_history": repeated_history,
                    "unrelated_read": unrelated_read,
                    "optional_none": optional_none,
                    "forbidden_absent": all(
                        token not in encoded_grant
                        for token in (
                            paired_task_id,
                            "US133000000121212121212",
                            "pair_role",
                            "treatment_arm",
                            "condition_id",
                        )
                    ),
                }}
            )

        profile_update_call = {{
            "function": "update_user_info",
            "args": {{"street": "Authorized Street"}},
        }}
        profile_update_grant = PROFILE.grants_from_ground_truth(
            "agentdojo:v1:banking:optional-none-test",
            (profile_update_call,),
        )
        profile_update_none = decide_banking(
            profile_update_grant,
            {{
                "function": "update_user_info",
                "args": {{
                    "street": "Authorized Street",
                    "first_name": None,
                    "last_name": None,
                    "city": None,
                }},
            }},
        ).as_json()

        print(json.dumps({{
            "native_names": native_names,
            "rows": rows,
            "profile_update_none": profile_update_none,
        }}, sort_keys=True))
        """
    )
    completed = subprocess.run(
        [str(PINNED_RUNTIME / "bin/python"), "-I", "-B", "-c", script],
        cwd=REPO_ROOT,
        env={
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    return json.loads(completed.stdout)


class BankingAuthorityProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.native = _run_pinned_native_audit()

    def test_all_eleven_native_tools_are_exhaustively_classified(self) -> None:
        self.assertEqual(len(PROFILE.tools), 11)
        self.assertEqual(set(BANKING_TOOL_AUTHORITY), set(self.native["native_names"]))
        validate_native_tool_coverage(PROFILE, self.native["native_names"])
        with self.assertRaises(AuthorityContractError):
            validate_native_tool_coverage(
                PROFILE, self.native["native_names"] + ["unclassified_tool"]
            )

    def test_six_resource_reads_are_controlled_not_blanket_allowed(self) -> None:
        actual = {
            row.function: row.authority_fields
            for row in PROFILE.tools
            if row.mode == "controlled_read"
        }
        self.assertEqual(actual, EXPECTED_READS)
        self.assertFalse(any(row.mode == "unrestricted" for row in PROFILE.tools))
        for row in self.native["rows"]:
            with self.subTest(user_task_id=row["user_task_id"]):
                self.assertFalse(row["ungranted_read"]["within_authority"])
                self.assertEqual(
                    row["ungranted_read"]["reason"],
                    "no_matching_user_authority_grant",
                )

    def test_five_mutations_have_exact_authority_bearing_fields(self) -> None:
        actual = {
            row.function: row.authority_fields
            for row in PROFILE.tools
            if row.mode == "controlled_mutation"
        }
        self.assertEqual(actual, EXPECTED_MUTATIONS)
        self.assertNotIn("subject", actual["send_money"])
        self.assertNotIn("date", actual["send_money"])
        self.assertNotIn("subject", actual["update_scheduled_transaction"])

    def test_profile_and_reset_time_grant_hashes_are_locked(self) -> None:
        self.assertEqual(
            PROFILE.profile_sha256,
            "ef8881cee2948696b7ef5245f320567f49ee8d9ae263153b7f6f5c2006b51623",
        )
        for row in self.native["rows"]:
            user_task_id = row["user_task_id"]
            with self.subTest(user_task_id=user_task_id):
                self.assertEqual(
                    row["grant_sha256"], EXPECTED_GRANT_HASHES[user_task_id]
                )
                self.assertEqual(row["repeat_sha256"], row["grant_sha256"])
                self.assertEqual(row["active_proxy_sha256"], row["grant_sha256"])
                self.assertEqual(row["entry_count"], row["ground_truth_count"])
                self.assertTrue(row["forbidden_absent"])

    def test_all_benign_ground_truth_projections_are_allowed(self) -> None:
        expected_steps = {"user_task_0": 2, "user_task_2": 3, "user_task_3": 2}
        for row in self.native["rows"]:
            with self.subTest(user_task_id=row["user_task_id"]):
                self.assertEqual(
                    len(row["benign"]), expected_steps[row["user_task_id"]]
                )
                self.assertTrue(
                    all(decision["within_authority"] for decision in row["benign"])
                )
                self.assertTrue(
                    all(
                        decision["reason"] == "authority_grant_match"
                        for decision in row["benign"]
                    )
                )

    def test_paired_final_mutations_are_rejected_without_checker_use(self) -> None:
        for row in self.native["rows"]:
            with self.subTest(user_task_id=row["user_task_id"]):
                decision = row["paired_final"]
                self.assertFalse(decision["within_authority"])
                self.assertEqual(
                    decision["reason"], "no_matching_user_authority_grant"
                )
                self.assertIsNone(decision["matched_grant_index"])
                self.assertIsNotNone(decision["projection"])

        source = (
            REPO_ROOT
            / "agentmembrane/host_v2/rq1_public_agentdojo_multi_v3/"
            "domain_authority/banking.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("_check_injection_task_security", source)
        self.assertNotIn("_check_user_task_utility", source)
        self.assertNotIn(".security(", source)

    def test_unknown_mutating_operation_fails_closed(self) -> None:
        for row in self.native["rows"]:
            with self.subTest(user_task_id=row["user_task_id"]):
                self.assertFalse(row["unknown"]["within_authority"])
                self.assertEqual(row["unknown"]["reason"], "operation_unclassified")
                self.assertIsNone(row["unknown"]["projection"])

    def test_u3_history_window_default_and_subsets_share_projection(self) -> None:
        row = next(
            row for row in self.native["rows"] if row["user_task_id"] == "user_task_3"
        )
        windows = row["history_windows"]
        allowed = ("omitted", "one", "ten", "hundred")
        effects = []
        for label in allowed:
            with self.subTest(label=label):
                decision = windows[label]
                self.assertTrue(decision["within_authority"])
                self.assertFalse(decision["consumes_grant"])
                self.assertEqual(decision["projection"]["value"], {"n": 100})
                effects.append(
                    {
                        key: decision["projection"][key]
                        for key in ("op", "resource", "value")
                    }
                )
        self.assertTrue(all(effect == effects[0] for effect in effects))

        for label in ("zero", "too_large", "boolean", "non_integer"):
            with self.subTest(label=label):
                decision = windows[label]
                self.assertTrue(
                    decision.get("failed_closed") is True
                    or decision.get("within_authority") is False
                )

    def test_controlled_history_read_is_repeatable_and_does_not_consume(self) -> None:
        row = next(
            row for row in self.native["rows"] if row["user_task_id"] == "user_task_3"
        )
        self.assertEqual(len(row["repeated_history"]), 2)
        self.assertTrue(
            all(item["within_authority"] for item in row["repeated_history"])
        )
        self.assertTrue(
            all(item["consumes_grant"] is False for item in row["repeated_history"])
        )

    def test_history_subset_rule_does_not_broaden_other_tools(self) -> None:
        row = next(
            row for row in self.native["rows"] if row["user_task_id"] == "user_task_3"
        )
        self.assertFalse(row["unrelated_read"]["within_authority"])
        for item in self.native["rows"]:
            with self.subTest(user_task_id=item["user_task_id"]):
                self.assertFalse(item["changed_authority"]["within_authority"])

    def test_optional_none_is_canonicalized_to_omission(self) -> None:
        u2 = next(
            row for row in self.native["rows"] if row["user_task_id"] == "user_task_2"
        )
        self.assertTrue(u2["optional_none"]["within_authority"])
        self.assertTrue(self.native["profile_update_none"]["within_authority"])

    def test_nonauthority_memo_and_date_changes_remain_allowed(self) -> None:
        for row in self.native["rows"]:
            with self.subTest(user_task_id=row["user_task_id"]):
                decision = row["nonauthority_variant"]
                self.assertTrue(decision["within_authority"])
                self.assertEqual(decision["reason"], "authority_grant_match")


if __name__ == "__main__":
    unittest.main()
