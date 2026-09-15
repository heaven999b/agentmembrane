"""Engineering fixtures test reporting mechanics, not research performance."""
import copy
import unittest

from agentmembrane.host_v2.rq1_measurement_v1.reporting import aggregate, DIMENSIONS


def fixture(eid="a", repeat=0, **changes):
    config = dict(episode_id=eid, topology="H_E", level="low", regime="honest",
                  repeat=repeat, execution_mode="engineering", bundle_sha256="bundle",
                  models={"H": {"model": "test"}, "E": {"model": "test"}})
    config.update(changes)
    binding = dict(source="agentdojo", suite="workspace", task_id="task1", initial_state_sha256="world")
    a = dict(config=config, system_profile="profile", system_spec_sha256="spec",
             source_version="source-v1", task_binding=binding, independent_world_id="agentdojo:workspace:world")
    r = dict(episode_id=eid, config=copy.deepcopy(config), system_profile="profile", system_spec_sha256="spec",
             task_binding=copy.deepcopy(binding), independent_world_id=a["independent_world_id"],
             schema_version="rq1-measurement-result/1", contract_sha256="contract1",
             contract={"measurement_version":"rq1-measurement/1"},
             dimensions={d:dict(lower=80,upper=80,point=80) for d in DIMENSIONS if d != "T"},
             overall=dict(lower=80,upper=80,point=80))
    return a,r


class ReportingTests(unittest.TestCase):
    def test_missing_in_denominator(self):
        a,r=fixture(); b,_=fixture("b",repeat=1)
        out=aggregate([a,b],{"a":r}); g=out["groups"][0]
        self.assertEqual(g["allocated_episodes"],2)
        self.assertEqual(g["missing_reports"],1)
        self.assertEqual(g["scores"]["Q"],dict(lower=40,upper=90,point=None))
        self.assertEqual(g["independent_world_count"],1)
        self.assertFalse(out["formal_ready"])

    def test_profiles_modes_versions_separated(self):
        aa=[];rr={}
        for i in range(4):
            a,r=fixture(str(i));
            if i==1: a["system_profile"]=r["system_profile"]="other"
            if i==2: a["source_version"]="v2"
            if i==3: a["config"]["execution_mode"]=r["config"]["execution_mode"]="live_diagnostic"
            aa.append(a);rr[str(i)]=r
        out=aggregate(aa,rr)
        self.assertEqual(len(out["groups"]),4)
        self.assertFalse(out["paired_differences"])

    def test_pair_missing_upper_lower(self):
        a,r=fixture();b,_=fixture("b",level="high")
        out=aggregate([a,b],{"a":r})
        p=out["paired_differences"][0]
        self.assertEqual(p["contrast"],"high-low")
        self.assertEqual(p["scores"]["T"],dict(lower=-80,upper=20,point=None))
        self.assertFalse(p["both_reports_present"])

    def test_unbound_is_retained_not_inferred(self):
        a,r=fixture();a.pop("source_version")
        out=aggregate([a],{"a":r})
        self.assertEqual(out["groups"][0]["scores"]["Q"],dict(lower=0.,upper=100.,point=None))
        self.assertEqual(out["groups"][0]["independent_world_count"],0)

    def test_invalid_dimension_does_not_erase_other_evidence(self):
        a,r=fixture();r["dimensions"]["Q"]["lower"]=float("nan")
        g=aggregate([a],{"a":r})["groups"][0]
        self.assertIsNone(g["scores"]["Q"]["point"])
        self.assertEqual(g["scores"]["D"]["point"],80)

    def test_report_identity_rejected(self):
        a,r=fixture();r["config"]["level"]="high"
        with self.assertRaisesRegex(ValueError,"identity"): aggregate([a],{"a":r})

    def test_contract_change_rejected(self):
        a,r=fixture();b,s=fixture("b",1);s["contract_sha256"]="altered"
        with self.assertRaisesRegex(ValueError,"contract_changed"): aggregate([a,b],{"a":r,"b":s})

    def test_duplicated_allocation_and_unallocated_report_rejected(self):
        a,r=fixture()
        with self.assertRaises(ValueError): aggregate([a,a],{"a":r})
        with self.assertRaises(ValueError): aggregate([],{"a":r})

    def test_tasks_repeats_are_not_worlds(self):
        a,r=fixture();b,s=fixture("b");b["task_binding"]["task_id"]=s["task_binding"]["task_id"]="task2"
        s["contract_sha256"]="contract2"
        g=aggregate([a,b],{"a":r,"b":s})["groups"][0]
        self.assertEqual(g["unique_task_count"],2)
        self.assertEqual(g["independent_world_count"],1)

    def test_v4_report_wrapper(self):
        a,r=fixture()
        self.assertEqual(aggregate([a],{"a":{"episode_id":"a","measurement":r}})["groups"][0]["scores"]["Q"]["point"],80)

    def test_world_binding_rejected(self):
        a,r=fixture();a["independent_world_id"]="artificial-independent-repeat"
        with self.assertRaisesRegex(ValueError,"world"): aggregate([a],{"a":r})

    def test_topology_pairs_optional_internal_model(self):
        a,r=fixture();b,s=fixture("b",topology="H_S_E")
        b["config"]["models"]["S"]={"model":"weak"};s["config"]=copy.deepcopy(b["config"])
        out=aggregate([a,b],{"a":r,"b":s})
        self.assertEqual(len(out["groups"]),2)
        self.assertEqual(out["paired_differences"][0]["contrast"],"H_S_E-H_E")


if __name__ == "__main__":
    unittest.main()
