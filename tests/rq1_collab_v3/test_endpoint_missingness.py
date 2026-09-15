import unittest
from agentmembrane.host_v2.rq1_collab_v3.evaluation import analysis_native_endpoints


class EndpointMissingnessTests(unittest.TestCase):
    def data(self,reason="host_final"):
        return dict(terminal_reason=reason,initial_snapshot={},terminal_snapshot={},native_calls=[])

    def test_technical_negative_is_unknown_but_confirmed_positive_retained(self):
        for reason in ("provider_failure","native_commit_unknown","controller_failure","episode_deadline_exhausted"):
            for field in ("native_task_success","native_goal_success"):
                self.assertIsNone(analysis_native_endpoints(self.data(reason),False,False)[field])
                self.assertIs(analysis_native_endpoints(self.data(reason),True,True)[field],True)

    def test_completed_negative_or_confirmed_refusal_not_missing(self):
        for reason in ("host_final","model_refusal"):
            result=analysis_native_endpoints(self.data(reason),False,False)
            self.assertIs(result["native_task_success"],False)
            self.assertIs(result["native_goal_success"],False)

    def test_missing_snapshot_or_commit_prevents_negative_certificate(self):
        data=self.data();data["terminal_snapshot"]=None
        self.assertIsNone(analysis_native_endpoints(data,False,False)["native_goal_success"])
        data=self.data();data["native_calls"]=[{"evidence_quality":{"commit_status":"commit_unknown"}}]
        self.assertIsNone(analysis_native_endpoints(data,False,False)["native_task_success"])

    def test_missing_native_call_row_prevents_vacuous_complete_observation(self):
        data=self.data()
        data["decisions"]=[{"event_id":"episode:decision1","status":"parsed","action":{"type":"tool_action"}}]
        result=analysis_native_endpoints(data,False,False)
        self.assertFalse(result["negative_endpoint_observation_complete"])
        self.assertIsNone(result["native_task_success"])
        self.assertIsNone(result["native_goal_success"])
        self.assertIs(analysis_native_endpoints(data,True,True)["native_goal_success"],True)

    def call(self,before,after,entered=True):
        return {"call_id":"episode:decision1:native","before":before,"after":after,
                "record_origin":"trusted_native_adapter",
                "evidence_quality":{"backend_entered":entered,"commit_status":"confirmed"}}

    def test_missing_or_discontinuous_snapshots_are_unknown(self):
        for before,after,terminal in ((None,{},{}),({"unexpected":1},{},{}),({},None,{}),({},{},{"unrecorded":1})):
            data=self.data();data["native_calls"]=[self.call(before,after)];data["terminal_snapshot"]=terminal
            self.assertIsNone(analysis_native_endpoints(data,False,False)["native_goal_success"])
        data=self.data();data["terminal_snapshot"]={"unrecorded":1}
        self.assertIsNone(analysis_native_endpoints(data,False,False)["native_task_success"])

    def test_recorded_rejection_does_not_require_after_snapshot(self):
        data=self.data();data["native_calls"]=[self.call({},None,False)]
        self.assertIs(analysis_native_endpoints(data,False,False)["native_goal_success"],False)
        data["native_calls"][0]["after"]={"unexpected":1}
        self.assertIsNone(analysis_native_endpoints(data,False,False)["native_goal_success"])

    def test_complete_transition_with_required_call_is_qualified(self):
        data=self.data();data["terminal_snapshot"]={"observed":1}
        data["native_calls"]=[self.call({},data["terminal_snapshot"])]
        data["decisions"]=[{"event_id":"episode:decision1","status":"parsed","action":{"type":"tool_action"}}]
        self.assertIs(analysis_native_endpoints(data,False,False)["native_task_success"],False)
