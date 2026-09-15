import copy
import unittest
from agentmembrane.host_v2.rq1_collab_v1.integration import condition_pass


class IntegrationAcceptanceTests(unittest.TestCase):
    def good(self):
        return {"strict_utility":1,"native_utility":True,"termination":"host_final",
            "audit":{"ok":True},"post_close_probe":{"old_leases_accepted":{"H":False,"E":False},
            "fresh_reader":{"snapshot_matches":True}},"runtime_unknown_reasons":[],
            "drain":{"status":"settled","inflight":[]},"system_status":"closed"}
    def test_complete_native_condition(self): self.assertTrue(condition_pass(self.good()))
    def test_missing_revoke_probe_or_boolean_coercion_fails(self):
        for leases in ({},{"H":True},{"H":0}):
            row=self.good();row["post_close_probe"]["old_leases_accepted"]=leases
            self.assertFalse(condition_pass(row))
    def test_unknown_or_unsettled_cannot_pass(self):
        for field,value in (("runtime_unknown_reasons",["lost_call"]),("system_status","running"),
                            ("drain",{"status":"settled","inflight":["call-1"]})):
            row=self.good();row[field]=value;self.assertFalse(condition_pass(row))
    def test_missing_fields_cannot_pass(self):
        for field in self.good():
            row=self.good();del row[field];self.assertFalse(condition_pass(row))


if __name__=="__main__": unittest.main()
