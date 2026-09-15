"""Source-native public travel facts; rule probes do not execute model attacks."""
import copy
from pathlib import Path
import unittest

from agentmembrane.host_v2.rq1_collab_v1.native import NativeTask
from agentmembrane.host_v2.rq1_collab_v1.policy import make_task_policy,compile_task_policy
from agentmembrane.host_v2.rq1_collab_v3.permissions import native_tools,authorize_native

SOURCE=str(Path(__file__).resolve().parents[2]/"data/host_boundary_v2/upstream/agentdojo")


class TaskScopedPermissionTests(unittest.TestCase):
    def setup_task(self,n):
        task=NativeTask(SOURCE,"travel",f"user_task_{n}")
        record={"suite":"travel","original_id":f"user_task_{n}"}
        policy=make_task_policy("travel",record["original_id"],task.prompt,
            compile_task_policy("travel",record["original_id"],task.prompt),[s["name"] for s in task.tool_specs])
        return task,record,policy

    def test_middle_travel_tools_match_original_task_but_high_stays_broad(self):
        for n in (0,2):
            task,record,policy=self.setup_task(n)
            self.assertEqual(native_tools(policy,record,"A0"),[])
            self.assertNotIn("get_flight_information",native_tools(policy,record,"A3"))
            self.assertEqual(native_tools(policy,record,"A4"),policy.native_tools("A4"))
            tool="get_all_hotels_in_city" if n==0 else "get_all_restaurants_in_city"
            self.assertTrue(authorize_native(policy,record,"A3",tool,{"city":policy.facts["city"]},task.snapshot())[0])
            self.assertFalse(authorize_native(policy,record,"A3",tool,{"city":"Outside City"},task.snapshot())[0])
            self.assertTrue(authorize_native(policy,record,"A4",tool,{"city":"Outside City"},task.snapshot())[0])

    def test_middle_hotel_dates_and_condition_not_arbitrary_booking(self):
        task,record,policy=self.setup_task(0);facts=policy.facts;snapshot=task.snapshot()
        args={"hotel":facts["hotel_name"],"start_day":facts["start_day"],"end_day":facts["end_day"]}
        self.assertTrue(authorize_native(policy,record,"A3","reserve_hotel",args,snapshot)[0])
        self.assertFalse(authorize_native(policy,record,"A3","reserve_hotel",{**args,"end_day":"2025-02-01"},snapshot)[0])
        self.assertTrue(authorize_native(policy,record,"A4","reserve_hotel",{**args,"end_day":"2025-02-01"},snapshot)[0])
        low=copy.deepcopy(snapshot)
        for hotel in low["hotels"]["hotel_list"]:
            if hotel["name"]==facts["hotel_name"] and hotel["city"]==facts["city"]:
                hotel["rating"]=facts["rating_strictly_greater_than"]
        for tool,arguments in (("reserve_hotel",args),("get_user_information",{})):
            self.assertFalse(authorize_native(policy,record,"A3",tool,arguments,low)[0])


if __name__=="__main__":unittest.main()
