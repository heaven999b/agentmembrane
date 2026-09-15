import copy
import unittest

from agentmembrane.host_v2.rq1_measurement_v1.format_checks import make_presentations,restore_presentation,compare_presentations,threshold_sensitivity


class FormatTests(unittest.TestCase):
    def test_reversible_views_J06(self):
        original={"display_id":"row-1","permission":{"role":"E","level":"low"},"recipient":"owner@example.invalid","facts":["中文\nvalue\u2028line",None,3,True],"empty":{}}
        before=copy.deepcopy(original)
        variants=make_presentations(original,nonsemantic_id_paths=["/display_id"])
        self.assertEqual(len(variants),4)
        for v in variants:self.assertEqual(restore_presentation(v),original)
        self.assertEqual(original,before)

    def test_cannot_rename_actual_permission(self):
        with self.assertRaises(ValueError):make_presentations({"actor":"E"},nonsemantic_id_paths=["/actor"])

    def test_tampered_view_rejected(self):
        view=make_presentations({"x":1})[0];view["payload"]='{"x":2}'
        with self.assertRaises(ValueError):restore_presentation(view)

    def test_unknown_not_zero_and_conclusion_flips(self):
        def score(lo,hi,accepted,conclusion):return {"canonical_sha256":"same","overall":{"lower":lo,"upper":hi},"dimensions":{"Q":{"lower":lo,"upper":hi}},"accepted":accepted,"primary_conclusion":conclusion}
        result=compare_presentations({"a":score(0,100,False,"A"),"b":score(50,50,True,"B")})
        self.assertEqual(result["format_difference"]["overall"]["upper"],100)
        self.assertIsNone(result["format_difference"]["overall"]["point"])
        self.assertTrue(result["primary_conclusion_flipped"]);self.assertEqual(result["acceptance_flip_rate"],1)

    def test_deterministic_invariance_failure(self):
        a={"canonical_sha256":"same","overall":{"lower":10,"upper":10},"dimensions":{"Q":{"lower":10,"upper":10}}}
        b=copy.deepcopy(a);b["overall"]={"lower":11,"upper":11}
        self.assertFalse(compare_presentations({"a":a,"b":b},deterministic=True)["deterministic_invariance_passed"])

    def test_threshold_reuses_votes(self):
        value={"planned_votes":6,"votes":[{}]*6,"fields":[{"agreement_count":4},{"agreement_count":5},{"agreement_count":6}]}
        result=threshold_sensitivity(value)
        self.assertEqual(result["additional_calls"],0)
        self.assertEqual([result["thresholds"][str(n)]["accepted_fields"] for n in (4,5,6)],[3,2,1])


if __name__=="__main__":unittest.main()
