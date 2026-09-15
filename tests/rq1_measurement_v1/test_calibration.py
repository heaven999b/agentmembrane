"""Engineering fixtures only; not calibration observations or benchmark data."""
import copy
import unittest

from agentmembrane.host_v2.rq1_measurement_v1.calibration import cp_upper,lock_manifest,certify,aggregate_record_class

D="filename_claim.closed_structured_v1"


def record(rid,cluster,gold=False,items=None):
    return {"record_id":rid,"domain_id":D,"source_cluster":cluster,"full_record_hash":"hash-"+rid,
            "status":"supported","items":items if items is not None else [{"field_id":"a","gold":gold}]}


def lock(records,**kwargs):
    return lock_manifest(records,[{"domain_id":D,"endpoint":e} for e in ("FPR","FNR")],
        selection_seed="locked-before-votes",provenance={"kind":"engineering_fixture"},**kwargs)


class CalibrationTests(unittest.TestCase):
    def test_exact_rejection_counterexample_J09(self):
        self.assertAlmostEqual(cp_upper(8,200,.05/12),.09185438985733191,places=12)
        self.assertGreater(cp_upper(8,200,.05/12),.05)
        self.assertLess(cp_upper(0,192,.05/12),.05)

    def test_cp_endpoints_and_types(self):
        self.assertIsNone(cp_upper(0,0)); self.assertEqual(cp_upper(5,5),1)
        self.assertLessEqual(cp_upper(0,59),.05)
        for args in [(True,1),(1,False),(-1,4),(5,4),(0,2,0)]:
            with self.assertRaises(ValueError): cp_upper(*args)

    def test_record_class_aggregation_J11(self):
        items=[{"field_id":str(i),"gold":False} for i in range(100)]
        pred={str(i):False for i in range(100)}; pred["0"]=True
        for i in (1,2,3): pred[str(i)]=None
        self.assertEqual(aggregate_record_class(items,pred,False),{"error":1,"unknown":0,"items":100})
        self.assertIsNone(aggregate_record_class(items,pred,True))

    def test_shared_source_not_inflated_J05_J10(self):
        rows=[record(str(i),"one-world") for i in range(500)]
        result=certify(lock(rows),{r["record_id"]:{"a":False} for r in rows})
        self.assertEqual(result["endpoints"][0]["N"],1)
        self.assertEqual(result["endpoints"][1]["N"],0)
        self.assertFalse(result["certified"])

    def test_selection_independent_of_predictions(self):
        rows=[record(str(i),"world") for i in range(5)]
        manifest=lock(rows); before=copy.deepcopy(manifest["selected"])
        certify(manifest,{r["record_id"]:{"a":bool(i%2)} for i,r in enumerate(rows)})
        self.assertEqual(manifest["selected"],before)

    def test_dynamic_family_and_missing_predictions(self):
        from agentmembrane.host_v2.rq1_measurement_v1.semantic_fields import domain_spec
        domains=["filename_claim.closed_structured_v1","email_claim.closed_structured_v1"]
        family=[{"domain_id":d,"endpoint":e} for d in domains for e in ("FPR","FNR")]
        manifest=lock_manifest([record("one","world")],family,selection_seed="fixed",provenance={"kind":"fixture"})
        result=certify(manifest,{})
        self.assertEqual(result["family_size"],4); self.assertEqual(result["alpha_per_endpoint"],.0125)
        self.assertEqual(result["endpoints"][0]["unknown"],1)

    def test_modified_lock_rejected(self):
        manifest=lock([record("one","world")]); manifest["selected"]=[]
        with self.assertRaises(ValueError): certify(manifest,{})

    def test_extra_prediction_and_duplicate_gold_rejected(self):
        with self.assertRaises(ValueError): lock([record("same","w"),record("same","w")])
        with self.assertRaises(ValueError): certify(lock([record("one","w")]),{"one":{"invented":False}})

    def test_engineering_never_certifies(self):
        rows=[record(str(i),str(i),bool(i%2)) for i in range(800)]
        result=certify(lock(rows,independent_sources=True,representative_sources=True),
            {r["record_id"]:{"a":r["items"][0]["gold"]} for r in rows})
        self.assertFalse(result["certified"])
        self.assertTrue(all(e["worst_case_exact_upper"]<.05 for e in result["endpoints"]))


if __name__=="__main__": unittest.main()
