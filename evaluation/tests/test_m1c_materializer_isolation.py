import json, tempfile, unittest
from pathlib import Path
from evaluation.agents.dsh_harbor_adapter.materializer import confined,create_run,digest,load_spec,materialize

BASE={"schema_version":"1.0.0","candidate_id":"adapter_smoke_h0","parent_candidate_id":None,"base_dsh_commit":"b150a551b8d465e31e418e1b2eaf5e79bbb7d28e","experiment_status":"INTEGRATION_ONLY","instruction_bundle":{"cordis_patch":"plugins: []\n"},"runtime_policy_reference":"runtime_policy_v1","skill_bundle_references":[],"memory_bootstrap_reference":None,"provenance":{"source":"M1C.1","created_by":"deterministic","purpose":"DSH_HARBOR_ADAPTER_INTEGRATION_ONLY"},"content_hashes":{}}
class T(unittest.TestCase):
 def setUp(self): self.t=tempfile.TemporaryDirectory(); self.r=Path(self.t.name)
 def tearDown(self): self.t.cleanup()
 def spec(self,v=BASE): p=self.r/"s.json";p.write_text(json.dumps(v));return p
 def test_01_two_runs_differ(self): self.assertNotEqual(create_run(self.r/"runs","a")["dsh-home"],create_run(self.r/"runs","b")["dsh-home"])
 def test_02_hash_same(self): self.assertEqual(digest(BASE),digest(json.loads(json.dumps(BASE))))
 def test_03_home_sentinel_isolated(self):
  a=create_run(self.r/"runs","a");b=create_run(self.r/"runs","b");(a["dsh-home"]/"x").touch();self.assertFalse((b["dsh-home"]/"x").exists())
 def test_04_memory_sentinel_isolated(self):
  a=create_run(self.r/"runs","a");b=create_run(self.r/"runs","b");(a["memory"]/"x").touch();self.assertFalse((b["memory"]/"x").exists())
 def test_05_materialize(self): self.assertTrue(materialize(self.spec(),self.r/"m")[0].is_dir())
 def test_06_stable_hash_independent_run(self): self.assertEqual(digest(BASE),digest(BASE))
 def test_07_traversal(self): self.assertRaises(ValueError,confined,self.r,"../x")
 def test_08_absolute(self): self.assertRaises(ValueError,confined,self.r,"/x")
 def test_09_artifact_escape(self): self.assertRaises(ValueError,confined,self.r,"a/../../x")
 def test_10_unknown_fail_closed(self):
  v={**BASE,"task_id":"x"};self.assertRaises(ValueError,load_spec,self.spec(v))
 def test_11_missing_provenance(self):
  v=json.loads(json.dumps(BASE));del v["provenance"]["purpose"];self.assertRaises(ValueError,load_spec,self.spec(v))
 def test_12_schema_version(self):
  v={**BASE,"schema_version":"2"};self.assertRaises(ValueError,load_spec,self.spec(v))
if __name__=="__main__": unittest.main()
