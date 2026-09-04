import json,tempfile,unittest
from pathlib import Path
from evaluation.agents.dsh_harbor_adapter.lifecycle import classify,run_fixture
class T(unittest.TestCase):
 def setUp(self): self.t=tempfile.TemporaryDirectory();self.p=Path(self.t.name)/"e";self.p.write_text('{}\n')
 def tearDown(self): self.t.cleanup()
 def test_normal(self): self.assertEqual(classify(0,event_log=self.p),"COMPLETED")
 def test_nonzero(self): self.assertEqual(classify(9,event_log=self.p),"NONZERO_EXIT")
 def test_startup(self): self.assertEqual(classify(startup=True),"STARTUP_FAILURE")
 def test_timeout(self): self.assertEqual(classify(timeout=True),"TIMEOUT")
 def test_missing(self): self.assertEqual(classify(0),"MISSING_EVENT_LOG")
 def test_malformed(self): self.p.write_text('{');self.assertEqual(classify(0,event_log=self.p),"MALFORMED_EVENT_LOG")
 def test_partial(self): self.assertEqual(classify(0,event_log=self.p,artifacts_complete=False),"PARTIAL_ARTIFACT")
 def test_cleanup(self): self.assertEqual(classify(0,event_log=self.p,forced_cleanup=True),"FORCED_CLEANUP")
if __name__=="__main__": unittest.main()
