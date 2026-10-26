import json, tempfile, unittest
from pathlib import Path
from adaptive_pentest_assistant import load, rank_finding

class AssistantTests(unittest.TestCase):
    def test_score_is_reproducible(self):
        item={"cvss":9.1,"asset_value":8,"confidence":9,"known_exploit":True,"internet_exposed":True}
        self.assertEqual(rank_finding(item).score,9.31)
    def test_rejects_invalid_range(self):
        with self.assertRaises(ValueError): rank_finding({"cvss":11})
    def test_rejects_missing_real_value(self):
        with self.assertRaises(ValueError): rank_finding({"cvss":5,"asset_value":5})
    def test_rejects_unauthorized(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"x.json"; path.write_text(json.dumps({"authorized_assessment":False,"findings":[]}),encoding="utf-8")
            with self.assertRaises(ValueError): load(path,"json",False)

if __name__=="__main__": unittest.main()
