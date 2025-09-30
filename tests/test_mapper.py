
import json
from pathlib import Path

def test_rules_load():
    data = json.loads(Path('src/mapper/rules.json').read_text())
    assert 'aws.s3.bucket.posture' in data
